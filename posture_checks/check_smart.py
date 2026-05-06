"""
SMART drive health check (host-health module, task #122).

Daily scan for drive failure signals. The whole point of this check is
DELTA detection — a drive sitting at 20 reallocated sectors for years
is not actionable, but a drive that gained 1 reallocated sector since
yesterday is starting to fail and needs replacement planning.

Per-drive signals tracked across runs:
  * SMART overall health (PASSED / FAILED)
  * reallocated_sector_count          (attribute 5)
  * current_pending_sector_count      (attribute 197)
  * reported_uncorrectable_errors     (attribute 187 on Intel/Micron)
  * command_timeout                   (attribute 188)
  * percent_used / wear_leveling      (NVMe / SATA SSD endurance)

Severity ladder (worst across all drives wins):
  * SMART overall = FAILED               -> CRITICAL  "replace immediately"
  * Endurance >= 95% used                -> CRITICAL  "replace now"
  * New reallocated/pending/uncorr      -> HIGH      "drive is failing, plan replacement"
  * New command timeouts                 -> HIGH      "controller / cable / drive instability"
  * Endurance >= 85% used                -> HIGH      "replace soon"
  * Endurance >= 70% used                -> MEDIUM    "plan replacement"
  * Existing reallocated > 0, no growth -> MEDIUM    "history only — monitor"
  * Otherwise                            -> PASS

Skip conditions (return SKIPPED):
  * Profile says is_virtualized — SMART through virtio is rarely meaningful
  * smartctl binary not installed
  * No physical disks discovered

Stored value (used for transition diffing) only contains stable counters
that should be 0 / unchanged on a healthy drive. Endurance is intentionally
NOT in the stored value because it creeps up daily by design — that would
generate a transition every run. Endurance is reported in `detail` and
contributes to severity, but doesn't trip the orchestrator's diff logic.
"""

import json
import logging
import os
import re
import subprocess

from posture_checks.base import Check, CheckResult, Severity, Status, Module

logger = logging.getLogger('wp-guardian.posture.smart')


# Severity thresholds for endurance-used percentage
ENDURANCE_CRITICAL = 95
ENDURANCE_HIGH = 85
ENDURANCE_MEDIUM = 70


def _safe_run(cmd, timeout=15):
    """Run a command, return (rc, stdout). Never raises."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, universal_newlines=True,
        )
        return proc.returncode, proc.stdout or ''
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.debug("Probe failed (%s): %s", ' '.join(cmd), e)
        return -1, ''


def _smartctl_present():
    """smartctl is in /usr/sbin on most distros; also check PATH."""
    for path in ('/usr/sbin/smartctl', '/usr/local/sbin/smartctl', '/sbin/smartctl'):
        if os.path.exists(path):
            return True
    rc, _ = _safe_run(['which', 'smartctl'], timeout=3)
    return rc == 0


def _discover_drives():
    """Return list of physical block-device names ('sda', 'nvme0n1', ...).

    Strategy: lsblk to enumerate, filter to TYPE=disk, exclude common
    virtual/loop/ram devices. We don't dedupe by serial here — a host
    with two physical drives reports two entries.
    """
    rc, out = _safe_run(['lsblk', '-d', '-n', '-o', 'NAME,TYPE'], timeout=5)
    if rc != 0:
        return []
    drives = []
    for line in (out or '').splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name, devtype = parts[0], parts[1]
        if devtype != 'disk':
            continue
        # Skip loop/ram/zram/dm/md/sr (cd) devices and virtio_block names
        # that are clearly not real disks. Real disks: sd[a-z]+, nvme*n*,
        # vd[a-z]+ (virtio — keep, but is_virtualized profile gate handles
        # most of these), hd[a-z]+.
        if name.startswith(('loop', 'ram', 'zram', 'dm-', 'md', 'sr')):
            continue
        drives.append(name)
    return drives


def _smartctl_json(device):
    """Run `smartctl -a -j /dev/<device>`. Returns parsed dict, or {} on
    failure. Tries `-d auto` first (lets smartctl pick), falls back to
    `-d sat` for SATA drives behind weird controllers.

    smartmontools 7.0+ supports -j / --json. EL9/EL10 ship 7.x.
    """
    for d_flag in ([], ['-d', 'sat']):
        cmd = ['smartctl', '-a', '-j'] + d_flag + ['/dev/' + device]
        rc, out = _safe_run(cmd, timeout=15)
        # smartctl exit codes are bitfield: 0=ok, but bit 6 = SMART data
        # available, bit 0-7 carry meanings. Non-zero rc with usable JSON
        # is normal (e.g. attribute below threshold sets bit 3).
        if not out:
            continue
        try:
            data = json.loads(out)
            return data
        except (ValueError, TypeError):
            continue
    return {}


def _extract_ata_attribute(data, attr_id):
    """Pull an ATA SMART attribute by ID from the parsed JSON. Returns
    int raw value, or None if absent."""
    table = ((data or {}).get('ata_smart_attributes') or {}).get('table') or []
    for entry in table:
        if entry.get('id') == attr_id:
            raw = entry.get('raw') or {}
            v = raw.get('value')
            if isinstance(v, int):
                return v
            # Some smartctl versions report raw as string; try parsing
            s = raw.get('string') or ''
            m = re.search(r'\d+', s)
            if m:
                return int(m.group(0))
            return None
    return None


def _drive_snapshot(device):
    """Return a per-drive snapshot dict, or None if probe failed.

    Snapshot shape:
      {
        'device': 'sda',
        'model':  'INTEL SSDSC2KB480G8',
        'serial': '...',
        'protocol': 'ATA' | 'NVMe' | ...,
        'smart_passed': bool,
        'reallocated_sector_count':   int,
        'current_pending_sector':     int,
        'reported_uncorrectable':     int,
        'command_timeout':            int,
        'endurance_used_pct':         int (0-100, None if not reported),
        'power_on_hours':             int,
      }
    """
    data = _smartctl_json(device)
    if not data:
        return None

    snap = {
        'device': device,
        'model': data.get('model_name') or data.get('model_family') or '',
        'serial': data.get('serial_number') or '',
        'protocol': (data.get('device') or {}).get('protocol') or '',
        'smart_passed': bool(((data.get('smart_status') or {}).get('passed', True))),
        'reallocated_sector_count': 0,
        'current_pending_sector':   0,
        'reported_uncorrectable':   0,
        'command_timeout':          0,
        'endurance_used_pct':       None,
        'power_on_hours':           0,
    }

    # Power-on hours is always in the same place
    poh = (data.get('power_on_time') or {}).get('hours')
    if isinstance(poh, int):
        snap['power_on_hours'] = poh

    # NVMe vs SATA / ATA pathways
    nvme_log = data.get('nvme_smart_health_information_log')
    if isinstance(nvme_log, dict):
        # NVMe — different attribute set
        snap['endurance_used_pct'] = nvme_log.get('percentage_used')
        snap['reported_uncorrectable'] = int(nvme_log.get('media_errors') or 0)
        # NVMe doesn't have reallocated/pending in the same sense; we use
        # critical_warning bits (bit 2 = reliability degraded) but only as
        # an extra signal under smart_passed.
        if int(nvme_log.get('critical_warning') or 0) != 0:
            snap['smart_passed'] = False
    else:
        # ATA / SATA SSD attributes
        v = _extract_ata_attribute(data, 5)   # Reallocated_Sector_Ct
        if v is not None:
            snap['reallocated_sector_count'] = v
        v = _extract_ata_attribute(data, 197) # Current_Pending_Sector
        if v is not None:
            snap['current_pending_sector'] = v
        v = _extract_ata_attribute(data, 187) # Reported_Uncorrect
        if v is not None:
            snap['reported_uncorrectable'] = v
        v = _extract_ata_attribute(data, 188) # Command_Timeout
        if v is not None:
            snap['command_timeout'] = v
        # Endurance: try a few attribute names — vendors disagree.
        # Intel/Micron: Percent_Lifetime_Remain (attr 233 raw OR normalized
        # 100=fresh, drops to 1=worn). Easier approach: read normalized
        # value of attr 233 if present, convert.
        # Fallback: attr 177 Wear_Leveling_Count normalized.
        for attr_id in (233, 177, 231):
            table = ((data.get('ata_smart_attributes') or {}).get('table') or [])
            for entry in table:
                if entry.get('id') == attr_id:
                    norm = entry.get('value')
                    if isinstance(norm, int) and 0 <= norm <= 100:
                        # Normalized value: 100 = fresh, decreases with wear.
                        # Convert to "used %": 100 - norm.
                        snap['endurance_used_pct'] = 100 - norm
                        break
            if snap['endurance_used_pct'] is not None:
                break

    return snap


def _stable_counters(snap):
    """Subset of snapshot fields that should NEVER change on a healthy
    drive — this is what goes into posture_state.current_value for
    transition diffing. Endurance is intentionally excluded (creeps up
    daily by design, would trip transitions every run)."""
    return {
        'smart_passed': snap['smart_passed'],
        'reallocated_sector_count': snap['reallocated_sector_count'],
        'current_pending_sector':   snap['current_pending_sector'],
        'reported_uncorrectable':   snap['reported_uncorrectable'],
        'command_timeout':          snap['command_timeout'],
    }


def _previous_drive(previous, device, serial):
    """Locate the matching drive snapshot in previous run's stored value.
    Match by serial first (stable across reboots / re-cabling), fall
    back to device name."""
    if not previous:
        return None
    drives = (previous.get('value') or {}).get('drives') or {}
    if serial:
        for k, prev in drives.items():
            if prev.get('serial') == serial:
                return prev
    return drives.get(device)


def _assess_drive(snap, prev):
    """Decide severity / status / detail for one drive given current
    snapshot and optional previous snapshot. Returns
    (severity, status, detail)."""
    device = snap['device']
    label = device + (' [' + snap['model'] + ']' if snap['model'] else '')

    # 1. Drive's self-assessment is the strongest signal
    if not snap['smart_passed']:
        return (Severity.CRITICAL, Status.FAIL,
                "{l}: SMART overall health FAILED — replace IMMEDIATELY".format(l=label))

    # 2. Growth detection vs previous run (only when we have a previous)
    if prev:
        deltas = {}
        for key in ('reallocated_sector_count', 'current_pending_sector',
                    'reported_uncorrectable', 'command_timeout'):
            cur = snap.get(key, 0) or 0
            old = prev.get(key, 0) or 0
            if cur > old:
                deltas[key] = cur - old
        if deltas:
            bits = []
            if 'reallocated_sector_count' in deltas:
                bits.append("+{n} reallocated".format(n=deltas['reallocated_sector_count']))
            if 'current_pending_sector' in deltas:
                bits.append("+{n} pending".format(n=deltas['current_pending_sector']))
            if 'reported_uncorrectable' in deltas:
                bits.append("+{n} uncorrectable".format(n=deltas['reported_uncorrectable']))
            if 'command_timeout' in deltas:
                bits.append("+{n} cmd timeouts".format(n=deltas['command_timeout']))
            return (Severity.HIGH, Status.FAIL,
                    "{l}: {b} since last scan — drive is failing, plan replacement"
                    .format(l=label, b=', '.join(bits)))

    # 3. Endurance thresholds (independent of growth)
    used = snap.get('endurance_used_pct')
    if used is not None:
        remaining = 100 - used
        if used >= ENDURANCE_CRITICAL:
            return (Severity.CRITICAL, Status.FAIL,
                    "{l}: SSD endurance {u}% used (only {r}% life left) — replace NOW"
                    .format(l=label, u=used, r=remaining))
        if used >= ENDURANCE_HIGH:
            return (Severity.HIGH, Status.FAIL,
                    "{l}: SSD endurance {u}% used ({r}% left) — replace soon"
                    .format(l=label, u=used, r=remaining))
        if used >= ENDURANCE_MEDIUM:
            return (Severity.MEDIUM, Status.WARN,
                    "{l}: SSD endurance {u}% used ({r}% left) — plan replacement"
                    .format(l=label, u=used, r=remaining))

    # 4. Existing wear with no recent growth — informational
    if (snap.get('reallocated_sector_count', 0) > 0
            or snap.get('current_pending_sector', 0) > 0):
        return (Severity.MEDIUM, Status.WARN,
                "{l}: {r} reallocated, {p} pending (no recent growth, monitor)".format(
                    l=label,
                    r=snap.get('reallocated_sector_count', 0),
                    p=snap.get('current_pending_sector', 0)))

    # 5. Healthy
    detail_bits = ["{u}% used".format(u=used)] if used is not None else []
    if snap.get('power_on_hours'):
        detail_bits.append("{h}h on".format(h=snap['power_on_hours']))
    suffix = " ({b})".format(b=', '.join(detail_bits)) if detail_bits else ""
    return (Severity.INFO, Status.PASS,
            "{l}: healthy{s}".format(l=label, s=suffix))


# Severity ranking for "worst across drives" aggregation.
_SEVERITY_RANK = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
    Severity.HIGH: 3, Severity.CRITICAL: 4,
}


class SmartCheck(Check):
    check_id = 'smart'
    module = Module.HEALTH
    severity = Severity.MEDIUM   # default; per-result override is the
                                 # interesting one (CRITICAL on FAIL, etc.)
    description = 'SMART drive health: overall status, reallocated/pending/uncorr counters with growth detection, SSD endurance'

    def applies_to(self, profile):
        # Linux + bare metal. SMART through virtio is rarely meaningful.
        if not profile.get('is_linux', True):
            return False
        extras = profile.get('extras') or {}
        if extras.get('is_virtualized'):
            return False
        return True

    def run(self, profile, previous=None):
        if not _smartctl_present():
            return CheckResult.warning(
                detail="smartctl not installed — `dnf install smartmontools` (or apt) to enable",
                value={'drives': {}, 'reason': 'smartctl_missing'},
                severity=Severity.LOW,
            )

        devices = _discover_drives()
        if not devices:
            return CheckResult.warning(
                detail="no physical disks discovered via lsblk",
                value={'drives': {}, 'reason': 'no_drives'},
                severity=Severity.LOW,
            )

        snapshots = []
        per_drive_assessments = []
        for device in devices:
            snap = _drive_snapshot(device)
            if snap is None:
                # Probe failed for this drive — skip but note it
                logger.debug("smartctl probe failed for /dev/%s", device)
                continue
            prev = _previous_drive(previous, device, snap['serial'])
            severity, status, detail = _assess_drive(snap, prev)
            snapshots.append(snap)
            per_drive_assessments.append({
                'device': device, 'severity': severity,
                'status': status, 'detail': detail,
            })

        if not snapshots:
            return CheckResult.errored(
                detail=("smartctl found drives ({n}) but couldn't read SMART "
                        "from any of them".format(n=len(devices))),
                value={'drives': {}, 'devices_attempted': devices},
            )

        # Aggregate: take the worst severity / status across drives
        worst_idx = max(
            range(len(per_drive_assessments)),
            key=lambda i: _SEVERITY_RANK.get(per_drive_assessments[i]['severity'], 0),
        )
        worst = per_drive_assessments[worst_idx]

        # Build the stored value — use stable counters per drive so the
        # orchestrator's diff doesn't fire on creeping endurance.
        stored_drives = {}
        for snap in snapshots:
            stored = _stable_counters(snap)
            stored['serial'] = snap['serial']  # for cross-run matching
            stored_drives[snap['device']] = stored

        value = {'drives': stored_drives}

        # Compose detail: lead with the worst drive, then short summary
        # of the rest if they're all healthy.
        if len(per_drive_assessments) == 1:
            detail = worst['detail']
        else:
            detail_lines = [worst['detail']]
            others = [a for i, a in enumerate(per_drive_assessments) if i != worst_idx]
            if all(a['status'] == Status.PASS for a in others):
                detail_lines.append("{n} other drive(s) healthy".format(n=len(others)))
            else:
                for a in others:
                    detail_lines.append(a['detail'])
            detail = ' | '.join(detail_lines)

        return CheckResult(
            status=worst['status'],
            value=value,
            detail=detail,
            severity_override=worst['severity'],
        )
