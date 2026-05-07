"""
SUID/SGID baseline drift — flag new (or modified) setuid binaries since
the last scan.

We deliberately self-baseline rather than ship a hardcoded per-distro
table:
  * Hardcoded baselines drift across minor distro releases (a polkit
    update relocates pkexec, an httpd update moves suexec, etc.) and
    generate false-positive HIGH alerts on every upgrade.
  * The operator's "what's normal on this host" is more accurate than
    ours after one successful run.

So: first run captures the current set silently as PASS (with the count
in the detail so the operator can eyeball it via `--posture-status`).
Subsequent runs diff against the previous stored set and flag additions
or modifications. Once the operator has reviewed an alert and decides
the new binary is legitimate, the next run absorbs it as the new
baseline (same self-healing model the SMART check uses for stable
counters that have already been reported).

Scope:
  * Standard system bin directories only — /usr/bin, /usr/sbin, /bin,
    /sbin, /usr/local/{bin,sbin}, /usr/libexec.
  * No deep filesystem walk; `find / -perm -4000` is comprehensive but
    too slow for daily runs. The interesting SUID binaries (sudo, su,
    pkexec, mount, ping, etc.) all live in these paths.
  * Symlinks are skipped to avoid double-counting.

Severity:
  * HIGH on additions — a new SUID binary is the highest-signal drift.
  * MEDIUM on removals or mode/owner changes only — less alarming but
    worth knowing (package downgrade, accidental chmod, etc.).
"""

import logging
import os
import stat as stat_mod

from posture_checks.base import Check, CheckResult, Severity

logger = logging.getLogger('wp-guardian.posture.suid_baseline')


SCAN_PATHS = (
    '/usr/bin', '/usr/sbin',
    '/bin', '/sbin',
    '/usr/local/bin', '/usr/local/sbin',
    '/usr/libexec',
)
SAMPLE_LIMIT = 5  # how many path names to surface in the detail string


def _scan_suid_dir(d, recurse_one_level=False):
    """Return list of {'path','uid','gid','bits'} for SUID/SGID binaries
    directly inside `d`. With recurse_one_level=True, also descends one
    level (used for /usr/libexec/<subsystem>/ entries)."""
    found = []
    try:
        scanner = os.scandir(d)
    except OSError:
        return found
    try:
        for entry in scanner:
            try:
                if entry.is_symlink():
                    continue
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            mode = st.st_mode
            if stat_mod.S_ISDIR(mode):
                if recurse_one_level:
                    found.extend(_scan_suid_dir(entry.path, recurse_one_level=False))
                continue
            if not stat_mod.S_ISREG(mode):
                continue
            if not (mode & (stat_mod.S_ISUID | stat_mod.S_ISGID)):
                continue
            bits = ''
            if mode & stat_mod.S_ISUID:
                bits += 's'
            if mode & stat_mod.S_ISGID:
                bits += 'g'
            found.append({
                'path': entry.path,
                'uid': st.st_uid,
                'gid': st.st_gid,
                'bits': bits,
            })
    finally:
        try:
            scanner.close()
        except Exception:
            pass
    return found


def _scan_all_paths():
    """Walk SCAN_PATHS and return one sorted list of SUID/SGID binaries.
    /usr/libexec gets a one-level-deep recurse because its layout is
    /usr/libexec/<subsystem>/<binary> (sudo/sesh, openssh/ssh-keysign).
    """
    out = []
    for d in SCAN_PATHS:
        if not os.path.isdir(d):
            continue
        recurse = (d == '/usr/libexec')
        out.extend(_scan_suid_dir(d, recurse_one_level=recurse))
    return sorted(out, key=lambda e: e['path'])


class SuidBaselineCheck(Check):
    check_id = 'suid_baseline'
    severity = Severity.HIGH
    description = 'SUID/SGID binary baseline drift (new or modified setuid binaries since last scan)'

    def applies_to(self, profile):
        return bool(profile.get('is_linux', True))

    def run(self, profile, previous=None):
        binaries = _scan_all_paths()
        value = {'binaries': binaries}

        # First run: silently establish the baseline. The orchestrator
        # already dampens non-CRITICAL alerts on the very first run, but
        # we ALSO want PASS status (not WARN) so --posture-status looks
        # clean afterwards.
        prev_binaries = ((previous or {}).get('value') or {}).get('binaries') or []
        if not prev_binaries:
            return CheckResult.passing(
                detail="SUID baseline established: {n} binary(ies) under system bin paths"
                       .format(n=len(binaries)),
                value=value,
            )

        prev_map = {b['path']: b for b in prev_binaries}
        cur_map = {b['path']: b for b in binaries}

        added = sorted(set(cur_map) - set(prev_map))
        removed = sorted(set(prev_map) - set(cur_map))
        changed = []
        for path in (set(cur_map) & set(prev_map)):
            cur, old = cur_map[path], prev_map[path]
            if (cur['uid'] != old['uid']
                    or cur['gid'] != old['gid']
                    or cur['bits'] != old['bits']):
                changed.append(path)
        changed.sort()

        if not (added or removed or changed):
            return CheckResult.passing(
                detail="SUID set unchanged ({n} binary(ies))".format(n=len(binaries)),
                value=value,
            )

        def _truncate(items):
            if len(items) <= SAMPLE_LIMIT:
                return ', '.join(items)
            return '{}, +{} more'.format(
                ', '.join(items[:SAMPLE_LIMIT]), len(items) - SAMPLE_LIMIT)

        bits = []
        if added:
            bits.append("added: {p}".format(p=_truncate(added)))
        if removed:
            bits.append("removed: {p}".format(p=_truncate(removed)))
        if changed:
            bits.append("mode/owner changed: {p}".format(p=_truncate(changed)))

        # Severity: a NEW SUID binary is the highest-signal drift.
        # Pure removals or owner-only changes are MEDIUM.
        sev = Severity.HIGH if added else Severity.MEDIUM
        return CheckResult.failing(
            detail='; '.join(bits),
            value=value,
            severity=sev,
        )
