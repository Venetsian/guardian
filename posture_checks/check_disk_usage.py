"""
Disk usage thresholds — host-health module.

Monitors free space on key partitions. The partition set is profile-driven:
  * always:                       /, /home, /var
  * web_server in (apache, ols):  /var/log
  * db_server in (mariadb, mysql): /var/lib/mysql

Partitions sharing the same st_dev (e.g. /home not separate from /) are
deduped so we don't report the same usage three times.

Severity ladder (worst across all monitored partitions wins):
  *  >= 85% used  → HIGH (status FAIL)
  *  >= 75% used  → MEDIUM (status WARN)
  *  otherwise    → PASS

Stored value is intentionally coarse — bucket per partition. Day-to-day
percentage wiggles don't trip a transition; only a threshold crossing
does. (Growth-trend detection — '+10% in a week' — is deferred; it
needs a separate historical sample table that doesn't exist yet.)
"""

import logging
import os

from posture_checks.base import Check, CheckResult, Severity, Module

logger = logging.getLogger('wp-guardian.posture.disk_usage')


THRESHOLD_HIGH = 85
THRESHOLD_MEDIUM = 75


def _statvfs_safe(path):
    try:
        return os.statvfs(path)
    except OSError:
        return None


def _percent_used(stat):
    if stat is None or stat.f_blocks == 0:
        return None
    used = stat.f_blocks - stat.f_bavail
    return int(round(100.0 * used / stat.f_blocks))


def _select_partitions(profile):
    """Return list of (label, path) for partitions worth monitoring.
    Dedupes by st_dev (same underlying filesystem reported once)."""
    relevant = ['/', '/home', '/var']
    if profile.get('web_server') in ('apache', 'ols'):
        relevant.append('/var/log')
    if profile.get('db_server') in ('mariadb', 'mysql'):
        relevant.append('/var/lib/mysql')

    out = []
    seen_devs = set()
    for path in relevant:
        if not os.path.isdir(path):
            continue
        try:
            st = os.stat(path)
        except OSError:
            continue
        if st.st_dev in seen_devs:
            continue
        seen_devs.add(st.st_dev)
        out.append((path, path))
    return out


def _bucket(pct):
    if pct >= THRESHOLD_HIGH:
        return 'high'
    if pct >= THRESHOLD_MEDIUM:
        return 'medium'
    return 'ok'


class DiskUsageCheck(Check):
    check_id = 'disk_usage'
    module = Module.HEALTH
    severity = Severity.MEDIUM
    description = ('Disk usage on key partitions '
                   '(root, /home, /var, /var/log, /var/lib/mysql)')

    def applies_to(self, profile):
        return bool(profile.get('is_linux', True))

    def run(self, profile, previous=None):
        partitions = _select_partitions(profile)
        if not partitions:
            return CheckResult.errored(
                detail="couldn't statvfs any monitored partition",
                value={'reason': 'statvfs_failed'},
            )

        per_part = {}
        worst_pct = -1
        worst_label = ''
        for label, path in partitions:
            stat = _statvfs_safe(path)
            pct = _percent_used(stat)
            if pct is None:
                continue
            per_part[label] = pct
            if pct > worst_pct:
                worst_pct = pct
                worst_label = label

        if not per_part:
            return CheckResult.errored(
                detail="statvfs returned zero blocks on every monitored partition",
                value={'reason': 'zero_blocks'},
            )

        # Coarse bucket per partition — so diffs only fire on threshold
        # crossings, not on daily wiggles.
        value = {
            'buckets': {label: _bucket(pct) for label, pct in per_part.items()},
        }

        summary = ', '.join('{l}: {p}%'.format(l=l, p=p)
                            for l, p in sorted(per_part.items()))

        if worst_pct >= THRESHOLD_HIGH:
            return CheckResult.failing(
                detail="{l} at {p}% — {s}".format(
                    l=worst_label, p=worst_pct, s=summary),
                value=value,
                severity=Severity.HIGH,
            )
        if worst_pct >= THRESHOLD_MEDIUM:
            return CheckResult.warning(
                detail="{l} at {p}% — {s}".format(
                    l=worst_label, p=worst_pct, s=summary),
                value=value,
                severity=Severity.MEDIUM,
            )
        return CheckResult.passing(detail=summary, value=value)
