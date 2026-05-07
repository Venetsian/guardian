"""
/tmp hygiene observation — passive LOW-severity signal.

Counts root-owned, world-readable entries in the top level of /tmp that
are older than 7 days. Flags count > threshold (default 5) with a file
list in the detail. Read-only even on hosts where the active-cleanup
module (Phase 5) is disabled — gives the operator visibility into
operational bloat without touching anything.

Scope:
  * Top-level entries in /tmp only. Recursing into per-user subdirs
    creates lots of noise (systemd-private-*, snap-private-*).
  * Symlinks are ignored (we don't follow them).
  * Directories owned by uid 0 still count, because operator-dropped
    leftovers like 'claude-0/' or extracted 'Divi.zip'-style detritus
    show up that way.

Severity is intentionally pinned at LOW — operational hygiene isn't a
security drift on its own. The active-cleanup module (Phase 5) is what
acts on this; this check is the always-on visibility layer.

Stored value is intentionally coarse — just the threshold-crossed bool —
so day-to-day count fluctuations don't trip a transition every run.
Only the over/under crossing fires an event. The detail field still
carries the full count + sample for forensics.
"""

import logging
import os
import time

from posture_checks.base import Check, CheckResult, Severity

logger = logging.getLogger('wp-guardian.posture.tmp_hygiene')


AGE_SECONDS_DEFAULT = 7 * 86400
THRESHOLD_DEFAULT = 5
TMP_PATH = '/tmp'
SAMPLE_COUNT = 10   # how many filenames to surface in the detail string


def _is_world_readable(mode):
    return bool(mode & 0o004)


def _scan_tmp(now, age_seconds):
    """Return list of {'name', 'size', 'age_days', 'is_dir'} dicts for
    matching top-level /tmp entries. Never raises."""
    matches = []
    try:
        scanner = os.scandir(TMP_PATH)
    except OSError:
        return matches
    try:
        for entry in scanner:
            try:
                if entry.is_symlink():
                    continue
                stat = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.st_uid != 0:
                continue
            if not _is_world_readable(stat.st_mode):
                continue
            age = now - stat.st_mtime
            if age < age_seconds:
                continue
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                is_dir = False
            matches.append({
                'name': entry.name,
                'size': stat.st_size,
                'age_days': int(age // 86400),
                'is_dir': is_dir,
            })
    finally:
        try:
            scanner.close()
        except Exception:
            pass
    return matches


def _format_size(size_bytes):
    kb = size_bytes / 1024.0
    if kb >= 1024:
        return '{:.1f}MB'.format(kb / 1024.0)
    return '{:.0f}KB'.format(kb)


class TmpHygieneCheck(Check):
    check_id = 'tmp_hygiene'
    severity = Severity.LOW
    description = '/tmp bloat: root-owned, world-readable entries older than 7 days'

    def applies_to(self, profile):
        return bool(profile.get('is_linux', True))

    def run(self, profile, previous=None):
        if not os.path.isdir(TMP_PATH):
            return CheckResult.errored(
                detail="/tmp not present (is this Linux?)",
                value={'over_threshold': False, 'threshold': THRESHOLD_DEFAULT},
            )

        now = time.time()
        matches = _scan_tmp(now, AGE_SECONDS_DEFAULT)
        count = len(matches)
        total_size = sum(m['size'] for m in matches)
        over = count > THRESHOLD_DEFAULT

        value = {
            'over_threshold': over,
            'threshold': THRESHOLD_DEFAULT,
        }

        if not over:
            if count == 0:
                detail = "/tmp clean — no root-owned world-readable entries >7d"
            else:
                detail = ("/tmp has {n} stale root-owned entry(ies) (under threshold of {t})"
                          .format(n=count, t=THRESHOLD_DEFAULT))
            return CheckResult.passing(detail=detail, value=value)

        sample = sorted(matches, key=lambda m: m['size'], reverse=True)[:SAMPLE_COUNT]
        sample_strs = []
        for m in sample:
            tag = '/' if m['is_dir'] else ''
            sample_strs.append("{n}{t} ({sz}, {a}d)".format(
                n=m['name'], t=tag, sz=_format_size(m['size']), a=m['age_days'],
            ))
        more = ('' if count <= SAMPLE_COUNT
                else ', +{n} more'.format(n=count - SAMPLE_COUNT))
        total_mb = total_size / (1024.0 * 1024.0)
        detail = ("/tmp has {n} stale root-owned entry(ies) (>7d, {tot:.1f}MB total): {s}{more}"
                  .format(n=count, tot=total_mb, s=', '.join(sample_strs), more=more))
        return CheckResult.warning(detail=detail, value=value, severity=Severity.LOW)
