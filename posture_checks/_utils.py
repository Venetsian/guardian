"""
Shared internal helpers used by multiple posture checks.

Kept separate from `base.py` so the public Check ABC stays small and
focused, and so future checks have one obvious place to import these
common utilities from.

Functions exported:
  python_vercmp(a, b)  — pure-Python RPM/Debian-style version comparator
  distro_major(v)      — extract major from VERSION_ID ('9.4' -> '9')
  safe_run(cmd, ...)   — wrap subprocess.run, return (rc, stdout), never raises
"""

import logging
import re
import subprocess

logger = logging.getLogger('wp-guardian.posture.utils')


def python_vercmp(a, b):
    """Pure-Python RPM/Debian-style version comparator. Returns -1/0/1.

    Splits each string into runs of digits and runs of letters (separators
    like .-_+~ are dropped) and compares pairwise. Numeric segments compare
    numerically; alphabetic segments compare lexically; numeric segments
    sort GREATER than alphabetic at the same position (RPM convention —
    '1' > 'a').

    Handles real-world strings we care about:
      125-4.el10        vs 121-1.el10        ->  1   (125 > 121)
      0.117-13.el9_4    vs 0.117-13.el9      ->  1   (extra '4' segment)
      5.14.0-611.49.2   vs 5.14.0-611.47.1   ->  1   (49 > 47)
      6.12.0-124.52.3   vs 6.12.0-124.52.2   ->  1   (3 > 2)

    Does NOT handle epoch prefixes or RPM tilde/caret pre-release ordering;
    we don't ship baselines that exercise those.
    """
    if a == b:
        return 0
    sa = re.findall(r'\d+|[A-Za-z]+', a or '')
    sb = re.findall(r'\d+|[A-Za-z]+', b or '')

    for ea, eb in zip(sa, sb):
        a_num = ea.isdigit()
        b_num = eb.isdigit()
        if a_num and b_num:
            ia, ib = int(ea), int(eb)
            if ia != ib:
                return -1 if ia < ib else 1
        elif a_num != b_num:
            # Numeric sorts greater than alphabetic at the same position
            return 1 if a_num else -1
        else:
            if ea != eb:
                return -1 if ea < eb else 1

    if len(sa) != len(sb):
        return -1 if len(sa) < len(sb) else 1
    return 0


def distro_major(version_id):
    """Extract the major version from VERSION_ID (e.g. '9.4' -> '9')."""
    if not version_id:
        return ''
    return version_id.split('.', 1)[0].strip()


def safe_run(cmd, timeout=5):
    """Run `cmd`, return (returncode, stdout). Never raises.

    On OSError or TimeoutExpired returns (-1, '') and logs at debug.
    """
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
