"""
PwnKit (CVE-2021-4034) — polkit/pkexec local privilege escalation.

Severity: CRITICAL on every Linux host. The vuln is widespread, easy to
exploit, and grants root from any unprivileged shell. Long since patched
upstream, but boxes left un-updated for months can still be vulnerable —
particularly long-lived staging or backup VMs that nobody touches.

Detection strategy:
  * Read polkit's installed version via the package manager (rpm or dpkg).
  * Compare against the distro-specific minimum patched version.

Patched versions (sources: vendor advisories):
  * RHEL/AlmaLinux/Rocky 9      polkit-0.117-13.el9      (or newer)
  * RHEL/AlmaLinux/Rocky 8      polkit-0.115-13.el8_5.2  (or newer)
  * CloudLinux 9 / 8            tracks the EL stream above
  * Debian 11 (bullseye)        policykit-1 0.105-31+deb11u1
  * Debian 12 (bookworm)        policykit-1 0.105-33
  * Ubuntu 20.04                policykit-1 0.105-26ubuntu1.2
  * Ubuntu 22.04                policykit-1 0.105-31ubuntu0.1

We don't try to be exhaustive — for any distro/version we don't know we
fall back to a string compare against the minimum tag and warn the
operator that the rule is best-effort.
"""

import logging
import os

from posture_checks.base import Check, CheckResult, Severity, Status
from posture_checks._utils import python_vercmp, distro_major

logger = logging.getLogger('wp-guardian.posture.pwnkit')


# Minimum patched versions per distro family, keyed by /etc/os-release ID
# and the major version stripped from VERSION_ID.
#
# Each entry is the package name we ask the package manager about, plus a
# version string we'll string-compare against (rpmdev-vercmp / dpkg
# --compare-versions when available; coarse string compare otherwise).
_MIN_PATCHED = {
    # RHEL 10 family. Upstream polkit was rewritten and switched from 0.x
    # versioning to a single integer (121, 122, ...); EL10 ships polkit-125
    # (verified on AlmaLinux 10.1: polkit-125-4.el10). The rewrite is
    # post-PwnKit by construction, so any 3-digit version >= 121 is patched.
    # Floor at 121-1.el10 so all real EL10 builds pass.
    ('rhel', '10'):        ('polkit', '121-1.el10'),
    ('almalinux', '10'):   ('polkit', '121-1.el10'),
    ('rocky', '10'):       ('polkit', '121-1.el10'),
    ('cloudlinux', '10'):  ('polkit', '121-1.el10'),
    # RHEL family — polkit (0.x version line, EL8/EL9)
    ('rhel', '9'):         ('polkit', '0.117-13.el9'),
    ('almalinux', '9'):    ('polkit', '0.117-13.el9'),
    ('rocky', '9'):        ('polkit', '0.117-13.el9'),
    ('cloudlinux', '9'):   ('polkit', '0.117-13.el9'),
    ('rhel', '8'):         ('polkit', '0.115-13.el8_5.2'),
    ('almalinux', '8'):    ('polkit', '0.115-13.el8_5.2'),
    ('rocky', '8'):        ('polkit', '0.115-13.el8_5.2'),
    ('cloudlinux', '8'):   ('polkit', '0.115-13.el8_5.2'),
    # Debian family — policykit-1 (older) / polkitd (newer)
    ('debian', '11'):      ('policykit-1', '0.105-31+deb11u1'),
    ('debian', '12'):      ('polkitd', '0.105-33'),
    ('ubuntu', '20'):      ('policykit-1', '0.105-26ubuntu1.2'),
    ('ubuntu', '22'):      ('policykit-1', '0.105-31ubuntu0.1'),
    ('ubuntu', '24'):      ('polkitd', '124-2ubuntu1'),
}


def _query_rpm(pkg):
    """Return installed RPM version-release for `pkg`, or '' if missing."""
    import subprocess
    try:
        proc = subprocess.run(
            ['rpm', '-q', '--queryformat', '%{VERSION}-%{RELEASE}', pkg],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=5, universal_newlines=True,
        )
        if proc.returncode != 0:
            return ''
        return (proc.stdout or '').strip()
    except (OSError, subprocess.TimeoutExpired):
        return ''


def _query_dpkg(pkg):
    """Return installed dpkg version for `pkg`, or '' if missing."""
    import subprocess
    try:
        proc = subprocess.run(
            ['dpkg-query', '-W', '-f=${Version}', pkg],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=5, universal_newlines=True,
        )
        if proc.returncode != 0:
            return ''
        return (proc.stdout or '').strip()
    except (OSError, subprocess.TimeoutExpired):
        return ''


def _rpm_vercmp(a, b):
    """RPM-style version comparison. Returns -1/0/1.

    Tries `rpmdev-vercmp` (canonical, from rpmdevtools) first; falls back
    to the pure-Python comparator when that package isn't installed —
    which is the common case on stock AlmaLinux/Rocky/CloudLinux. Never
    returns None: we always produce a real answer.
    """
    import subprocess
    if os.path.exists('/usr/bin/rpmdev-vercmp'):
        try:
            proc = subprocess.run(
                ['rpmdev-vercmp', a, b],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=5, universal_newlines=True,
            )
            # rpmdev-vercmp exit codes: 0 equal, 11 a>b, 12 a<b
            if proc.returncode == 0:
                return 0
            if proc.returncode == 11:
                return 1
            if proc.returncode == 12:
                return -1
        except (OSError, subprocess.TimeoutExpired):
            pass
    return python_vercmp(a, b)


def _dpkg_vercmp(a, b):
    """Debian-style version comparison. Returns -1/0/1.

    Tries `dpkg --compare-versions` first (always present on Debian/Ubuntu);
    falls back to the pure-Python comparator if dpkg isn't reachable.
    """
    import subprocess
    try:
        eq = subprocess.run(['dpkg', '--compare-versions', a, 'eq', b],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        if eq.returncode == 0:
            return 0
        gt = subprocess.run(['dpkg', '--compare-versions', a, 'gt', b],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        if gt.returncode == 0:
            return 1
        return -1
    except (OSError, subprocess.TimeoutExpired):
        return python_vercmp(a, b)


class PwnKitCheck(Check):
    check_id = 'pwnkit'
    severity = Severity.CRITICAL
    description = 'polkit/pkexec patched against CVE-2021-4034 (PwnKit)'

    def applies_to(self, profile):
        # Linux only. We don't try to gate on distro_id == known —
        # an unknown distro will surface as a UNKNOWN result with a
        # helpful detail string rather than silently skipping.
        return bool(profile.get('is_linux', True))

    def run(self, profile, previous=None):
        # `previous` is unused — this check is stateless (just compares
        # current installed polkit against the patched-version baseline).
        distro_id = (profile.get('distro_id') or '').lower()
        major = distro_major(profile.get('distro_version'))
        key = (distro_id, major)

        baseline = _MIN_PATCHED.get(key)
        if not baseline:
            # We don't have a patched-version table for this distro/major.
            # Don't claim CRITICAL — that would create false positives.
            # Return WARN so the operator knows the check ran but couldn't
            # decide.
            return CheckResult.warning(
                detail=("no PwnKit baseline known for {d}/{m}; manual review needed"
                        .format(d=distro_id or '?', m=major or '?')),
                value={'distro': distro_id, 'major': major,
                       'installed': '', 'min_patched': ''},
                severity=Severity.LOW,
            )

        pkg, min_version = baseline

        # Pick the right package manager probe + version comparator
        if distro_id in ('rhel', 'almalinux', 'rocky', 'cloudlinux', 'centos', 'fedora'):
            installed = _query_rpm(pkg)
            comparator = 'rpm'
            cmp_fn = _rpm_vercmp
        elif distro_id in ('debian', 'ubuntu'):
            installed = _query_dpkg(pkg)
            comparator = 'dpkg'
            cmp_fn = _dpkg_vercmp
        else:
            installed = ''
            comparator = 'unknown'
            cmp_fn = None

        if not installed:
            # Package not present at all — depending on distro this might
            # mean polkit isn't installed (rare but possible on minimal VMs)
            # or rpm/dpkg isn't on PATH. Either way, can't decide.
            return CheckResult.warning(
                detail="{p} not found via package manager".format(p=pkg),
                value={'distro': distro_id, 'major': major,
                       'installed': '', 'min_patched': min_version},
                severity=Severity.LOW,
            )

        if cmp_fn is None:
            # Unknown distro family — _MIN_PATCHED only ships entries for
            # rpm/dpkg families, so reaching here means a baseline was added
            # for a distro we don't know how to query. Surface as WARN.
            return CheckResult.warning(
                detail=("baseline known for {d}/{m} but no version comparator "
                        "for that distro family".format(d=distro_id, m=major)),
                value={'distro': distro_id, 'major': major,
                       'installed': installed, 'min_patched': min_version},
                severity=Severity.LOW,
            )

        cmp_result = cmp_fn(installed, min_version)

        value = {
            'distro': distro_id,
            'major': major,
            'installed': installed,
            'min_patched': min_version,
            'package': pkg,
            'comparator': comparator,
        }

        if cmp_result >= 0:
            return CheckResult.passing(
                detail=("{p}={v} >= {m} (patched)"
                        .format(p=pkg, v=installed, m=min_version)),
                value=value,
            )

        # Vulnerable
        return CheckResult.failing(
            detail=("{p}={v} is BELOW patched {m} on {d}{maj} — "
                    "PwnKit (CVE-2021-4034) likely exploitable"
                    .format(p=pkg, v=installed, m=min_version,
                            d=distro_id, maj=major)),
            value=value,
            severity=Severity.CRITICAL,
        )
