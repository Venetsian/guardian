"""
Generic pending-security-updates posture check (task #123 Layer 2a).

Replaces hand-coded per-CVE checks for the long tail. Distro security
teams curate the "this is a security errata" tag — we just consult
their feed. The named-CVE checks (`pwnkit`, `kernel_copy_fail`) stay
as overrides for high-priority bugs where the distro's own severity
tagging is too quiet or the alert needs to fire before the errata
shows up.

Probes:
  RHEL/CL/Alma/Rocky/CentOS  8+:  `dnf updateinfo list security --quiet`
  RHEL/CL                     7:  `yum --security check-update`
  Debian/Ubuntu/Mint:             `apt list --upgradable` filtered for
                                  *-security suite

Severity ladder (worst across pending items wins):
  0 pending                       → PASS
  any Moderate / Low / unclassified  → LOW
  any Important                   → MEDIUM
  any Critical                    → HIGH
  Critical AND kernel package     → CRITICAL

Stored value is bucket-only so day-to-day errata count drift doesn't
fire transitions; only severity-class crossings (or kernel-critical
appearing) do. Detail string carries the full count breakdown for
forensics.
"""

import logging
import re

from posture_checks.base import Check, CheckResult, Severity
from posture_checks._utils import safe_run

logger = logging.getLogger('wp-guardian.posture.security_updates')


# RHSA / DNF severity classes, ordered worst-first
DNF_CLASSES = ('Critical', 'Important', 'Moderate', 'Low')

# Kernel package match — covers kernel, kernel-core, kernel-modules,
# kernel.x86_64, etc., plus CL-specific kmod-* if needed.
_KERNEL_PKG_RE = re.compile(r'^(kernel|kmod-)(-|\.|_|$)', re.IGNORECASE)

# Pattern for a typical NVRA in `yum check-update` / `apt list` output:
# starts with [a-z0-9._+-], whitespace, then version.
_PKG_LINE_RE = re.compile(r'^([A-Za-z0-9._\-+]+)\s+\S+')


_EL_FAMILY = {
    'rhel', 'almalinux', 'rocky', 'centos', 'cloudlinux', 'cl', 'fedora', 'ol',
}
_DEB_FAMILY = {'debian', 'ubuntu', 'linuxmint'}


def _is_el_family(distro_id):
    return (distro_id or '').lower() in _EL_FAMILY


def _is_debian_family(distro_id):
    return (distro_id or '').lower() in _DEB_FAMILY


# ---------------------------------------------------------------------------
# Probes — each returns dict[class -> [pkg names]] or None on probe failure
# ---------------------------------------------------------------------------

def _probe_dnf_updateinfo():
    """EL8+/CL8+ probe. `dnf updateinfo list security` per-line:
        RHSA-2024:1234 Important/Sec.  kernel-1.2.3-...x86_64
    """
    rc, out = safe_run(
        ['dnf', 'updateinfo', 'list', 'security', '--quiet'],
        timeout=20,
    )
    # rc=0 normal (with or without rows); rc=100 not used by `list`
    if rc < 0:
        return None
    return _parse_dnf_table(out)


def _parse_dnf_table(out):
    by_class = {c: [] for c in DNF_CLASSES}
    by_class['Other'] = []
    for line in (out or '').splitlines():
        line = line.strip()
        if not line:
            continue
        # Skip headers / metadata banners
        low = line.lower()
        if 'metadata' in low or low.startswith('last metadata'):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        # parts[0] = advisory id, parts[1] = "Class/Type", parts[2] = pkg
        klass_field = parts[1]
        klass = klass_field.split('/', 1)[0]
        pkg = parts[2]
        if klass in DNF_CLASSES:
            by_class[klass].append(pkg)
        else:
            by_class['Other'].append(pkg)
    return by_class


def _probe_yum_security():
    """EL/CL 7 probe — yum doesn't tag classes per package. We treat all
    listed pending updates as 'Other' (we'll still surface the count and
    kernel detection works)."""
    rc, out = safe_run(['yum', '--security', 'check-update'], timeout=30)
    # rc=100 means updates available; rc=0 means none; rc=1 is an error
    if rc < 0 or rc not in (0, 100):
        return None
    by_class = {c: [] for c in DNF_CLASSES}
    by_class['Other'] = []
    for line in (out or '').splitlines():
        line = line.rstrip()
        if not line or line.startswith((' ', '\t')):
            continue
        if line.startswith(('Loaded plugins', 'Loading mirror',
                            'Last metadata', '---')):
            continue
        m = _PKG_LINE_RE.match(line)
        if m:
            by_class['Other'].append(m.group(1))
    return by_class


def _probe_apt_security():
    """Debian/Ubuntu probe. `apt list --upgradable` lines look like:
        pkg/bookworm-security 1.2.3 amd64 [upgradable from: 1.2.2]
    We filter for the security suite. APT doesn't expose RHSA-style
    severity classes so everything counted goes into 'Other'.
    """
    rc, out = safe_run(['apt', 'list', '--upgradable'], timeout=15)
    if rc < 0:
        return None
    by_class = {c: [] for c in DNF_CLASSES}
    by_class['Other'] = []
    for line in (out or '').splitlines():
        if line.startswith('Listing'):
            continue
        if '/' not in line:
            continue
        # Suite token after the slash, before the first space
        suite_field = line.split('/', 1)[1].split(None, 1)[0]
        if 'security' not in suite_field.lower():
            continue
        pkg = line.split('/', 1)[0]
        by_class['Other'].append(pkg)
    return by_class


def _has_kernel(by_class):
    for pkgs in by_class.values():
        for pkg in pkgs:
            if _KERNEL_PKG_RE.match(pkg):
                return True
    return False


# ---------------------------------------------------------------------------
# Check
# ---------------------------------------------------------------------------

class SecurityUpdatesCheck(Check):
    check_id = 'security_updates'
    severity = Severity.MEDIUM   # default; per-result override is the real signal
    description = 'Pending OS security updates (distro-tagged errata)'

    def applies_to(self, profile):
        if not profile.get('is_linux', True):
            return False
        return (_is_el_family(profile.get('distro_id'))
                or _is_debian_family(profile.get('distro_id')))

    def run(self, profile, previous=None):
        distro = (profile.get('distro_id') or '').lower()
        version = profile.get('distro_version') or ''
        major = version.split('.', 1)[0] if version else ''

        if _is_el_family(distro):
            try:
                major_int = int(major)
            except ValueError:
                major_int = 8
            by_class = (_probe_dnf_updateinfo() if major_int >= 8
                        else _probe_yum_security())
        elif _is_debian_family(distro):
            by_class = _probe_apt_security()
        else:
            return CheckResult.errored(
                detail="distro {d!r} not recognized for security-update probe"
                       .format(d=distro),
                value={'reason': 'unknown_distro'},
            )

        if by_class is None:
            return CheckResult.errored(
                detail=("security-update probe failed (package manager not "
                        "available or returned an error)"),
                value={'reason': 'probe_failed'},
            )

        crit = len(by_class.get('Critical', []))
        imp = len(by_class.get('Important', []))
        mod = len(by_class.get('Moderate', []))
        low = len(by_class.get('Low', []))
        other = len(by_class.get('Other', []))
        total = crit + imp + mod + low + other
        kernel_pending = _has_kernel(by_class)

        if total == 0:
            return CheckResult.passing(
                detail="no pending security updates",
                value={'bucket': 'pass', 'has_kernel': False},
            )

        # Bucket + severity decision
        if crit > 0 and kernel_pending:
            sev, bucket = Severity.CRITICAL, 'kernel_critical'
        elif crit > 0:
            sev, bucket = Severity.HIGH, 'critical'
        elif imp > 0:
            sev, bucket = Severity.MEDIUM, 'important'
        else:
            sev, bucket = Severity.LOW, 'moderate_or_lower'

        value = {'bucket': bucket, 'has_kernel': kernel_pending}

        bits = []
        if crit:
            bits.append("{} critical".format(crit))
        if imp:
            bits.append("{} important".format(imp))
        if mod:
            bits.append("{} moderate".format(mod))
        if low:
            bits.append("{} low".format(low))
        if other:
            bits.append("{} other".format(other))
        kernel_tag = " (kernel update pending)" if kernel_pending else ""
        detail = "{n} pending security update(s): {b}{k}".format(
            n=total, b=', '.join(bits), k=kernel_tag,
        )

        # Status bucketing matches severity gravity
        if bucket in ('moderate_or_lower',):
            return CheckResult.warning(detail=detail, value=value, severity=sev)
        if bucket == 'important':
            return CheckResult.warning(detail=detail, value=value, severity=sev)
        return CheckResult.failing(detail=detail, value=value, severity=sev)
