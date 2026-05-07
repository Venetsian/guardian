"""
SELinux state — defense-in-depth visibility on EL-family hosts (#123 Layer 3).

On a multi-tenant box, SELinux Enforcing meaningfully limits the blast
radius of an exploit (e.g. PHP web shells writing outside their type
context, daemons connecting to ports they don't own). Disabled means
the kernel module isn't even active; Permissive means it's loaded but
only logs violations. Either non-Enforcing state is information the
operator wants surfaced — and on a multi-tenant box, Disabled rises to
MEDIUM because it's a real isolation degradation.

We deliberately do NOT remediate. Re-enabling SELinux on a long-running
multi-tenant box requires a labeling pass and is its own operational
project. This check just makes the current state visible.

Severity:
  Enforcing                          → PASS
  Permissive                         → LOW (logs but doesn't enforce)
  Disabled (single-site)             → PASS-with-note (lower defense-in-depth value)
  Disabled (multi-tenant)            → MEDIUM (degraded isolation)

Applies: EL family (RHEL/AlmaLinux/Rocky/CloudLinux/CentOS/Fedora/OL).
Other distros (Debian/Ubuntu) ship without SELinux by default — AppArmor
covers the same role there but exposes a different interface; left for
a future check.
"""

import logging

from posture_checks.base import Check, CheckResult, Severity
from posture_checks._utils import safe_run

logger = logging.getLogger('wp-guardian.posture.selinux')


_EL_FAMILY = {
    'rhel', 'almalinux', 'rocky', 'centos', 'cloudlinux', 'cl', 'fedora', 'ol',
}


def _getenforce():
    """Returns 'Enforcing' / 'Permissive' / 'Disabled', or None on probe
    failure (binary missing, etc.). The runtime state is what matters
    for current-actual security; the config-file value tells us only
    what will happen on the next boot."""
    rc, out = safe_run(['getenforce'], timeout=3)
    if rc < 0:
        return None
    return (out or '').strip()


def _read_config_default():
    """Read /etc/selinux/config to find the BOOT-time SELINUX= value
    (visibility into mismatch between current runtime and next boot)."""
    try:
        with open('/etc/selinux/config', 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#') or '=' not in line:
                    continue
                key, val = line.split('=', 1)
                if key.strip() == 'SELINUX':
                    return val.strip().lower()
    except (IOError, OSError):
        return ''
    return ''


def _is_el_family(distro_id):
    return (distro_id or '').lower() in _EL_FAMILY


class SelinuxCheck(Check):
    check_id = 'selinux'
    severity = Severity.MEDIUM   # default; per-result override
    description = 'SELinux runtime state (Enforcing / Permissive / Disabled)'

    def applies_to(self, profile):
        return _is_el_family(profile.get('distro_id'))

    def run(self, profile, previous=None):
        runtime = _getenforce()
        if runtime is None:
            return CheckResult.errored(
                detail="couldn't query SELinux state (`getenforce` failed)",
                value={'reason': 'getenforce_failed'},
            )

        runtime_lower = runtime.lower()
        config_default = _read_config_default()
        is_multi_tenant = bool(profile.get('is_multi_tenant'))

        value = {
            'runtime': runtime_lower,
            'config_default': config_default,
            'multi_tenant': is_multi_tenant,
        }

        if runtime_lower == 'enforcing':
            return CheckResult.passing(
                detail="SELinux Enforcing",
                value=value,
            )

        if runtime_lower == 'permissive':
            return CheckResult.warning(
                detail="SELinux Permissive (logs violations but doesn't block)",
                value=value,
                severity=Severity.LOW,
            )

        if runtime_lower == 'disabled':
            if is_multi_tenant:
                return CheckResult.failing(
                    detail=("SELinux Disabled on multi-tenant host — "
                            "defense-in-depth degraded"),
                    value=value,
                    severity=Severity.MEDIUM,
                )
            return CheckResult.passing(
                detail=("SELinux Disabled (single-site; lower "
                        "defense-in-depth value)"),
                value=value,
            )

        return CheckResult.errored(
            detail="SELinux state {r!r} unrecognized".format(r=runtime),
            value=value,
        )
