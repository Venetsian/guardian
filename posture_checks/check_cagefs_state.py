"""
CageFS / LVE state — multi-tenant kernel-level isolation on CloudLinux.

CL's CageFS jails each tenant into its own private filesystem view, and
LVE (Lightweight Virtual Environment) is the kernel mechanism that makes
those per-tenant namespaces possible. If LVE isn't loaded or CageFS is
disabled, the box falls back to plain Linux user isolation — defeating
the point of paying for CL on a multi-tenant box.

Probes (all four must pass for full status PASS):
  * kmodlve kernel module loaded — kernel-side proof of life
  * /proc/lve/list present — LVE namespace API exposed
  * `cagefsctl --status` reports enabled
  * lvestatsd or cagefs-stats service running — soft requirement, only
    flags as LOW (lvestats reporting outage doesn't break isolation
    on its own; just degrades visibility)

Severity HIGH on hard misconfigs (kmodlve / proc-lve / cagefsctl).
LOW on lvestats-only outages.

Applies: is_cloudlinux. (We don't gate on multi-tenant — even a
single-site CL plan benefits from CageFS being healthy.)
"""

import logging
import os

from posture_checks.base import Check, CheckResult, Severity
from posture_checks._utils import safe_run

logger = logging.getLogger('wp-guardian.posture.cagefs_state')


def _module_loaded(module):
    """Check whether a kernel module is loaded."""
    if os.path.isdir('/sys/module/' + module):
        return True
    rc, out = safe_run(['lsmod'], timeout=3)
    if rc == 0 and out:
        for line in out.splitlines():
            tokens = line.split()
            if tokens and tokens[0] == module:
                return True
    return False


def _cagefs_status():
    """Run `cagefsctl --status` and return its raw stdout, or None if
    the binary isn't present."""
    rc, out = safe_run(['cagefsctl', '--status'], timeout=10)
    if rc < 0:
        return None
    return (out or '').strip()


def _service_active(unit):
    rc, _ = safe_run(['systemctl', 'is-active', '--quiet', unit], timeout=3)
    return rc == 0


class CageFSStateCheck(Check):
    check_id = 'cagefs_state'
    severity = Severity.HIGH
    description = 'CloudLinux CageFS / LVE active (multi-tenant kernel isolation)'

    def applies_to(self, profile):
        return bool(profile.get('is_cloudlinux'))

    def run(self, profile, previous=None):
        kmodlve = _module_loaded('kmodlve')
        proc_lve = os.path.exists('/proc/lve/list')
        cagefs_status = _cagefs_status()
        cagefs_unit = _service_active('cagefs')
        lvestats_active = (_service_active('lvestats')
                           or _service_active('cagefs-stats'))

        cagefs_ok = False
        if cagefs_status is not None:
            s = cagefs_status.lower()
            if 'enabled' in s and 'disabled' not in s:
                cagefs_ok = True
        # Fallback: cagefsctl missing but service unit reports active
        if not cagefs_ok and cagefs_unit:
            cagefs_ok = True

        value = {
            'kmodlve_loaded': kmodlve,
            'proc_lve_list': proc_lve,
            'cagefs_status': cagefs_status,
            'cagefs_unit_active': cagefs_unit,
            'lvestats_active': lvestats_active,
        }

        problems = []
        if not kmodlve:
            problems.append('kmodlve kernel module not loaded')
        if not proc_lve:
            problems.append('/proc/lve/list missing')
        if not cagefs_ok:
            problems.append('CageFS not enabled (status: {s!r})'.format(s=cagefs_status))

        if problems:
            return CheckResult.failing(
                detail='; '.join(problems),
                value=value,
            )

        if not lvestats_active:
            return CheckResult.warning(
                detail="LVE+CageFS active; lvestats service not running",
                value=value,
                severity=Severity.LOW,
            )

        return CheckResult.passing(
            detail="LVE+CageFS+lvestats all active",
            value=value,
        )
