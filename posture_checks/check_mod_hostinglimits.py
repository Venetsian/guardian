"""
mod_hostinglimits — Apache module that ties HTTP requests to per-tenant
LVE containers on CloudLinux + Apache hosts.

Without this module loaded, Apache requests on a CL+Apache box run as
the apache uid for every tenant, defeating the CageFS isolation that
the kernel-level pieces are providing. The result is a quiet degradation
to plain Apache shared hosting — visible only as a check like this.

The check verifies BOTH that the module is currently loaded by the
running httpd AND that it has a LoadModule directive on disk under
/etc/httpd/conf.modules.d (so it survives a clean restart).

Severity HIGH when not loaded at runtime.
MEDIUM when loaded but missing from disk config (works today, will
break on next clean restart).

Applies: is_cloudlinux AND web_server=apache AND is_multi_tenant.
"""

import logging
import os

from posture_checks.base import Check, CheckResult, Severity
from posture_checks._utils import safe_run

logger = logging.getLogger('wp-guardian.posture.mod_hostinglimits')


_MODULE_DIRS = (
    '/etc/httpd/conf.modules.d',
    '/etc/httpd/modules.d',
    '/etc/apache2/mods-enabled',
)


def _httpd_modules():
    """Return list of currently loaded Apache module names. None on
    failure. Tries httpd / apache2ctl / explicit absolute paths."""
    candidates = (
        ['httpd', '-M'],
        ['apache2ctl', '-M'],
        ['/usr/sbin/httpd', '-M'],
        ['/usr/sbin/apache2ctl', '-M'],
    )
    for cmd in candidates:
        rc, out = safe_run(cmd, timeout=5)
        if rc == 0 and (out or '').strip():
            mods = []
            for line in out.splitlines():
                tokens = line.strip().split()
                if not tokens:
                    continue
                name = tokens[0]
                if '_module' in name:
                    mods.append(name)
            return mods
    return None


def _disk_config_has_hostinglimits():
    """Look for `LoadModule ... hostinglimits_module` under the standard
    Apache modules.d-style directories. Returns True on first match."""
    for d in _MODULE_DIRS:
        if not os.path.isdir(d):
            continue
        try:
            scanner = os.scandir(d)
        except OSError:
            continue
        try:
            for entry in scanner:
                if not entry.name.endswith('.conf'):
                    continue
                try:
                    with open(entry.path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith('#') or not line:
                                continue
                            if (line.startswith('LoadModule')
                                    and 'hostinglimits_module' in line):
                                return True
                except (IOError, OSError):
                    continue
        finally:
            try:
                scanner.close()
            except Exception:
                pass
    return False


class ModHostinglimitsCheck(Check):
    check_id = 'mod_hostinglimits'
    severity = Severity.HIGH
    description = 'Apache mod_hostinglimits loaded (CL tenant LVE binding)'

    def applies_to(self, profile):
        return (bool(profile.get('is_cloudlinux'))
                and profile.get('web_server') == 'apache'
                and bool(profile.get('is_multi_tenant')))

    def run(self, profile, previous=None):
        loaded = _httpd_modules()
        config_has = _disk_config_has_hostinglimits()

        if loaded is None:
            return CheckResult.errored(
                detail="couldn't query Apache loaded modules (`httpd -M` failed)",
                value={'reason': 'httpd_M_failed', 'config_present': config_has},
            )

        runtime_loaded = ('hostinglimits_module' in loaded)
        value = {'runtime_loaded': runtime_loaded, 'config_present': config_has}

        if runtime_loaded and config_has:
            return CheckResult.passing(
                detail="mod_hostinglimits loaded and configured on disk",
                value=value,
            )
        if runtime_loaded and not config_has:
            return CheckResult.warning(
                detail=("mod_hostinglimits loaded but no LoadModule on disk — "
                        "won't survive a clean restart"),
                value=value,
                severity=Severity.MEDIUM,
            )
        if config_has and not runtime_loaded:
            return CheckResult.failing(
                detail=("mod_hostinglimits configured on disk but NOT loaded by "
                        "running Apache — restart needed"),
                value=value,
            )
        return CheckResult.failing(
            detail="mod_hostinglimits not loaded — CL tenant LVE binding broken",
            value=value,
        )
