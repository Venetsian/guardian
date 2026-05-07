"""
Tenant home directory permissions — multi-tenant isolation foundation.

On a multi-tenant shared-hosting box (CL+OLS, CL+Apache, plain Apache
multi-tenant), every /home/<tenant>/ directory should be 0711 owned by
the tenant. 0711 lets:
  * the owning tenant do anything
  * the web server / `nobody` traverse INTO public_html (needs the +x)
  * BUT no listing of the home contents leaks across tenants

Anything wider (0755, 0775, 0777) defeats cross-tenant isolation —
another tenant's process or the web server can ls the home dir, see
backup tarballs, vendor includes, .git directories, etc. Anything
narrower (0700) breaks the web server's ability to serve the site.

We only run this check when the host profile says is_multi_tenant.
On single-site hosts the constraint doesn't apply.

Severity HIGH — wrong perms here are a real cross-tenant info-leak.

Stored value: list of misconfigured basenames (sorted). The orchestrator
fires a transition whenever the SET of bad tenants changes, so a tenant
getting fixed (or a new one going wrong) generates exactly one event.
"""

import logging
import os
import stat as stat_mod

from posture_checks.base import Check, CheckResult, Severity

logger = logging.getLogger('wp-guardian.posture.tenant_home_perms')


EXPECTED_MODE = 0o711
SAMPLE_LIMIT = 5


def _looks_like_tenant_home(path):
    """Tenant heuristic — a /home subdir owning a public_html, web, or
    logs subdirectory."""
    for sub in ('public_html', 'web', 'logs'):
        if os.path.isdir(os.path.join(path, sub)):
            return True
    return False


def _list_tenant_homes():
    """Enumerate tenant-shaped /home/<X>/ entries. Returns sorted list
    of (path, stat_result)."""
    out = []
    try:
        scanner = os.scandir('/home')
    except OSError:
        return out
    try:
        for entry in scanner:
            if entry.name.startswith('.'):
                continue
            try:
                if entry.is_symlink():
                    continue
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if not stat_mod.S_ISDIR(st.st_mode):
                continue
            if not _looks_like_tenant_home(entry.path):
                continue
            out.append((entry.path, st))
    finally:
        try:
            scanner.close()
        except Exception:
            pass
    return sorted(out, key=lambda t: t[0])


class TenantHomePermsCheck(Check):
    check_id = 'tenant_home_perms'
    severity = Severity.HIGH
    description = 'Tenant /home/<user> directories are 0711 owner:owner'

    def applies_to(self, profile):
        return bool(profile.get('is_multi_tenant'))

    def run(self, profile, previous=None):
        homes = _list_tenant_homes()
        if not homes:
            return CheckResult.errored(
                detail="multi-tenant profile but no tenant-shaped /home entries found",
                value={'reason': 'no_tenant_homes'},
            )

        issues = []
        for path, st in homes:
            bn = os.path.basename(path)
            mode = stat_mod.S_IMODE(st.st_mode)
            if mode != EXPECTED_MODE:
                issues.append((bn, "mode {m:04o} (expected 0711)".format(m=mode)))
                continue
            if st.st_uid == 0:
                issues.append((bn, "owned by root (expected tenant uid)"))

        bad_basenames = sorted({bn for bn, _ in issues})
        value = {
            'tenant_count': len(homes),
            'bad_paths': bad_basenames,
        }

        if not issues:
            return CheckResult.passing(
                detail="{n} tenant home(s) all 0711".format(n=len(homes)),
                value=value,
            )

        sample = ['{bn}: {iss}'.format(bn=bn, iss=iss)
                  for bn, iss in issues[:SAMPLE_LIMIT]]
        more = ('' if len(issues) <= SAMPLE_LIMIT
                else ', +{n} more'.format(n=len(issues) - SAMPLE_LIMIT))
        return CheckResult.failing(
            detail="{n} of {tot} tenant home(s) misconfigured: {s}{more}".format(
                n=len(issues), tot=len(homes), s='; '.join(sample), more=more),
            value=value,
        )
