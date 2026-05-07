"""
public_html permissions — the second half of multi-tenant isolation.

Each tenant's /home/<user>/public_html should be 0750, owned by the
tenant uid, with a group the web server can read from. The exact group
varies by stack:
  * Apache+CL:    apache
  * plain Apache: apache (EL family) or www-data (Debian/Ubuntu)
  * OLS:          nobody, OR the tenant's own group (when OLS uses
                  per-vhost extprocessor running as the tenant uid)
  * Some setups also use the lshttpd 'lsws' group

0750 means:
  * owner: rwx
  * group: r-x   (web server reads + serves)
  * other: 0     (cross-tenant readers blocked)

We deliberately don't fork+setuid to do a "real" cross-read smoke test —
that's complex enough to be its own risk surface, and a misconfigured
mode bit is the only realistic vector for cross-read on a non-ACL host.
The mode + ownership check is functionally equivalent: if other=0 and
the group only contains web-server users, no tenant can read another's
public_html.

Severity HIGH — same isolation tier as tenant home perms.
"""

import logging
import os
import pwd
import grp
import stat as stat_mod

from posture_checks.base import Check, CheckResult, Severity

logger = logging.getLogger('wp-guardian.posture.public_html_perms')


EXPECTED_MODE = 0o750
SAMPLE_LIMIT = 5

# Group names the web server might run as (stack-dependent).
ACCEPTABLE_WEB_GROUPS = {
    'apache', 'www-data', 'httpd',
    'nobody', 'nogroup',
    'lsws',
}


def _list_tenant_public_htmls():
    """Walk /home/<tenant>/public_html for each tenant-shaped entry.
    Returns list of (tenant_basename, public_html_path, stat_result)."""
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
            except OSError:
                continue
            ph_path = os.path.join(entry.path, 'public_html')
            if not os.path.isdir(ph_path):
                continue
            try:
                ph_stat = os.stat(ph_path, follow_symlinks=False)
            except OSError:
                continue
            out.append((entry.name, ph_path, ph_stat))
    finally:
        try:
            scanner.close()
        except Exception:
            pass
    return sorted(out, key=lambda t: t[0])


def _resolve_tenant_uid(tenant_basename):
    """Return tenant uid via pwd lookup, or None if no such user."""
    try:
        return pwd.getpwnam(tenant_basename).pw_uid
    except (KeyError, OSError):
        return None


def _resolve_group_name(gid):
    try:
        return grp.getgrgid(gid).gr_name
    except (KeyError, OSError):
        return ''


class PublicHtmlPermsCheck(Check):
    check_id = 'public_html_perms'
    severity = Severity.HIGH
    description = 'Tenant public_html dirs are 0750 with web-server group'

    def applies_to(self, profile):
        return bool(profile.get('is_multi_tenant'))

    def run(self, profile, previous=None):
        entries = _list_tenant_public_htmls()
        if not entries:
            return CheckResult.errored(
                detail="multi-tenant profile but no <tenant>/public_html dirs found",
                value={'reason': 'no_public_htmls'},
            )

        issues = []
        for tenant_bn, ph_path, st in entries:
            mode = stat_mod.S_IMODE(st.st_mode)
            tenant_uid = _resolve_tenant_uid(tenant_bn)
            group_name = _resolve_group_name(st.st_gid)

            if mode != EXPECTED_MODE:
                issues.append((tenant_bn, "mode {m:04o} (expected 0750)".format(m=mode)))
                continue
            if tenant_uid is not None and st.st_uid != tenant_uid:
                issues.append((tenant_bn,
                    "owner uid {u} does not match tenant uid {t}".format(
                        u=st.st_uid, t=tenant_uid)))
                continue
            # Owner uid matches tenant; group must be either the web server
            # group, OR the tenant's own primary group (OLS-extprocessor case).
            if (group_name not in ACCEPTABLE_WEB_GROUPS
                    and group_name != tenant_bn):
                issues.append((tenant_bn,
                    "group '{g}' not in acceptable web groups {a}".format(
                        g=group_name or '?', a=sorted(ACCEPTABLE_WEB_GROUPS))))

        bad_basenames = sorted({bn for bn, _ in issues})
        value = {
            'tenant_count': len(entries),
            'bad_paths': bad_basenames,
        }

        if not issues:
            return CheckResult.passing(
                detail="{n} public_html dir(s) all 0750 with acceptable owner/group"
                       .format(n=len(entries)),
                value=value,
            )

        sample = ['{bn}: {iss}'.format(bn=bn, iss=iss)
                  for bn, iss in issues[:SAMPLE_LIMIT]]
        more = ('' if len(issues) <= SAMPLE_LIMIT
                else ', +{n} more'.format(n=len(issues) - SAMPLE_LIMIT))
        return CheckResult.failing(
            detail="{n} of {tot} public_html dir(s) misconfigured: {s}{more}".format(
                n=len(issues), tot=len(entries), s='; '.join(sample), more=more),
            value=value,
        )
