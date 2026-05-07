"""
Apache vhost UID mapping — every tenant vhost must explicitly assign a
tenant uid; otherwise PHP runs as the system apache user and breaks
multi-tenant isolation.

The "ghost vhost" failure mode: someone copies a vhost block, adjusts
ServerName / DocumentRoot, but forgets the per-tenant assignment
directive. Apache happily serves the site as the apache uid — which
has read access to every tenant's public_html under the standard
0750 group=apache convention.

We parse every vhost source file (enumerated via `httpd -S`) and check
that any <VirtualHost> block whose DocumentRoot is under /home/<X>/ has
at least one of:
  * AssignUserID <uid> <gid>            — mod_hostinglimits  (CL+Apache)
  * SuexecUserGroup <user> <group>      — mod_suexec
  * User <name>  AND  Group <name>      — mpm_itk_module

Vhosts whose DocumentRoot is NOT under /home/<X>/ (operator-owned admin
panels, the apache default site, etc.) are ignored — those run as the
apache uid by design.

Severity HIGH. Applies: web_server=apache AND is_multi_tenant.
"""

import logging
import os
import re

from posture_checks.base import Check, CheckResult, Severity
from posture_checks._utils import safe_run

logger = logging.getLogger('wp-guardian.posture.apache_vhost_uid')


# Matches the "(/path/to/file:NN)" tail in `httpd -S` output. Linux file
# paths can't contain ':' so the simple "no parens, no colon" character
# class works without ambiguity.
_SOURCE_RE = re.compile(r'\(([^():]+):\d+\)')

_BLOCK_RE = re.compile(
    r'<\s*VirtualHost[^>]*>(.*?)<\s*/\s*VirtualHost\s*>',
    re.DOTALL | re.IGNORECASE,
)

SAMPLE_LIMIT = 5


def _httpd_vhost_files():
    """Run `httpd -S` and return set of source filenames where vhosts
    are defined. Tries httpd / apache2ctl / explicit absolute paths."""
    candidates = (
        ['httpd', '-S'],
        ['apache2ctl', '-S'],
        ['/usr/sbin/httpd', '-S'],
        ['/usr/sbin/apache2ctl', '-S'],
    )
    for cmd in candidates:
        rc, out = safe_run(cmd, timeout=5)
        if rc != 0 or not (out or '').strip():
            continue
        files = set()
        for m in _SOURCE_RE.finditer(out):
            path = m.group(1)
            if os.path.isfile(path):
                files.add(path)
        if files:
            return files
    return set()


def _read_text(path):
    try:
        with open(path, 'r') as f:
            return f.read()
    except (IOError, OSError):
        return ''


def _block_directive(block_text, name):
    """Return list of tokens after a directive in the block, or None.
    Only first match is returned; per-vhost duplicates are unusual."""
    pattern = re.compile(
        r'^\s*' + re.escape(name) + r'\s+(.+?)\s*$',
        re.IGNORECASE | re.MULTILINE,
    )
    m = pattern.search(block_text)
    if not m:
        return None
    return m.group(1).split()


def _parse_vhosts(text):
    """Yield dicts (server_name, document_root, and assignment fields)
    for every <VirtualHost> block in the given config text."""
    out = []
    for m in _BLOCK_RE.finditer(text):
        block_text = m.group(1)
        b = {
            'server_name': '',
            'document_root': '',
            'assign_user_id': None,
            'suexec_user': None,
            'user_directive': None,
            'group_directive': None,
        }
        sn = _block_directive(block_text, 'ServerName')
        if sn:
            b['server_name'] = sn[0]
        dr = _block_directive(block_text, 'DocumentRoot')
        if dr:
            b['document_root'] = dr[0].strip('"').strip("'")
        au = _block_directive(block_text, 'AssignUserID')
        if au and len(au) >= 2:
            b['assign_user_id'] = (au[0], au[1])
        su = _block_directive(block_text, 'SuexecUserGroup')
        if su and len(su) >= 2:
            b['suexec_user'] = (su[0], su[1])
        ud = _block_directive(block_text, 'User')
        if ud:
            b['user_directive'] = ud[0]
        gd = _block_directive(block_text, 'Group')
        if gd:
            b['group_directive'] = gd[0]
        out.append(b)
    return out


def _is_tenant_docroot(docroot):
    """True if `docroot` looks like /home/<tenant>/<something>."""
    if not docroot:
        return False
    parts = os.path.normpath(docroot).split(os.sep)
    return len(parts) >= 3 and parts[1] == 'home' and parts[2] != ''


def _has_uid_assignment(block):
    return bool(
        block.get('assign_user_id')
        or block.get('suexec_user')
        or (block.get('user_directive') and block.get('group_directive'))
    )


class ApacheVhostUidCheck(Check):
    check_id = 'apache_vhost_uid'
    severity = Severity.HIGH
    description = ('Apache tenant vhosts have explicit UID assignment '
                   '(AssignUserID / SuexecUserGroup / User+Group)')

    def applies_to(self, profile):
        return (profile.get('web_server') == 'apache'
                and bool(profile.get('is_multi_tenant')))

    def run(self, profile, previous=None):
        files = _httpd_vhost_files()
        if not files:
            return CheckResult.errored(
                detail="couldn't enumerate Apache vhost source files via `httpd -S`",
                value={'reason': 'httpd_S_failed'},
            )

        ghosts = []
        tenant_count = 0
        for path in sorted(files):
            text = _read_text(path)
            if not text:
                continue
            for block in _parse_vhosts(text):
                if not _is_tenant_docroot(block['document_root']):
                    continue
                tenant_count += 1
                if not _has_uid_assignment(block):
                    ghosts.append({
                        'server_name': block['server_name'] or '?',
                        'source': os.path.basename(path),
                        'docroot': block['document_root'],
                    })

        ghost_keys = sorted({(g['server_name'], g['source']) for g in ghosts})
        value = {
            'tenant_vhost_count': tenant_count,
            'ghost_vhosts': [list(t) for t in ghost_keys],
        }

        if not ghosts:
            return CheckResult.passing(
                detail=("{n} tenant vhost(s) all have explicit UID assignment"
                        .format(n=tenant_count)),
                value=value,
            )

        sample = ['{sn} ({src})'.format(sn=g['server_name'], src=g['source'])
                  for g in ghosts[:SAMPLE_LIMIT]]
        more = ('' if len(ghosts) <= SAMPLE_LIMIT
                else ', +{n} more'.format(n=len(ghosts) - SAMPLE_LIMIT))
        return CheckResult.failing(
            detail=("{n} of {tot} tenant vhost(s) have no UID assignment "
                    "(would run PHP as system apache): {s}{more}"
                    .format(n=len(ghosts), tot=tenant_count,
                            s=', '.join(sample), more=more)),
            value=value,
        )
