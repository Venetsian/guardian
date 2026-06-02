"""
Apache tenant vhost PHP-execution identity — every tenant vhost must run
PHP as a *per-tenant* uid, never as the shared `apache` user. If PHP runs
as apache, it can read every tenant's files under the standard
0750 group=apache convention → cross-tenant credential disclosure.

The "ghost vhost" failure mode: someone copies a vhost block, adjusts
ServerName / DocumentRoot, but forgets the per-tenant PHP wiring. Apache
then serves that site's PHP as the apache uid.

There is more than one correct way to pin a tenant uid, and a host
usually uses exactly one of them fleet-wide. We accept ALL of these as a
valid per-tenant assignment:

  Apache-native uid directives (the directive itself pins the uid):
    * AssignUserID <user> <group>      — mod_ruid2 / mod_hostinglimits
    * SuexecUserGroup <user> <group>   — mod_suexec
    * User <name>  AND  Group <name>   — mpm_itk_module

  Per-user PHP handlers (PHP runs in a per-tenant process):
    * SetHandler "proxy:unix:/.../<user>.sock|fcgi://..."   — per-user PHP-FPM
    * ProxyPassMatch ^/.*\\.php$  unix:/.../<user>.sock|...  — per-user PHP-FPM
    * SetHandler application/x-httpd-php<NN>-cgi  (or lsphp / lsapi / fcgid)
                                         — mod_lsapi / suEXEC CGI (runs as owner)

Older revisions of this check only knew the three Apache-native directives
and therefore false-positived on every vhost of a PHP-FPM / mod_lsapi host
(where the uid is pinned in the FPM pool, not the vhost). The 100%-of-vhosts
failure that produced was the tell. This revision resolves the vhost's
actual PHP-execution identity instead.

We FAIL (HIGH) a vhost whose PHP is wired to a SHARED pool — a TCP
`fcgi://host:port`, a shared socket (`www.sock`), a pool socket that
resolves to the `apache` / `nobody` user, or plain mod_php
(`application/x-httpd-php` with no per-user suffix). That is the real
cross-tenant exposure.

A vhost with no detectable PHP wiring at all (it would fall through to a
server-global handler we can't see from the vhost) is reported as a softer
WARN, and only when the host otherwise uses per-vhost handlers — so a
single copy-paste omission stands out without crying wolf on hosts that
legitimately pin the uid globally (e.g. global mod_ruid2).

Evaluation is per source file (one tenant site per `*.conf` on the common
stacks): a site's :80 redirect stub doesn't mask the :443 block's proper
per-user handler, and vice-versa.

Severity HIGH. Applies: web_server=apache AND is_multi_tenant.
"""

import logging
import os
import re

try:
    import pwd
except ImportError:            # non-Linux dev box; the check only runs on Linux
    pwd = None

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

# Socket basenames (sans .sock) and pool users that are SHARED, i.e. NOT a
# per-tenant identity. A vhost wired to one of these runs PHP as a shared
# user and breaks isolation.
_SHARED_SOCK_NAMES = ('www', 'php-fpm', 'phpfpm', 'php')
_SHARED_USERS = ('apache', 'httpd', 'nobody', 'www-data', 'nginx', 'daemon')

# Pull a unix socket path out of a proxy target like
#   proxy:unix:/run/alt-phpfpm-php83/foo.sock|fcgi://localhost
_UNIX_SOCK_RE = re.compile(r'unix:([^|]+)')
# A TCP fcgi authority with an explicit port, e.g. fcgi://127.0.0.1:9000.
# (A unix-socket target's trailing "|fcgi://localhost" has no port, so it
# is intentionally NOT matched here.)
_TCP_FCGI_RE = re.compile(r'fcgi://[^/|\s]*:\d+')


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
    """Return list of tokens after the first occurrence of a directive in
    the block, or None."""
    pattern = re.compile(
        r'^\s*' + re.escape(name) + r'\s+(.+?)\s*$',
        re.IGNORECASE | re.MULTILINE,
    )
    m = pattern.search(block_text)
    if not m:
        return None
    return m.group(1).split()


def _block_directive_all(block_text, name):
    """Return a token-list for EVERY occurrence of a directive (some, like
    ProxyPassMatch / SetHandler, can legitimately repeat in one block)."""
    pattern = re.compile(
        r'^\s*' + re.escape(name) + r'\s+(.+?)\s*$',
        re.IGNORECASE | re.MULTILINE,
    )
    return [m.group(1).split() for m in pattern.finditer(block_text)]


def _php_targets(block_text):
    """Return the raw target strings of any PHP-handler directives in the
    block (SetHandler value, ProxyPassMatch/ProxyPass fcgi target)."""
    targets = []
    for toks in _block_directive_all(block_text, 'SetHandler'):
        if toks:
            targets.append(toks[-1].strip('"').strip("'"))
    for toks in _block_directive_all(block_text, 'ProxyPassMatch'):
        # ProxyPassMatch <url-pattern> <target> [params]
        if len(toks) >= 2 and '.php' in toks[0].lower():
            targets.append(toks[1].strip('"').strip("'"))
    for toks in _block_directive_all(block_text, 'ProxyPass'):
        # ProxyPass <path> <target> — only the PHP-ish fcgi/unix ones.
        if len(toks) >= 2 and ('fcgi' in toks[1].lower()
                               or 'unix:' in toks[1].lower()):
            targets.append(toks[1].strip('"').strip("'"))
    return targets


def _parse_vhosts(text):
    """Yield dicts (server_name, document_root, assignment fields, and the
    list of PHP-handler targets) for every <VirtualHost> block."""
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
            'php_targets': _php_targets(block_text),
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


def _user_is_shared(name):
    return (not name) or name.lower() in _SHARED_USERS


def _passwd_ok(name):
    """True if `name` is a real, non-shared local user account."""
    if pwd is None or not name:
        return False
    try:
        pwd.getpwnam(name)
    except KeyError:
        return False
    return not _user_is_shared(name)


def _classify_target(target):
    """Classify one PHP-handler target string.

    Returns one of:
      'none'      — SetHandler none (PHP disabled for this block)
      'per_user'  — per-tenant PHP-FPM socket (uid is a real, non-shared user)
      'lsapi'     — mod_lsapi / suEXEC CGI handler (runs as the file owner)
      'risk'      — shared pool / runs as apache (cross-tenant exposure)
      'unknown'   — couldn't determine (e.g. unresolvable socket name)
    """
    t = (target or '').strip()
    tl = t.lower()
    if not tl:
        return 'unknown'
    if tl == 'none':
        return 'none'
    # Unix-socket FPM target — resolve the socket to a user. Per-user pools
    # are named after the tenant on every common stack (CloudLinux alt-php,
    # cPanel ea-php, Plesk, DirectAdmin): /run/.../<user>.sock.
    if 'unix:' in tl:
        m = _UNIX_SOCK_RE.search(t)
        if not m:
            return 'unknown'
        base = os.path.basename(m.group(1).strip().strip('"').strip("'"))
        name = base[:-5] if base.endswith('.sock') else base
        if name.lower() in _SHARED_SOCK_NAMES or _user_is_shared(name):
            return 'risk'
        if _passwd_ok(name):
            return 'per_user'
        return 'unknown'
    # TCP fcgi pool (host:port) — a single shared pool, not per-tenant.
    if _TCP_FCGI_RE.search(tl):
        return 'risk'
    # Some other proxy/fcgi form we can't resolve to a user.
    if tl.startswith('proxy:') or 'fcgi' in tl:
        return 'unknown'
    # mod_lsapi / suEXEC CGI / mod_fcgid handlers run as the file owner.
    if ('lsphp' in tl or 'lsapi' in tl or 'fcgid' in tl or tl.endswith('-cgi')):
        return 'lsapi'
    # Plain mod_php handler (application/x-httpd-php[NN]) runs in-process as
    # the apache worker uid.
    if tl.startswith('application/x-httpd-'):
        return 'risk'
    return 'unknown'


def _block_verdict(block):
    """Reduce a single vhost block to one verdict (see _classify_target)."""
    if _has_uid_assignment(block):
        return 'ok_apache_directive'
    classes = [_classify_target(t) for t in block['php_targets']]
    if 'risk' in classes:
        return 'risk'
    if 'per_user' in classes:
        return 'ok_per_user'
    if 'lsapi' in classes:
        return 'ok_lsapi'
    if 'none' in classes:
        return 'ok_no_php'
    return 'unknown'


_OK_VERDICTS = ('ok_apache_directive', 'ok_per_user', 'ok_lsapi', 'ok_no_php')
_PER_VHOST_HANDLER_VERDICTS = ('ok_per_user', 'ok_lsapi')


def _file_mechanism(verdicts):
    """Pick a representative mechanism label for an OK site, for the summary."""
    for v, label in (('ok_per_user', 'per_user'),
                     ('ok_lsapi', 'lsapi'),
                     ('ok_apache_directive', 'apache_directive'),
                     ('ok_no_php', 'no_php')):
        if v in verdicts:
            return label
    return 'unknown'


class ApacheVhostUidCheck(Check):
    check_id = 'apache_vhost_uid'
    severity = Severity.HIGH
    description = ('Apache tenant vhosts run PHP as a per-tenant uid '
                   '(Apache directive, per-user FPM pool, or suEXEC/lsapi)')

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

        # Group tenant blocks by source file — one tenant site per *.conf on
        # the common stacks. A site is judged across all its blocks so a :80
        # redirect stub doesn't get mistaken for an unwired (ghost) vhost.
        sites = {}              # path -> {'server_name': str, 'verdicts': set}
        tenant_block_count = 0
        for path in sorted(files):
            text = _read_text(path)
            if not text:
                continue
            for block in _parse_vhosts(text):
                if not _is_tenant_docroot(block['document_root']):
                    continue
                tenant_block_count += 1
                entry = sites.setdefault(
                    path, {'server_name': '', 'verdicts': set()})
                entry['verdicts'].add(_block_verdict(block))
                if not entry['server_name'] and block['server_name']:
                    entry['server_name'] = block['server_name']

        risk_sites = []         # real exposure — PHP runs shared/apache
        unwired_sites = []      # no detectable per-tenant mechanism (ghost?)
        mechanisms = {'per_user': 0, 'lsapi': 0,
                      'apache_directive': 0, 'no_php': 0}
        per_vhost_handlers = False

        for path, info in sites.items():
            verdicts = info['verdicts']
            label = (info['server_name'] or '?', os.path.basename(path))
            if any(v in _PER_VHOST_HANDLER_VERDICTS for v in verdicts):
                per_vhost_handlers = True
            if 'risk' in verdicts:
                risk_sites.append(label)
            elif any(v in _OK_VERDICTS for v in verdicts):
                mechanisms[_file_mechanism(verdicts)] += 1
            else:
                unwired_sites.append(label)

        risk_sites = sorted(set(risk_sites))
        unwired_sites = sorted(set(unwired_sites))
        value = {
            'tenant_site_count': len(sites),
            'tenant_vhost_count': tenant_block_count,
            'mechanisms': mechanisms,
            'risk_sites': [list(t) for t in risk_sites],
            'unwired_sites': [list(t) for t in unwired_sites],
        }

        # Shared/apache PHP execution is the real cross-tenant exposure.
        if risk_sites:
            return CheckResult.failing(
                detail=self._format_finding(
                    risk_sites,
                    "{n} of {tot} tenant site(s) run PHP as a shared/apache "
                    "user (cross-tenant read risk)", len(sites)),
                value=value,
            )

        # No per-tenant wiring detected — only meaningful as a possible ghost
        # vhost when this host otherwise uses per-vhost handlers. On hosts
        # that pin the uid globally (no per-vhost handler anywhere) this is
        # the norm, so we stay quiet. Softer than the shared-pool case (WARN).
        if unwired_sites and per_vhost_handlers:
            return CheckResult.warning(
                detail=self._format_finding(
                    unwired_sites,
                    "{n} of {tot} tenant site(s) have no detectable per-tenant "
                    "PHP handler (possible ghost vhost)", len(sites)),
                value=value,
                severity=Severity.MEDIUM,
            )

        return CheckResult.passing(
            detail=("{tot} tenant site(s) all run PHP per-tenant "
                    "({pu} per-user FPM, {ls} suEXEC/lsapi, "
                    "{ad} apache-directive, {np} php-disabled)".format(
                        tot=len(sites),
                        pu=mechanisms['per_user'], ls=mechanisms['lsapi'],
                        ad=mechanisms['apache_directive'],
                        np=mechanisms['no_php'])),
            value=value,
        )

    @staticmethod
    def _format_finding(site_labels, template, total):
        sample = ['{sn} ({src})'.format(sn=sn, src=src)
                  for sn, src in site_labels[:SAMPLE_LIMIT]]
        more = ('' if len(site_labels) <= SAMPLE_LIMIT
                else ', +{n} more'.format(n=len(site_labels) - SAMPLE_LIMIT))
        head = template.format(n=len(site_labels), tot=total)
        return "{head}: {s}{more}".format(head=head, s=', '.join(sample),
                                          more=more)
