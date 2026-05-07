"""
sshd config report — visibility into auth-relevant SSH settings.

Reports the effective values of:
  * PermitRootLogin
  * PasswordAuthentication
  * PermitEmptyPasswords
  * PubkeyAuthentication
  * Port + ListenAddress

We use `sshd -T` to get the effective config because it correctly handles
include directives, Match blocks, and built-in defaults — much more
reliable than scraping /etc/ssh/sshd_config ourselves.

Severity policy:
  * PermitEmptyPasswords=yes is HIGH no matter what — it's universally wrong.
  * Other issues (root-with-password, plain password auth) are MEDIUM on
    standalone hosts, demoted to LOW behind a perimeter firewall.
  * Configurations considered acceptable: PermitRootLogin in
    (no, prohibit-password, forced-commands-only) AND
    PasswordAuthentication=no.

Requires running as root for `sshd -T` to read the host keys; wp-guardian
already runs as root so this is fine.
"""

import logging

from posture_checks.base import Check, CheckResult, Severity
from posture_checks._utils import safe_run

logger = logging.getLogger('wp-guardian.posture.sshd_config')


_ACCEPTABLE_PERMIT_ROOT = ('no', 'prohibit-password', 'forced-commands-only')


def _query_sshd_config():
    """Run `sshd -T` and return dict of lowercased option → value/list-of-values.
    Returns None on any failure (binary missing, requires root, etc.)."""
    out = ''
    for candidate in ('sshd', '/usr/sbin/sshd', '/sbin/sshd'):
        rc, candidate_out = safe_run([candidate, '-T'], timeout=5)
        if rc == 0 and (candidate_out or '').strip():
            out = candidate_out
            break
    else:
        return None

    options = {}
    for line in out.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) < 2:
            continue
        key = parts[0].lower()
        value = parts[1].strip()
        existing = options.get(key)
        if existing is None:
            options[key] = value
        elif isinstance(existing, list):
            existing.append(value)
        else:
            options[key] = [existing, value]
    return options


class SshdConfigCheck(Check):
    check_id = 'sshd_config'
    severity = Severity.MEDIUM
    description = 'sshd authentication config (PermitRootLogin, PasswordAuthentication, Port)'

    def applies_to(self, profile):
        return bool(profile.get('is_linux', True))

    def run(self, profile, previous=None):
        opts = _query_sshd_config()
        if opts is None:
            return CheckResult.errored(
                detail="couldn't query effective sshd config (sshd -T failed; need root)",
                value={'reason': 'sshd_T_failed'},
            )

        permit_root = (opts.get('permitrootlogin') or '').lower()
        password_auth = (opts.get('passwordauthentication') or '').lower()
        empty_passwords = (opts.get('permitemptypasswords') or '').lower()
        pubkey_auth = (opts.get('pubkeyauthentication') or '').lower()
        port = opts.get('port') or '22'
        listen_addr = opts.get('listenaddress')
        if isinstance(listen_addr, list):
            listen_str = ','.join(listen_addr)
        else:
            listen_str = listen_addr or ''

        behind_perimeter = bool(profile.get('behind_perimeter_firewall'))
        base_severity = Severity.LOW if behind_perimeter else Severity.MEDIUM

        issues = []
        if permit_root and permit_root not in _ACCEPTABLE_PERMIT_ROOT:
            issues.append('PermitRootLogin={v}'.format(v=permit_root))
        if password_auth == 'yes':
            issues.append('PasswordAuthentication=yes')
        # Universally wrong — escalates regardless of perimeter
        if empty_passwords == 'yes':
            issues.append('PermitEmptyPasswords=yes')
            base_severity = Severity.HIGH

        value = {
            'PermitRootLogin': permit_root,
            'PasswordAuthentication': password_auth,
            'PermitEmptyPasswords': empty_passwords,
            'PubkeyAuthentication': pubkey_auth,
            'Port': port,
            'ListenAddress': listen_str,
            'behind_perimeter': behind_perimeter,
        }

        summary = ("PermitRootLogin={r} PasswordAuth={p} Port={port}"
                   .format(r=permit_root or '?', p=password_auth or '?', port=port))

        if not issues:
            return CheckResult.passing(
                detail="sshd config OK ({s})".format(s=summary),
                value=value,
            )

        return CheckResult.warning(
            detail="sshd issues: {issues} ({s})".format(
                issues='; '.join(issues), s=summary),
            value=value,
            severity=base_severity,
        )
