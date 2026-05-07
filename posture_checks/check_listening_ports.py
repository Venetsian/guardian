"""
Listening port inventory — visibility into which ports the host accepts
connections on, with explicit attention to non-localhost binds.

The interesting signal is the *delta* across runs: a new non-localhost
listener appearing (e.g. someone enabling a debug daemon, an installer
flipping a service to listen on 0.0.0.0) is the kind of drift this
check is built to catch. The orchestrator's transition diff fires the
event for free as long as we put a stable, deterministic representation
of the listener set into `value`.

Severity policy:
  * Status WARN whenever the host has any non-localhost listener (which
    is normal for any internet-facing box). The status alone isn't an
    alert — what matters is the value-diff transition.
  * Severity LOW behind a perimeter firewall, MEDIUM standalone.
  * Status PASS when every listener is bound to localhost only.

We rely on `ss` (iproute2). It's been the default on every modern Linux
since iproute2 superseded net-tools. Falls back to ERROR if ss isn't
available — `netstat` backfilling isn't worth the parsing complexity.
"""

import logging
import re

from posture_checks.base import Check, CheckResult, Severity
from posture_checks._utils import safe_run

logger = logging.getLogger('wp-guardian.posture.listening_ports')


_PROCESS_RE = re.compile(r'users:\(\("([^"]+)"')


def _parse_ss_output(out):
    """Parse `ss -lntup` output. Returns list of
    {'proto', 'address', 'port', 'process'} dicts.

    ss output mixes TCP (with State col) and UDP (no State on older
    versions). We don't try to be column-precise — instead we identify
    each row by its leading 'tcp'/'udp' token and find the bind tuple
    by scanning for an 'addr:port' shaped token within the line.
    """
    results = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if not parts:
            continue
        netid = parts[0].lower()
        if netid not in ('tcp', 'udp'):
            continue

        # Find the local-address:port column. ss prints LocalAddr:Port
        # before PeerAddr:Port; we want the first one whose tail is
        # all-digits. *:443 and [::]:443 both round-trip cleanly.
        local = None
        for idx, token in enumerate(parts):
            if ':' not in token or idx == 0:
                continue
            tail = token.rsplit(':', 1)
            if len(tail) == 2 and tail[1].isdigit():
                local = token
                break
        if not local:
            continue

        addr, port_str = local.rsplit(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            continue
        # Strip IPv6 brackets
        if addr.startswith('[') and addr.endswith(']'):
            addr = addr[1:-1]

        process = ''
        m = _PROCESS_RE.search(line)
        if m:
            process = m.group(1)

        results.append({
            'proto': netid,
            'address': addr,
            'port': port,
            'process': process,
        })
    return results


def _is_localhost_addr(addr):
    if addr in ('127.0.0.1', '::1', ''):
        return True
    if addr.startswith('127.'):
        return True
    if addr.startswith('::ffff:127.'):
        return True
    return False


class ListeningPortsCheck(Check):
    check_id = 'listening_ports'
    severity = Severity.MEDIUM
    description = 'Listening TCP/UDP ports inventory (flags non-localhost binds)'

    def applies_to(self, profile):
        return bool(profile.get('is_linux', True))

    def run(self, profile, previous=None):
        rc, out = safe_run(['ss', '-lntup'], timeout=10)
        if rc != 0 or not out:
            return CheckResult.errored(
                detail="couldn't enumerate listening ports (`ss -lntup` failed)",
                value={'reason': 'ss_failed'},
            )

        sockets = _parse_ss_output(out)

        # Deterministic keysets for the stored value (transition diffing
        # only fires when the SET changes — process restarts that keep
        # the same bindings don't trip it).
        all_keys = sorted({(s['proto'], s['address'], s['port']) for s in sockets})
        non_localhost = [s for s in sockets if not _is_localhost_addr(s['address'])]
        non_localhost_keys = sorted(
            {(s['proto'], s['address'], s['port']) for s in non_localhost}
        )

        behind_perimeter = bool(profile.get('behind_perimeter_firewall'))
        severity = Severity.LOW if behind_perimeter else Severity.MEDIUM

        # One-line attribution per (proto, port, process) for the detail
        proc_summary = []
        seen = set()
        for s in sorted(non_localhost, key=lambda x: (x['proto'], x['port'])):
            key = (s['proto'], s['port'], s['process'])
            if key in seen:
                continue
            seen.add(key)
            proc_summary.append("{p}/{port} {proc}".format(
                p=s['proto'], port=s['port'], proc=s['process'] or '?'))

        value = {
            'all_listeners': [list(t) for t in all_keys],
            'non_localhost': [list(t) for t in non_localhost_keys],
            'behind_perimeter': behind_perimeter,
        }

        if not non_localhost:
            return CheckResult.passing(
                detail=("{n} listener(s), all bound to localhost"
                        .format(n=len(all_keys))),
                value=value,
            )

        detail = ("{n} non-localhost listener(s): {s}"
                  .format(n=len(non_localhost_keys),
                          s=', '.join(proc_summary[:20])))
        if len(proc_summary) > 20:
            detail += ' (+{n} more)'.format(n=len(proc_summary) - 20)

        return CheckResult.warning(
            detail=detail, value=value, severity=severity,
        )
