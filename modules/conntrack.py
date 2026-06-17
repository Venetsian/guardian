"""
WP-Guardian conntrack helper (v1.7.7+)

Why this exists
---------------
Stateful firewalls (firewalld and nftables) accept packets that belong to an
ALREADY-ESTABLISHED connection via an early ``ct state {established, related}
accept`` rule, which runs *before* any block rule is evaluated. Adding an IP to
a drop set therefore only stops *new* connections — an attacker holding HTTP
keep-alive connections open keeps flooding until those connections close on
their own (observed: a blocked IP logged 48,000+ requests in the minutes after
the block during the 2026-06-07 xmlrpc flood on wp.maiahost.com).

Flushing the offender's conntrack entries fixes this: once the tracking entry
is destroyed, the next packet on each live connection is re-evaluated as
``ct state new``, which bypasses the established-accept and hits the block rule.
This works even with ``nf_conntrack_tcp_loose=1`` (the default) — the packet
that re-creates the entry is seen as ``new`` until a reply is observed, and
since we drop it, no reply is ever sent, so it stays ``new`` and keeps getting
dropped. This is the same technique fail2ban uses on ban.

Dependency
----------
Requires the ``conntrack`` CLI:
  * RHEL / AlmaLinux / CentOS / Fedora : ``conntrack-tools``
  * Debian / Ubuntu                    : ``conntrack``
If the binary is absent, every flush is a logged no-op — new-connection
blocking still works, only the live-connection teardown is unavailable. The
firewalld/nftables backends warn loudly at startup when this is the case.
"""

import re
import shutil
import logging
import subprocess

logger = logging.getLogger('wp-guardian.conntrack')

# conntrack writes "N flow entries have been deleted." to stderr after a -D.
# Stable across conntrack-tools versions for years.
_DELETED_RE = re.compile(r'(\d+)\s+flow entries have been deleted')


def conntrack_path():
    """Return the absolute path to the conntrack binary, or None if missing."""
    return shutil.which('conntrack')


class ConntrackFlusher:
    """Tears down a source's live connections after it has been blocked.

    Construct once per backend with ``enabled`` from
    ``[firewall] flush_conntrack``. Call :meth:`flush_source` right *after*
    the IP/CIDR has been added to the drop set (order matters — the set must
    already contain the source so the re-evaluated NEW packet gets dropped).
    """

    def __init__(self, enabled=True):
        self.enabled = enabled
        self.path = conntrack_path() if enabled else None

    @property
    def usable(self):
        """True if flushing is enabled AND the conntrack binary is present."""
        return bool(self.path)

    def flush_source(self, src, timeout=5):
        """Delete all conntrack entries whose origin is ``src`` (IP or CIDR).

        Args:
            src:     source IP ('192.0.2.7') or CIDR ('192.0.2.0/24').
            timeout: seconds to wait for the conntrack command.

        Returns:
            int  — number of live connections torn down (0 if none matched),
            None — if flushing is disabled, conntrack is missing, or it errored.
        """
        if not self.path:
            return None

        try:
            result = subprocess.run(
                [self.path, '-D', '-s', src],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning(f"conntrack -D -s {src} timed out after {timeout}s")
            return None
        except Exception as e:
            logger.warning(f"conntrack -D -s {src} failed: {e}")
            return None

        # The deletion summary goes to stderr; some builds echo each flow to
        # stdout too. conntrack exits 0 when >=1 entry was deleted and 1 when
        # nothing matched — both are normal outcomes for us.
        text = (result.stderr or '') + '\n' + (result.stdout or '')
        match = _DELETED_RE.search(text)
        if match:
            return int(match.group(1))
        if result.returncode in (0, 1):
            return 0

        logger.warning(
            f"conntrack -D -s {src} exited {result.returncode}: "
            f"{(result.stderr or '').strip()}"
        )
        return None
