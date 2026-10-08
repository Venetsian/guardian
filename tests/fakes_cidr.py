"""Fakes for the subnet (CIDR) block lifecycle tests (v1.7.19).

Not a test module (no test_ prefix), so discovery skips it. Builds on
fakes_enforcement. RFC 5737 networks and RFC 2606 names only: the repo is
public.
"""

import gzip
import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fakes_enforcement import DBFixture, FakeFirewall, FakeTelegram  # noqa: E402,F401

# The daemon's handlers are configured in setup_logging(); under test the
# warnings the code under test emits on purpose would otherwise print to stderr.
logging.getLogger('wp-guardian').addHandler(logging.NullHandler())

NET_A = '198.51.100.0/24'
NET_B = '203.0.113.0/24'
NET_C = '192.0.2.0/24'
DAY = 86400


class CidrFirewall(FakeFirewall):
    """A backend that supports CIDR blocks and models its own set.

    self_expiring: expires_own_entries (mikrotik / nftables / csf style).
    lists:         can list its entries (firewalld style). list_raises makes
                   the listing fail, which the backend must report by raising.
    Test code simulates a router TTL by discarding from self.entries.
    """

    supports_cidr = True

    def __init__(self, self_expiring=False, lists=False, friendly=(), **kwargs):
        FakeFirewall.__init__(self, **kwargs)
        self.expires_own_entries = self_expiring
        self.lists = lists
        self.entries = set()
        self.friendly_subnets = set(friendly)
        self.supports_friendly_list = bool(friendly)
        self.cidr_blocked = []       # (subnet, reason, service, duration)
        self.cidr_unblocked = []
        self.block_cidr_ok = True
        self.unblock_cidr_ok = True
        self.unblock_cidr_raises = None
        self.list_raises = None
        self.is_cidr_calls = 0
        self.counts = {}

    def block_cidr(self, subnet, reason, service='web', duration='30d'):
        self.cidr_blocked.append((subnet, reason, service, duration))
        if self.block_cidr_ok:
            self.entries.add(subnet)
        return self.block_cidr_ok

    def unblock_cidr(self, subnet):
        self.cidr_unblocked.append(subnet)
        if self.unblock_cidr_raises is not None:
            raise self.unblock_cidr_raises
        if self.unblock_cidr_ok:
            self.entries.discard(subnet)
        return self.unblock_cidr_ok

    def is_cidr_blocked(self, subnet):
        self.is_cidr_calls += 1
        return subnet in self.entries

    def is_friendly_subnet(self, subnet):
        return subnet in self.friendly_subnets

    def list_cidr_entries(self):
        if not self.lists:
            return None
        if self.list_raises is not None:
            raise self.list_raises
        return set(self.entries)

    def get_block_counts(self):
        return dict(self.counts)


class FakeRouter(object):
    """Verbosity router stand-in: returns a fixed level per rule."""

    def __init__(self, levels=None):
        self.levels = levels or {}
        self.calls = []

    def route(self, rule, tier=0, severity='medium'):
        self.calls.append((rule, tier, severity))
        return self.levels.get(rule, 'immediate')


class FakeDigest(object):
    def __init__(self):
        self.queued = []

    def queue(self, event_type, severity, summary, payload=None):
        self.queued.append((event_type, severity, summary, payload))
        return True


def cidr_config(**overrides):
    """[cidr] section values for DBFixture.blocker(cidr=...): aggregation on."""
    values = {'enabled': 'true', 'threshold': '5', 'duration': '30d'}
    values.update(overrides)
    return values


def block_n(blocker, prefix, count, start=1):
    """Block `count` distinct IPs in prefix ('198.51.100') through block()."""
    for i in range(start, start + count):
        blocker.block('{}.{}'.format(prefix, i), 'Tripwire: /alfa.php')


def stamp(epoch):
    """A blocked.log timestamp in host local time, as the logger writes it."""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch))


def write_log(directory, name, lines):
    """Write a blocked.log-style file; a .gz name is written compressed."""
    path = os.path.join(directory, name)
    text = ''.join(line + '\n' for line in lines)
    if name.endswith('.gz'):
        with gzip.open(path, 'wt', encoding='utf-8') as handle:
            handle.write(text)
    else:
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(text)
    return path


def add_row(db, subnet, status='active', age_days=0, expires_in_days=30,
            source='auto', ended_days_ago=0, permanent=False):
    """Insert a cidr_blocks row positioned relative to now. Returns its id."""
    now = int(time.time())
    expires_at = 0 if permanent else now + int(expires_in_days * DAY)
    return db.insert_cidr_block(
        subnet, expires_at, 'permanent' if permanent else '30d', source,
        blocked_at=now - int(age_days * DAY), status=status,
        ended_at=(now - int(ended_days_ago * DAY)) if status != 'active' else 0)


def rows(db, subnet=None):
    if subnet is None:
        return db.conn.execute("SELECT * FROM cidr_blocks ORDER BY id").fetchall()
    return db.conn.execute(
        "SELECT * FROM cidr_blocks WHERE subnet = ? ORDER BY id", (subnet,)).fetchall()


def statuses(db, subnet):
    return [r['status'] for r in rows(db, subnet)]
