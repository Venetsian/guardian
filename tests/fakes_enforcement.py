"""Shared fakes for the dry-run, backend-outage and Telegram sender tests.

Not a test module (no test_ prefix), so discovery skips it. Test files import
it after putting this directory on sys.path, which works both under
`python -m unittest discover -s tests` and when a single file is run directly.

Everything here uses RFC 5737 addresses and RFC 2606 names only: the repo is
public.
"""

import configparser
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.blocker import Blocker  # noqa: E402
from modules.database import GuardianDB  # noqa: E402
from modules.whitelist import WhitelistManager  # noqa: E402


class FakeFirewall(object):
    """Records every call. Flip the knobs to simulate a misbehaving backend."""

    supports_cidr = False
    supports_friendly_list = False
    expires_own_entries = False

    def __init__(self, block_ok=True, unblock_ok=True, unblock_raises=None):
        self.block_ok = block_ok
        self.unblock_ok = unblock_ok
        self.unblock_raises = unblock_raises
        self.blocked = []
        self.unblocked = []
        self.ensure_calls = 0
        self.friendly_refreshes = 0

    def block(self, ip, tier, reason, service='web'):
        self.blocked.append((ip, tier))
        return self.block_ok

    def unblock(self, ip):
        self.unblocked.append(ip)
        if self.unblock_raises is not None:
            raise self.unblock_raises
        return self.unblock_ok

    def ensure_firewall_rules(self):
        self.ensure_calls += 1

    def refresh_friendly_list(self):
        self.friendly_refreshes += 1

    def is_friendly(self, ip):
        return False

    def is_cidr_blocked(self, subnet):
        return False

    def is_friendly_subnet(self, subnet):
        return False

    def block_cidr(self, subnet, reason, service='web', duration='30d'):
        return True


class FakeTelegram(object):
    def __init__(self):
        self.sent = []      # (message, priority)
        self.blocks = []    # alert_block calls

    def send(self, message, priority='INFO'):
        self.sent.append((message, priority))
        return True

    def alert_block(self, ip, tier, reason, service, country='', city='',
                    site='', username=''):
        self.blocks.append((ip, tier))


def make_config(dry_run=False, **sections):
    """ConfigParser for a Blocker. CIDR aggregation is off unless asked for."""
    config = configparser.ConfigParser()
    config.add_section('general')
    config.set('general', 'dry_run', 'true' if dry_run else 'false')
    config.add_section('cidr')
    config.set('cidr', 'enabled', 'false')
    config.add_section('firewall')
    config.set('firewall', 'backend', 'fake')
    for section, values in sections.items():
        if not config.has_section(section):
            config.add_section(section)
        for key, value in values.items():
            config.set(section, key, str(value))
    return config


class DBFixture(object):
    """A real GuardianDB (the genuine schema and migrations) in a temp dir."""

    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix='wpg-test-')
        self.db = GuardianDB(os.path.join(self.tmp, 'state', 'guardian.db'))
        self.whitelist = WhitelistManager(self.db, None, set())

    def blocker(self, dry_run=False, firewall=None, telegram=None, **sections):
        return Blocker(make_config(dry_run=dry_run, **sections), self.db,
                       self.whitelist, firewall,
                       telegram if telegram is not None else FakeTelegram())

    def block_log(self, ip=None):
        if ip is None:
            return self.db.conn.execute("SELECT * FROM block_log ORDER BY id").fetchall()
        return self.db.conn.execute(
            "SELECT * FROM block_log WHERE ip = ? ORDER BY id", (ip,)).fetchall()

    def tier(self, ip):
        row = self.db.get_ip(ip)
        return row['current_tier'] if row else None

    def close(self):
        try:
            self.db.close()
        finally:
            shutil.rmtree(self.tmp, ignore_errors=True)
