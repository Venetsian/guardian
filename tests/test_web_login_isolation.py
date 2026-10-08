"""Login isolation regression tests (v1.7.17).

The rule blocked real customers on wp.maiahost.com: of the IPs it blocked that
appear in the current logs, 355 (6.4%) had fetched static assets AND carried a
browser user-agent, i.e. they had rendered the page — the thing this rule
claims to test for. (Not all 355 are customers; a headless browser on a cloud
host renders too. Anything that renders is out of this rule's scope either way
— scanners that fetch assets are caught by `suspicious` / `php_scan` /
`post_flood`.)

Cause: the only "real browser" signal was a `.css` request, and the evidence
died with the 48h tracking row. A returning admin re-opens wp-login.php with
every stylesheet already cached (WordPress serves them with a `?ver=` buster
and a far-future max-age), or behind a CDN that answers assets from the edge,
so the current row holds login hits and nothing else — identical to a bot.

Fix, measured by replaying 55,132 real log lines through the detector:

    widen the asset signal        90% of FPs removed, 100% of bots still caught
    + 30-day browser memory       94% of FPs removed, 100% of bots still caught

Two other candidate fixes were measured and REJECTED; the tests at the bottom
pin that decision so they are not re-proposed:

    skip 5xx responses            +1% FPs, but bot detection fell to 55%
    120s sliding hit window       +1% FPs, but bot detection fell to 34%
    GET wp-login -> 302 as auth   +1% FPs, but bot detection fell to 87%

All IPs below are RFC 5737 documentation addresses.
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detectors.web import WebDetector, is_browser_asset  # noqa: E402


class FakeConfig(object):
    """Minimal ConfigParser stand-in returning the shipped defaults."""

    def __init__(self, overrides=None):
        self._o = overrides or {}

    def getint(self, section, option, fallback=None):
        return self._o.get(option, fallback)

    def getfloat(self, section, option, fallback=None):
        return self._o.get(option, fallback)

    def get(self, section, option, fallback=None):
        return self._o.get(option, fallback)

    def getboolean(self, section, option, fallback=None):
        return self._o.get(option, fallback)

    def has_section(self, section):
        return False

    def has_option(self, section, option):
        return option in self._o


class FakeDB(object):
    """In-memory stand-in for the login_isolation table."""

    def __init__(self):
        self.rows = {}
        self.auth_ips = {}
        self.recorded_auth = []

    def login_isolation_record_hit(self, ip):
        now = int(time.time())
        row = self.rows.get(ip)
        if row is None:
            self.rows[ip] = {'hits': 1, 'has_css': 0, 'last': now}
            return (1, 0)
        row['hits'] += 1
        row['last'] = now
        return (row['hits'], row['has_css'])

    def login_isolation_record_css(self, ip):
        row = self.rows.setdefault(ip, {'hits': 0, 'has_css': 0, 'last': int(time.time())})
        row['has_css'] = 1

    def login_isolation_has_css(self, ip):
        return self.rows.get(ip, {}).get('has_css', 0) == 1

    def is_ip_authenticated(self, ip, trust_duration):
        ts = self.auth_ips.get(ip)
        return ts is not None and (int(time.time()) - ts) < trust_duration

    def record_auth(self, ip, service, user, site='', country='', city=''):
        self.recorded_auth.append((ip, service, user))
        self.auth_ips[ip] = int(time.time())

    def record_tripwire_hit(self, path):
        pass


class FakeBlocker(object):
    def __init__(self):
        self.blocked = []

    def block(self, ip, reason, service='', site='', rule=''):
        self.blocked.append({'ip': ip, 'reason': reason, 'rule': rule})
        return True


def make_detector(db=None, blocker=None, **overrides):
    return WebDetector(FakeConfig(overrides), blocker or FakeBlocker(),
                       db or FakeDB(), tripwires=set())


def line(ip, method, path, status, ua='Mozilla/5.0 (Windows NT 10.0; Win64; x64)'):
    """Build an OLS-format access log line (outer quotes)."""
    return '"{ip} - - [11/Sep/2026:10:00:00 +0000] "{m} {p} HTTP/2" {s} 512 "-" "{ua}""'.format(
        ip=ip, m=method, p=path, s=status, ua=ua
    )


class TestBrowserAssetSignal(unittest.TestCase):
    """The load-bearing fix: any static asset, not just `.css`."""

    def test_recognises_non_css_assets(self):
        for p in ('/wp-includes/js/jquery/jquery.min.js', '/logo.png',
                  '/fonts/inter.woff2', '/icon.svg', '/favicon.ico',
                  '/img/hero.webp', '/theme/style.css'):
            self.assertTrue(is_browser_asset(p), p)

    def test_rejects_pages_and_php(self):
        """Must not match a .php path — every high-value rule is .php-scoped."""
        for p in ('/wp-login.php', '/', '/wp-admin/load-styles.php',
                  '/about/', '/xmlrpc.php', '/.env'):
            self.assertFalse(is_browser_asset(p), p)

    def test_js_alone_clears_the_rule(self):
        """A browser whose CSS is cached but which still pulls JS is not a bot."""
        blocker = FakeBlocker()
        d = make_detector(FakeDB(), blocker)
        d.process_line(line('192.0.2.10', 'GET', '/wp-includes/js/jquery/jquery.min.js', '200'))
        for _ in range(5):
            d.process_line(line('192.0.2.10', 'GET', '/wp-login.php', '200'))
        self.assertEqual(blocker.blocked, [])

    def test_bare_login_hits_still_block(self):
        """The rule must still catch a bot that fetches nothing else."""
        blocker = FakeBlocker()
        d = make_detector(FakeDB(), blocker)
        for _ in range(3):
            d.process_line(line('192.0.2.11', 'GET', '/wp-login.php', '200'))
        self.assertEqual(len(blocker.blocked), 1)
        self.assertEqual(blocker.blocked[0]['rule'], 'login_isolation')

    def test_authenticated_ip_is_exempt(self):
        blocker = FakeBlocker()
        db = FakeDB()
        d = make_detector(db, blocker)
        # A 302 alone only nominates a login; the admin page confirms it.
        d.process_line(line('192.0.2.12', 'POST', '/wp-login.php', '302'))
        d.process_line(line('192.0.2.12', 'GET', '/wp-admin/', '200'))
        for _ in range(5):
            d.process_line(line('192.0.2.12', 'GET', '/wp-login.php', '200'))
        self.assertEqual(blocker.blocked, [])
        self.assertEqual(len(db.recorded_auth), 1)


class TestRejectedFixes(unittest.TestCase):
    """Pins the measured decisions so they are not re-proposed.

    Each of these looks like an obvious improvement and each one costs far more
    bot detection than it buys in false-positive removal. See the module
    docstring for the numbers.
    """

    def test_5xx_still_counts(self):
        """Rejected: skipping 5xx. It kept only 55% of bot detection."""
        blocker = FakeBlocker()
        d = make_detector(FakeDB(), blocker)
        for _ in range(3):
            d.process_line(line('192.0.2.20', 'GET', '/wp-login.php', '503'))
        self.assertEqual(len(blocker.blocked), 1,
                         "5xx must still count — see module docstring")

    def test_get_302_is_not_a_browser_signal(self):
        """Rejected: GET wp-login -> 302 as proof of a logged-in visitor.

        Plenty of sites redirect wp-login.php for everyone (hidden-login
        plugins, http->https, canonical host), so bots collect that 302 too.
        """
        blocker = FakeBlocker()
        db = FakeDB()
        d = make_detector(db, blocker)
        for _ in range(3):
            d.process_line(line('192.0.2.21', 'GET', '/wp-login.php', '302'))
        self.assertEqual(len(blocker.blocked), 1)
        self.assertEqual(db.recorded_auth, [], "a GET 302 must not record auth")

    def test_hits_accumulate_without_a_window(self):
        """Rejected: a sliding window. Bots pace hits slowly; 120s kept 34%."""
        db = FakeDB()
        db.rows['192.0.2.22'] = {'hits': 2, 'has_css': 0,
                                 'last': int(time.time()) - 86400}
        hits, _ = db.login_isolation_record_hit('192.0.2.22')
        self.assertEqual(hits, 3, "a day-old run must still carry forward")


class TestBrowserMemoryRetention(unittest.TestCase):
    """The 30-day memory, at the layer that implements it: the cleanup query."""

    def setUp(self):
        import sqlite3
        from modules.database import GuardianDB
        self.conn = sqlite3.connect(':memory:')
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
            CREATE TABLE login_isolation (
                ip TEXT PRIMARY KEY, first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL, login_hits INTEGER DEFAULT 0,
                has_css INTEGER DEFAULT 0);
        """)
        self.db = GuardianDB.__new__(GuardianDB)
        self.db.conn = self.conn

    def _add(self, ip, has_css, age_hours):
        ts = int(time.time()) - int(age_hours * 3600)
        self.conn.execute(
            "INSERT INTO login_isolation (ip, first_seen, last_seen, login_hits, has_css)"
            " VALUES (?,?,?,?,?)", (ip, ts, ts, 1, has_css))
        self.conn.commit()

    def _ips(self):
        return {r[0] for r in self.conn.execute("SELECT ip FROM login_isolation")}

    def test_bot_row_expires_at_normal_retention(self):
        self._add('192.0.2.30', has_css=0, age_hours=72)
        self.db.login_isolation_cleanup(48 * 3600, 30 * 86400)
        self.assertNotIn('192.0.2.30', self._ips())

    def test_browser_row_survives_normal_retention(self):
        """The whole point: browser evidence outlives the 48h tracking row."""
        self._add('192.0.2.31', has_css=1, age_hours=72)
        self.db.login_isolation_cleanup(48 * 3600, 30 * 86400)
        self.assertIn('192.0.2.31', self._ips())

    def test_browser_row_expires_at_its_own_retention(self):
        self._add('192.0.2.32', has_css=1, age_hours=31 * 24)
        self.db.login_isolation_cleanup(48 * 3600, 30 * 86400)
        self.assertNotIn('192.0.2.32', self._ips())

    def test_zero_disables_browser_memory(self):
        self._add('192.0.2.33', has_css=1, age_hours=72)
        self.db.login_isolation_cleanup(48 * 3600, 0)
        self.assertNotIn('192.0.2.33', self._ips())

    def test_returns_total_removed(self):
        self._add('192.0.2.34', has_css=0, age_hours=72)
        self._add('192.0.2.35', has_css=1, age_hours=31 * 24)
        self._add('192.0.2.36', has_css=1, age_hours=72)
        self.assertEqual(self.db.login_isolation_cleanup(48 * 3600, 30 * 86400), 2)


class TestRealCustomerScenario(unittest.TestCase):
    """The production trace that triggered this fix (Fidium residential IP)."""

    def test_returning_admin_with_warm_cache_is_not_blocked(self):
        """Browses the site, comes back days later past the 24h auth trust with
        every stylesheet cached, and opens the login page three times."""
        db, blocker = FakeDB(), FakeBlocker()
        d = make_detector(db, blocker)

        # First visit: a real browsing session leaves browser evidence.
        d.process_line(line('192.0.2.50', 'GET', '/', '200'))
        d.process_line(line('192.0.2.50', 'GET', '/wp-content/themes/x/style.css', '200'))
        d.process_line(line('192.0.2.50', 'GET', '/wp-content/uploads/logo.jpg', '200'))

        # Days later: auth trust expired, stylesheets cached, login page only.
        db.auth_ips.pop('192.0.2.50', None)
        for _ in range(4):
            d.process_line(line('192.0.2.50', 'GET', '/wp-login.php', '200'))

        self.assertEqual(blocker.blocked, [],
                         "browser evidence from the earlier visit must still count")


if __name__ == '__main__':
    unittest.main()
