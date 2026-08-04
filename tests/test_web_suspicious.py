"""Regression tests for the `suspicious` PHP-scanning rule in detectors/web.py.

Guards the v1.7.10 false-positive fix: an authenticated customer hitting a
permission-denied response on an ordinary application endpoint was blocked at
the firewall as a scanner, because this was the one tripwire branch that never
consulted is_ip_authenticated().

Stdlib unittest on purpose — the daemon runs on Python 3.6 and the repo has no
test dependencies. Run from the repo root:

    python3 -m unittest discover -s tests -v
"""

import configparser
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detectors.web import WebDetector  # noqa: E402


def log_line(ip, method, path, status):
    """Build an Apache/nginx combined access-log line."""
    return (
        '{ip} - - [04/Aug/2026:13:08:46 +0200] "{m} {p} HTTP/2" {s} 1234 '
        '"https://portal.example.com/" "Mozilla/5.0 (Macintosh) Safari/605.1"'
    ).format(ip=ip, m=method, p=path, s=status)


class FakeBlocker:
    def __init__(self):
        self.blocks = []

    def block(self, ip, reason, service='', site='', rule='', **kwargs):
        self.blocks.append({'ip': ip, 'reason': reason, 'rule': rule})
        return True

    def rules_blocked(self):
        return [b['rule'] for b in self.blocks]


class FakeDB:
    """Only the methods WebDetector actually touches."""

    def __init__(self, authenticated_ips=None):
        self.authenticated_ips = set(authenticated_ips or [])
        self.css_recorded = []
        self.auths = []
        self.tripwire_hits = []
        self._login_hits = {}

    def is_ip_authenticated(self, ip, trust_duration_seconds):
        return ip in self.authenticated_ips

    def login_isolation_record_css(self, ip):
        self.css_recorded.append(ip)

    def login_isolation_record_hit(self, ip):
        self._login_hits[ip] = self._login_hits.get(ip, 0) + 1
        return self._login_hits[ip], 0

    def record_auth(self, ip, service, username, site='', country='', city=''):
        self.auths.append((ip, service, username))

    def record_tripwire_hit(self, path):
        self.tripwire_hits.append(path)


def build_detector(db=None, **threshold_overrides):
    """WebDetector wired to fakes. Kwargs override [thresholds]/[whitelist]."""
    config = configparser.ConfigParser()
    config.add_section('thresholds')
    config.add_section('whitelist')
    config.add_section('auth_tracking')
    config.set('auth_tracking', 'wp_trust_duration', '24')
    for key, value in threshold_overrides.items():
        section = 'whitelist' if key == 'legit_php_paths' else 'thresholds'
        config.set(section, key, value)

    blocker = FakeBlocker()
    detector = WebDetector(config, blocker, db or FakeDB(), tripwires=set())
    return detector, blocker


def feed(detector, ip, path, status, count=3, method='POST'):
    for _ in range(count):
        detector.process_line(log_line(ip, method, path, status))


class SuspiciousRuleTests(unittest.TestCase):

    def test_authenticated_ip_not_blocked_on_403s(self):
        """§6.1 — Fix A: the confirmed false positive.

        192.0.2.10 hit /client.php with three 403s in 22s while holding a
        live session. Uses /billing.php so the allowlist isn't what saves it.
        """
        db = FakeDB(authenticated_ips=['192.0.2.10'])
        detector, blocker = build_detector(db)

        feed(detector, '192.0.2.10', '/billing.php', '403')

        self.assertEqual(blocker.blocks, [], 'authenticated customer was blocked')

    def test_unauthenticated_scanner_still_blocked_on_404s(self):
        """§6.2 — no detection regression: the rule's core true positive."""
        detector, blocker = build_detector()

        feed(detector, '203.0.113.9', '/adminfuns.php', '404')

        self.assertEqual(blocker.rules_blocked(), ['suspicious'])

    def test_403_still_counts_under_default_statuses(self):
        """Deny-heavy installs answer scans with 403, not 404.

        The FP report proposed defaulting suspicious_statuses to 404 alone.
        Fleet data contradicted that: on the Apache host 403 outnumbers 404 on
        these paths ~100:1, so a 404-only default would have removed nearly
        every detection there. Default therefore stays 404,401,403.
        """
        detector, blocker = build_detector()

        feed(detector, '203.0.113.10', '/phpinfo.php', '403')

        self.assertEqual(blocker.rules_blocked(), ['suspicious'])

    def test_403_not_counted_when_statuses_narrowed_to_404(self):
        """§6.3 — Fix B: portal-style hosts can opt out of 403-as-evidence."""
        detector, blocker = build_detector(suspicious_statuses='404')

        feed(detector, '203.0.113.11', '/billing.php', '403')

        self.assertEqual(blocker.blocks, [])

    def test_404_still_counted_when_statuses_narrowed_to_404(self):
        """Narrowing the statuses must not disable the rule outright."""
        detector, blocker = build_detector(suspicious_statuses='404')

        feed(detector, '203.0.113.12', '/billing.php', '404')

        self.assertEqual(blocker.rules_blocked(), ['suspicious'])

    def test_configured_legit_path_never_counted(self):
        """§6.4 — Fix C: [whitelist] legit_php_paths, any status."""
        detector, blocker = build_detector(legit_php_paths='/billing.php, /account.php')

        feed(detector, '203.0.113.13', '/billing.php', '404')
        feed(detector, '203.0.113.13', '/account.php', '403')

        self.assertEqual(blocker.blocks, [])

    def test_builtin_allowlist_covers_client_and_index(self):
        """Fix C: /client.php was the gap; /index.php was safe only by accident
        of being 5 characters, which no longer has to be true."""
        detector, blocker = build_detector()

        feed(detector, '203.0.113.14', '/client.php', '403')
        feed(detector, '203.0.113.14', '/index.php', '404')

        self.assertEqual(blocker.blocks, [])

    def test_structural_tripwire_unchanged_by_the_auth_guard(self):
        """§6.5 — Fix A must not leak into the higher-signal branches.

        The report's phrasing of this test ("authenticated IP + PHP in uploads
        -> still blocked") is wrong and contradicts its own §3.4 table: the
        structural branch has consulted is_ip_authenticated() since v1.5, so an
        authenticated IP there is skipped with a warning, not blocked. What
        actually needs guarding is that Fix A left both halves of that branch
        exactly as they were — instant block for everyone else, and the block
        happening on the *structural* rule rather than falling through to the
        threshold-based `suspicious` one.
        """
        authed_db = FakeDB(authenticated_ips=['198.51.100.5'])
        detector, blocker = build_detector(authed_db)
        detector.process_line(
            log_line('198.51.100.5', 'GET', '/wp-content/uploads/2026/08/x.php', '200')
        )
        self.assertEqual(blocker.blocks, [], 'authenticated IP lost its pre-existing exemption')

        detector, blocker = build_detector()
        detector.process_line(
            log_line('198.51.100.6', 'GET', '/wp-content/uploads/2026/08/x.php', '200')
        )
        self.assertEqual(blocker.rules_blocked(), ['structural'])

    def test_instant_webshell_unchanged_by_the_auth_guard(self):
        """Same check for the known-webshell branch that sits just above ours."""
        detector, blocker = build_detector()

        detector.process_line(log_line('198.51.100.7', 'GET', '/alfa.php', '404'))

        self.assertEqual(blocker.rules_blocked(), ['instant'])

    def test_threshold_is_not_reached_below_limit(self):
        """Two hits must not block — the rule needs suspicious_threshold hits."""
        detector, blocker = build_detector()

        feed(detector, '203.0.113.15', '/adminfuns.php', '404', count=2)

        self.assertEqual(blocker.blocks, [])

    def test_threshold_is_configurable(self):
        """suspicious_threshold is no longer hardcoded to 3."""
        detector, blocker = build_detector(suspicious_threshold='5')

        feed(detector, '203.0.113.16', '/adminfuns.php', '404', count=4)
        self.assertEqual(blocker.blocks, [])

        feed(detector, '203.0.113.16', '/adminfuns.php', '404', count=1)
        self.assertEqual(blocker.rules_blocked(), ['suspicious'])


if __name__ == '__main__':
    unittest.main()
