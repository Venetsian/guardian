"""Regression tests for the general 404-storm rule in detectors/web.py.

Guards the false positive where a developer rebuilding a Next.js site was
blocked by his own firewall several times a day. An App Router client
prefetches a payload per route; once the build on disk stops matching the
route manifest in an already-loaded bundle, every one of those prefetches
misses at once. Two production incidents, anonymised here:

    peak minute   134 misses, 129 of them RSC payloads, 100 successes
    second host    74 misses,  68 of them RSC payloads, 156 successes
    threshold      general_404_threshold = 50 per 300s

Six blocks over four months off the back of that, one escalated to tier 2
(30 days). The fix has two halves, and each of these tests pins one of them:
framework payloads are counted in their own loose bucket (they are not path
enumeration), and a storm is judged on the ratio of misses to real responses
rather than on a raw count.

The evasion tests matter as much as the false-positive ones: `?_rsc=` must
never become a token that switches the rule off.

Stdlib unittest on purpose — the daemon runs on Python 3.6 and the repo has
no test dependencies. Run from the repo root:

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
        '{ip} - - [30/Aug/2026:16:04:12 +0300] "{m} {p} HTTP/2" {s} 711 '
        '"https://dev.example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"'
    ).format(ip=ip, m=method, p=path, s=status)


class FakeBlocker:
    def __init__(self):
        self.blocks = []
        self._blocked = set()

    def block(self, ip, reason, service='', site='', rule='', **kwargs):
        # Production Blocker.block() skips an IP that already holds a block
        # (tier > 0). Mirror it, so a test that keeps feeding past the
        # threshold sees one block rather than one per later request.
        if ip in self._blocked:
            return False
        self._blocked.add(ip)
        self.blocks.append({'ip': ip, 'reason': reason, 'rule': rule})
        return True

    def rules_blocked(self):
        return [b['rule'] for b in self.blocks]


class FakeDB:
    """Only the methods WebDetector actually touches."""

    def __init__(self, authenticated_ips=None):
        self.authenticated_ips = set(authenticated_ips or [])
        self._login_hits = {}

    def is_ip_authenticated(self, ip, trust_duration_seconds):
        return ip in self.authenticated_ips

    def login_isolation_record_css(self, ip):
        pass

    def login_isolation_record_hit(self, ip):
        self._login_hits[ip] = self._login_hits.get(ip, 0) + 1
        return self._login_hits[ip], 0

    def record_auth(self, ip, service, username, site='', country='', city=''):
        pass

    def record_tripwire_hit(self, path):
        pass


WHITELIST_KEYS = ('legit_php_paths', 'framework_payload_paths')


def build_detector(db=None, **overrides):
    """WebDetector wired to fakes. Kwargs override [thresholds]/[whitelist]."""
    config = configparser.ConfigParser()
    config.add_section('thresholds')
    config.add_section('whitelist')
    config.add_section('auth_tracking')
    config.set('auth_tracking', 'wp_trust_duration', '24')
    for key, value in overrides.items():
        section = 'whitelist' if key in WHITELIST_KEYS else 'thresholds'
        config.set(section, key, value)

    blocker = FakeBlocker()
    detector = WebDetector(config, blocker, db or FakeDB(), tripwires=set())
    return detector, blocker


def feed(detector, ip, path, status, count=1, method='GET'):
    for _ in range(count):
        detector.process_line(log_line(ip, method, path, status))


def replay_rebuild(detector, ip, payload_misses, plain_misses, successes):
    """Replay a post-deploy burst in the order a browser produces it.

    Interleaved on purpose. A browser loads the document and its assets and
    only then prefetches the routes it might navigate to, so successes and
    misses arrive mixed together rather than in blocks. Feeding every miss
    before the first success would model a total outage, not a rebuild.
    """
    events = []
    for i in range(payload_misses):
        route = 'route{n}'.format(n=i)
        events.append(('/{r}/__next.{r}.__PAGE__.txt?_rsc=1nnv4'.format(r=route), '404'))
    for i in range(plain_misses):
        events.append(('/vehicles/type{n}/'.format(n=i), '404'))
    hits = [('/_next/static/chunks/{n}.js'.format(n=i), '200')
            for i in range(successes)]

    every = max(1, len(events) // max(1, len(hits))) if hits else 0
    merged = []
    for i, event in enumerate(events):
        if hits and every and i % every == 0:
            merged.append(hits.pop(0))
        merged.append(event)
    merged.extend(hits)

    for path, status in merged:
        feed(detector, ip, path, status)


class FrameworkPayloadTests(unittest.TestCase):
    """The false positive: a developer rebuilding his own site."""

    def test_measured_burst_does_not_block(self):
        """The exact shape of the 30/Aug incident: 129 payload misses."""
        detector, blocker = build_detector()

        replay_rebuild(detector, '203.0.113.10',
                       payload_misses=129, plain_misses=5, successes=100)

        self.assertEqual(blocker.blocks, [], 'developer blocked mid-rebuild')

    def test_second_measured_burst_does_not_block(self):
        """The 03/Sep incident on the other developer IP."""
        detector, blocker = build_detector()

        replay_rebuild(detector, '203.0.113.11',
                       payload_misses=68, plain_misses=6, successes=156)

        self.assertEqual(blocker.blocks, [])

    def test_segment_file_without_query_marker_counted_as_payload(self):
        """Next.js 15 segment files are recognised by name alone.

        Static exports serve them without a ?_rsc= query, so the filename has
        to carry the classification on its own.
        """
        detector, blocker = build_detector(general_404_threshold='50')

        for i in range(80):
            feed(detector, '203.0.113.12',
                 '/r{n}/__next.r{n}.txt'.format(n=i), '404')

        self.assertEqual(blocker.blocks, [])

    def test_build_output_prefix_counted_as_payload(self):
        """A stale bundle re-requesting /_next/ chunks is not enumeration."""
        detector, blocker = build_detector(general_404_threshold='50')

        for i in range(80):
            feed(detector, '203.0.113.13',
                 '/_next/static/chunks/{n}.js'.format(n=i), '404')

        self.assertEqual(blocker.blocks, [])


class DetectionRegressionTests(unittest.TestCase):
    """The rule must still catch what it was built to catch."""

    def test_plain_scanner_still_blocked(self):
        """A scanner with no successful requests trips at the threshold."""
        detector, blocker = build_detector()

        for i in range(50):
            feed(detector, '198.51.100.20', '/secret{n}/'.format(n=i), '404')

        self.assertEqual(blocker.rules_blocked(), ['general_404'])

    def test_403_heavy_scanner_still_blocked(self):
        """Deny-heavy hosts answer scans with 403, and that still counts."""
        detector, blocker = build_detector()

        for i in range(50):
            feed(detector, '198.51.100.21', '/admin{n}/'.format(n=i), '403')

        self.assertEqual(blocker.rules_blocked(), ['general_404'])

    def test_scanner_padding_with_successes_still_blocked_at_hard_limit(self):
        """The ratio guard has a ceiling.

        Fetching real pages to dilute the ratio must not buy immunity, only
        delay. Well under one success per nine misses is still a scan.
        """
        detector, blocker = build_detector(general_404_hard_limit='120')

        for i in range(60):
            feed(detector, '198.51.100.22', '/real{n}/'.format(n=i), '200')
        for i in range(130):
            feed(detector, '198.51.100.22', '/probe{n}/'.format(n=i), '404')

        self.assertEqual(blocker.rules_blocked(), ['general_404'])


class HardLimitScopeTests(unittest.TestCase):
    """The ceiling is per bucket, not the two summed."""

    def test_long_rebuild_session_not_blocked_by_hard_limit(self):
        """450 payload misses beside 60 plain ones is still a developer.

        Summing the buckets would cross general_404_hard_limit (500) and
        block despite a miss ratio nowhere near the guard.
        """
        detector, blocker = build_detector()

        replay_rebuild(detector, '203.0.113.30',
                       payload_misses=450, plain_misses=60, successes=400)

        self.assertEqual(blocker.blocks, [])

    def test_single_bucket_over_ceiling_still_blocked(self):
        """One bucket past the ceiling blocks whatever the ratio says."""
        detector, blocker = build_detector()

        for i in range(400):
            feed(detector, '198.51.100.50', '/real{n}/'.format(n=i), '200')
        for i in range(520):
            feed(detector, '198.51.100.50', '/probe{n}/'.format(n=i), '404')

        self.assertEqual(blocker.rules_blocked(), ['general_404'])


class EvasionTests(unittest.TestCase):
    """`?_rsc=` must not be a token that disarms the rule."""

    def test_rsc_marker_does_not_shield_php_probes(self):
        """Every PHP rule is .php-scoped, and the classifier refuses .php."""
        detector, blocker = build_detector()

        feed(detector, '198.51.100.30', '/alfa.php?_rsc=1', '404')

        self.assertEqual(blocker.rules_blocked(), ['instant'])

    def test_rsc_marker_does_not_shield_uploads_webshell(self):
        detector, blocker = build_detector()

        feed(detector, '198.51.100.31',
             '/wp-content/uploads/2026/09/evil.php?_rsc=1', '200')

        self.assertEqual(blocker.rules_blocked(), ['structural'])

    def test_rsc_marker_does_not_shield_file_enumeration(self):
        """A route has no extension; /backup.zip is not a route."""
        detector, blocker = build_detector()

        for i in range(50):
            feed(detector, '198.51.100.32',
                 '/backup{n}.zip?_rsc=1'.format(n=i), '404')

        self.assertEqual(blocker.rules_blocked(), ['general_404'])

    def test_rsc_marker_does_not_shield_hidden_path_enumeration(self):
        """Dot-prefixed segments — /.env, /.git/config — are never routes."""
        detector, blocker = build_detector()

        for i in range(25):
            feed(detector, '198.51.100.33', '/.env{n}?_rsc=1'.format(n=i), '404')
            feed(detector, '198.51.100.33',
                 '/.git/objects/{n}?_rsc=1'.format(n=i), '404')

        self.assertEqual(blocker.rules_blocked(), ['general_404'])

    def test_route_shaped_enumeration_still_capped(self):
        """The loose bucket is a budget, not an exemption.

        Extension-less paths with a payload marker are the one shape an
        attacker can still borrow, so they must remain bounded.
        """
        detector, blocker = build_detector(framework_404_threshold='40')

        for i in range(40):
            feed(detector, '198.51.100.34', '/page{n}?_rsc=1'.format(n=i), '404')

        self.assertEqual(blocker.rules_blocked(), ['general_404'])


class RatioGuardTests(unittest.TestCase):

    def test_broken_build_on_plain_routes_not_blocked(self):
        """The half of the burst that carries no marker at all.

        During a re-upload the pages themselves 404 too. A visitor clicking
        through a half-deployed site is not a scanner, and the ratio is what
        says so.
        """
        detector, blocker = build_detector()

        for i in range(60):
            feed(detector, '203.0.113.20', '/asset{n}.webp'.format(n=i), '200')
        for i in range(55):
            feed(detector, '203.0.113.20', '/vehicles/t{n}/'.format(n=i), '404')

        self.assertEqual(blocker.blocks, [])

    def test_ratio_guard_can_be_disabled(self):
        """An operator who wants the old count-only behaviour can have it."""
        detector, blocker = build_detector(general_404_min_fail_ratio='0')

        for i in range(60):
            feed(detector, '203.0.113.21', '/asset{n}.webp'.format(n=i), '200')
        for i in range(55):
            feed(detector, '203.0.113.21', '/vehicles/t{n}/'.format(n=i), '404')

        self.assertEqual(blocker.rules_blocked(), ['general_404'])

    def test_threshold_zero_disables_the_rule(self):
        """0 means "off" everywhere else in [thresholds]; it must here too."""
        detector, blocker = build_detector(general_404_threshold='0')

        for i in range(200):
            feed(detector, '198.51.100.40', '/probe{n}/'.format(n=i), '404')

        self.assertEqual(blocker.blocks, [])


if __name__ == '__main__':
    unittest.main()
