"""WordPress login trust and /wp-admin/ blind-spot regression tests.

Two weaknesses in detectors/web.py, both fixed together:

1. `POST wp-login.php -> 302` was taken as proof of a login, and a login makes
   the IP "authenticated" for 24h (exempt from the tripwire-class rules and
   login isolation). It is forgeable: stock WordPress answers
   `action=postpass` with a 302 whatever the password, and `action` is read
   from $_REQUEST, so it can sit in the POST *body* where the access log never
   shows it. A 302 now only nominates a login; a later 200 from an admin page
   that anonymous clients cannot load (same ip and site, within
   LOGIN_CONFIRM_WINDOW) confirms it.

2. /wp-admin/ and /wp-includes/ were skipped before the known-webshell and
   PHP-404 rules ran, so probes for shells planted there produced no block.
   Known webshell names now block everyone, and PHP 404/401 misses under the
   safe paths are counted.

All IPs are RFC 5737 documentation addresses, all names RFC 2606.
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detectors.web import (  # noqa: E402
    WebDetector, LOGIN_CONFIRM_WINDOW, MAX_PENDING_LOGINS,
    is_admin_session_page, is_login_candidate,
)

SITE = 'shop.example.com'
OTHER_SITE = 'blog.example.net'


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


class FakeDB(object):
    """Only the methods WebDetector touches; record_auth grants trust."""

    def __init__(self):
        self.rows = {}
        self.auth_ips = {}
        self.recorded_auth = []

    def login_isolation_record_hit(self, ip):
        row = self.rows.setdefault(ip, {'hits': 0, 'has_css': 0})
        row['hits'] += 1
        return (row['hits'], row['has_css'])

    def login_isolation_record_css(self, ip):
        self.rows.setdefault(ip, {'hits': 0, 'has_css': 0})['has_css'] = 1

    def is_ip_authenticated(self, ip, trust_duration):
        ts = self.auth_ips.get(ip)
        return ts is not None and (int(time.time()) - ts) < trust_duration

    def record_auth(self, ip, service, user, site='', country='', city=''):
        self.recorded_auth.append((ip, service, user, site))
        self.auth_ips[ip] = int(time.time())

    def record_tripwire_hit(self, path):
        pass


class FakeBlocker(object):
    def __init__(self):
        self.blocked = []

    def block(self, ip, reason, service='', site='', rule='', **kwargs):
        self.blocked.append({'ip': ip, 'reason': reason, 'rule': rule})
        return True

    def rules(self):
        return [b['rule'] for b in self.blocked]


class FakeWhitelist(object):
    def __init__(self, ips):
        self.ips = set(ips)

    def is_whitelisted(self, ip):
        return ip in self.ips


def make_detector(whitelist=None, **overrides):
    db, blocker = FakeDB(), FakeBlocker()
    d = WebDetector(FakeConfig(overrides), blocker, db, tripwires=set(),
                    whitelist=whitelist)
    return d, db, blocker


def line(ip, method, path, status):
    """Build an OLS-format access log line (outer quotes)."""
    return ('"{ip} - - [08/Oct/2026:10:00:00 +0000] "{m} {p} HTTP/2" {s} 512 '
            '"https://shop.example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)""'
            ).format(ip=ip, m=method, p=path, s=status)


def feed(d, ip, method, path, status, count=1, site=SITE):
    for _ in range(count):
        d.process_line(line(ip, method, path, status), site=site)


class TestLoginCandidateHelpers(unittest.TestCase):

    def test_plain_and_subdirectory_logins_are_candidates(self):
        for p in ('/wp-login.php', '/blog/wp-login.php', '/a/b/wp-login.php'):
            self.assertTrue(is_login_candidate('POST', p, p, '302'), p)

    def test_look_alikes_are_not_candidates(self):
        for p in ('/anything-wp-login.php', '/wp-login.php.bak', '/wp-login.phps',
                  '/xmlrpc.php'):
            self.assertFalse(is_login_candidate('POST', p, p, '302'), p)

    def test_only_post_302_qualifies(self):
        self.assertFalse(is_login_candidate('GET', '/wp-login.php', '/wp-login.php', '302'))
        self.assertFalse(is_login_candidate('POST', '/wp-login.php', '/wp-login.php', '200'))

    def test_core_non_login_actions_are_not_candidates(self):
        for action in ('postpass', 'logout', 'lostpassword', 'retrievepassword',
                       'resetpass', 'rp', 'register', 'confirm_admin_email',
                       'confirmaction', 'checkemail', 'entered_recovery_mode',
                       'POSTPASS', 'PostPass'):
            path = '/wp-login.php?action=' + action
            self.assertFalse(is_login_candidate('POST', path, '/wp-login.php', '302'), action)

    def test_duplicate_action_parameter_is_judged_conservatively(self):
        path = '/wp-login.php?action=login&action=postpass'
        self.assertFalse(is_login_candidate('POST', path, '/wp-login.php', '302'))

    def test_login_and_unknown_actions_stay_candidates(self):
        """Unknown actions fall back to the login handler in WordPress core."""
        for q in ('', '?', '?action=login', '?action=', '?action=whatever',
                  '?redirect_to=%2Fwp-admin%2F', '?reauth=1',
                  '?x=postpass', '?Action=postpass'):
            path = '/wp-login.php' + q
            self.assertTrue(is_login_candidate('POST', path, '/wp-login.php', '302'), path)

    def test_admin_session_pages(self):
        for p in ('/wp-admin', '/wp-admin/', '/blog/wp-admin/', '/wp-admin/index.php',
                  '/wp-admin/edit.php', '/wp-admin/post-new.php', '/wp-admin/plugins.php',
                  '/wp-admin/options-general.php', '/blog/wp-admin/profile.php',
                  '/wp-admin/site-editor.php', '/wp-admin/about.php'):
            self.assertTrue(is_admin_session_page(p), p)

    def test_pages_anonymous_clients_can_load_are_not_session_pages(self):
        for p in ('/wp-admin/admin-ajax.php', '/wp-admin/admin-post.php',
                  '/wp-admin/load-styles.php', '/wp-admin/load-scripts.php',
                  '/wp-admin/install.php', '/wp-admin/upgrade.php',
                  '/wp-admin/setup-config.php', '/wp-admin/maint/repair.php',
                  '/wp-admin/css/login.min.css', '/wp-admin/images/wordpress-logo.svg',
                  '/wp-admin/js/common.js', '/wp-login.php', '/', '/foo-wp-admin/',
                  '/wp-admin/evil.php', '/wp-admin/index.php.bak'):
            self.assertFalse(is_admin_session_page(p), p)


class TestLoginConfirmation(unittest.TestCase):

    def test_postpass_302_grants_nothing(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.10', 'POST', '/wp-login.php?action=postpass', '302')
        feed(d, '192.0.2.10', 'GET', '/wp-admin/', '200')
        self.assertEqual(db.recorded_auth, [])

    def test_postpass_does_not_exempt_the_ip_from_login_isolation(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.11', 'POST', '/wp-login.php?action=postpass', '302', count=3)
        self.assertEqual(db.recorded_auth, [])
        self.assertEqual(blocker.rules(), ['login_isolation'])

    def test_postpass_does_not_exempt_the_ip_from_tripwires(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.12', 'POST', '/wp-login.php?action=postpass', '302')
        feed(d, '192.0.2.12', 'GET', '/wp-content/uploads/2026/10/x.php', '200')
        self.assertEqual(blocker.rules(), ['structural'])

    def test_login_302_without_confirmation_grants_nothing(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.13', 'POST', '/wp-login.php', '302')
        feed(d, '192.0.2.13', 'GET', '/', '200')
        self.assertEqual(db.recorded_auth, [])
        self.assertFalse(db.is_ip_authenticated('192.0.2.13', 86400))

    def test_login_then_admin_page_records_auth_once(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.14', 'POST', '/wp-login.php', '302')
        self.assertEqual(db.recorded_auth, [], 'the redirect alone must not record')
        feed(d, '192.0.2.14', 'GET', '/wp-admin/', '200')
        feed(d, '192.0.2.14', 'GET', '/wp-admin/index.php', '200')
        self.assertEqual(db.recorded_auth,
                         [('192.0.2.14', 'wordpress', 'wp@' + SITE, SITE)])

    def test_unknown_site_user_label(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.15', 'POST', '/wp-login.php', '302', site='')
        feed(d, '192.0.2.15', 'GET', '/wp-admin/', '200', site='')
        self.assertEqual(db.recorded_auth,
                         [('192.0.2.15', 'wordpress', 'wp@unknown', '')])

    def test_confirmed_login_exempts_login_isolation(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.16', 'POST', '/wp-login.php', '302')
        feed(d, '192.0.2.16', 'GET', '/wp-admin/', '200')
        feed(d, '192.0.2.16', 'GET', '/wp-login.php', '200', count=5)
        self.assertEqual(blocker.blocked, [])

    def test_confirmed_login_exempts_tripwire_class_rules(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.17', 'POST', '/wp-login.php', '302')
        feed(d, '192.0.2.17', 'GET', '/wp-admin/', '200')
        feed(d, '192.0.2.17', 'GET', '/wp-content/uploads/2026/10/x.php', '200')
        self.assertEqual(blocker.blocked, [])

    def test_admin_page_without_a_pending_login_grants_nothing(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.18', 'GET', '/wp-admin/', '200')
        self.assertEqual(db.recorded_auth, [])

    def test_confirmation_after_the_window_grants_nothing(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.19', 'POST', '/wp-login.php', '302')
        d._pending_logins[('192.0.2.19', SITE)] = time.time() - LOGIN_CONFIRM_WINDOW - 5
        feed(d, '192.0.2.19', 'GET', '/wp-admin/', '200')
        self.assertEqual(db.recorded_auth, [])
        self.assertEqual(d._pending_logins, {}, 'stale entry should be dropped')

    def test_confirmation_just_inside_the_window_counts(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.20', 'POST', '/wp-login.php', '302')
        d._pending_logins[('192.0.2.20', SITE)] = time.time() - LOGIN_CONFIRM_WINDOW + 10
        feed(d, '192.0.2.20', 'GET', '/wp-admin/', '200')
        self.assertEqual(len(db.recorded_auth), 1)

    def test_admin_ajax_does_not_confirm(self):
        """admin-ajax.php answers 200 to anonymous clients."""
        d, db, blocker = make_detector()
        feed(d, '192.0.2.21', 'POST', '/wp-login.php', '302')
        feed(d, '192.0.2.21', 'POST', '/wp-admin/admin-ajax.php', '200')
        feed(d, '192.0.2.21', 'GET', '/wp-admin/admin-post.php', '200')
        feed(d, '192.0.2.21', 'GET', '/wp-admin/load-styles.php', '200')
        self.assertEqual(db.recorded_auth, [])

    def test_non_200_admin_response_does_not_confirm(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.22', 'POST', '/wp-login.php', '302')
        feed(d, '192.0.2.22', 'GET', '/wp-admin/', '302')
        feed(d, '192.0.2.22', 'GET', '/wp-admin/', '403')
        self.assertEqual(db.recorded_auth, [])

    def test_look_alike_login_path_is_not_a_candidate(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.23', 'POST', '/anything-wp-login.php', '302')
        feed(d, '192.0.2.23', 'GET', '/wp-admin/', '200')
        self.assertEqual(db.recorded_auth, [])

    def test_confirmation_from_another_site_does_not_count(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.24', 'POST', '/wp-login.php', '302', site=SITE)
        feed(d, '192.0.2.24', 'GET', '/wp-admin/', '200', site=OTHER_SITE)
        self.assertEqual(db.recorded_auth, [])
        # The pending login is still there for the right site.
        feed(d, '192.0.2.24', 'GET', '/wp-admin/', '200', site=SITE)
        self.assertEqual(len(db.recorded_auth), 1)

    def test_confirmation_from_another_ip_does_not_count(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.25', 'POST', '/wp-login.php', '302')
        feed(d, '192.0.2.26', 'GET', '/wp-admin/', '200')
        self.assertEqual(db.recorded_auth, [])

    def test_subdirectory_install(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.27', 'POST', '/blog/wp-login.php', '302')
        feed(d, '192.0.2.27', 'GET', '/blog/wp-admin/', '200')
        self.assertEqual(len(db.recorded_auth), 1)

    def test_login_with_redirect_to_query_is_still_a_candidate(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.28', 'POST', '/wp-login.php?redirect_to=%2Fwp-admin%2F', '302')
        feed(d, '192.0.2.28', 'GET', '/wp-admin/edit.php', '200')
        self.assertEqual(len(db.recorded_auth), 1)

    def test_login_post_is_not_counted_by_later_rules(self):
        """Pins only the FIRST candidate: it returns early, as it always did."""
        d, db, blocker = make_detector()
        feed(d, '192.0.2.29', 'POST', '/wp-login.php', '302')
        self.assertEqual(blocker.blocked, [])
        self.assertNotIn('192.0.2.29', db.rows, 'first candidate must not feed login isolation')
        self.assertIn(('192.0.2.29', SITE), d._pending_logins)

    def test_whitelisted_ip_login_is_recorded_via_confirmation(self):
        wl = FakeWhitelist(['198.51.100.5'])
        d, db, blocker = make_detector(whitelist=wl)
        feed(d, '198.51.100.5', 'POST', '/wp-login.php', '302')
        self.assertEqual(db.recorded_auth, [])
        feed(d, '198.51.100.5', 'GET', '/wp-admin/', '200')
        self.assertEqual(len(db.recorded_auth), 1)
        self.assertEqual(blocker.blocked, [])

    def test_whitelisted_ip_postpass_records_nothing(self):
        wl = FakeWhitelist(['198.51.100.6'])
        d, db, blocker = make_detector(whitelist=wl)
        feed(d, '198.51.100.6', 'POST', '/wp-login.php?action=postpass', '302')
        feed(d, '198.51.100.6', 'GET', '/wp-admin/', '200')
        self.assertEqual(db.recorded_auth, [])
        self.assertEqual(blocker.blocked, [])


class TestRepeatedLoginCandidates(unittest.TestCase):
    """A second candidate while the first is unconfirmed is a failed attempt.

    On a host where a redirect answers nearly every wp-login POST with 302,
    POST-only bots would otherwise be invisible to login isolation and brute
    force. The first candidate still returns early, which protects a real user
    who mistypes once.
    """

    def test_second_candidate_is_counted_as_a_login_hit(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.50', 'POST', '/wp-login.php', '302')
        self.assertNotIn('192.0.2.50', db.rows)
        feed(d, '192.0.2.50', 'POST', '/wp-login.php', '302')
        self.assertEqual(db.rows['192.0.2.50']['hits'], 1)

    def test_post_only_bot_is_blocked_by_login_isolation(self):
        d, db, blocker = make_detector()
        # POST 1 is the uncounted first candidate; POSTs 2-4 are repeats and
        # count as login-isolation hits 1-3, so the block lands on the 4th.
        feed(d, '192.0.2.51', 'POST', '/wp-login.php', '302', count=3)
        self.assertEqual(blocker.blocked, [])
        feed(d, '192.0.2.51', 'POST', '/wp-login.php', '302')
        self.assertEqual(blocker.rules(), ['login_isolation'])
        self.assertEqual(db.recorded_auth, [])

    def test_rapid_posts_from_a_browser_ip_hit_brute_force(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.52', 'GET', '/wp-content/themes/x/style.css', '200')
        # POST 1 is the uncounted first candidate; POSTs 2-11 are ten counted
        # repeats, so wp_login_threshold (10) is reached on the 11th POST.
        feed(d, '192.0.2.52', 'POST', '/wp-login.php', '302', count=10)
        self.assertEqual(blocker.blocked, [])
        feed(d, '192.0.2.52', 'POST', '/wp-login.php', '302')
        self.assertEqual(blocker.rules(), ['wp_login'])
        self.assertEqual(blocker.blocked[0]['reason'], 'wp-login brute force (10 in 300s)')

    def test_real_user_mistyping_once_with_a_warm_cache_is_not_blocked(self):
        """GET (hit 1), POST 200 (hit 2), POST 302 (first candidate, uncounted),
        then the dashboard confirms. No asset loads, so has_css is false and a
        third counted hit would have blocked."""
        d, db, blocker = make_detector()
        feed(d, '192.0.2.53', 'GET', '/wp-login.php', '200')
        feed(d, '192.0.2.53', 'POST', '/wp-login.php', '200')
        feed(d, '192.0.2.53', 'POST', '/wp-login.php', '302')
        feed(d, '192.0.2.53', 'GET', '/wp-admin/', '200')
        self.assertEqual(blocker.blocked, [])
        self.assertEqual(db.rows['192.0.2.53'], {'hits': 2, 'has_css': 0})
        self.assertEqual(len(db.recorded_auth), 1)

    def test_separate_confirmed_logins_never_count(self):
        d, db, blocker = make_detector()
        for _ in range(5):
            # Hours later: the previous trust has lapsed, but the confirmed
            # login popped its pending entry, so this POST is a fresh first
            # candidate rather than a repeat.
            db.auth_ips.clear()
            feed(d, '192.0.2.54', 'POST', '/wp-login.php', '302')
            feed(d, '192.0.2.54', 'GET', '/wp-admin/', '200')
        self.assertEqual(blocker.blocked, [])
        self.assertNotIn('192.0.2.54', db.rows, 'no login may have been counted')
        self.assertEqual(len(db.recorded_auth), 5)

    def test_repeat_after_an_expired_unconfirmed_candidate_still_counts(self):
        """Any age: an unconfirmed candidate means that login failed."""
        d, db, blocker = make_detector()
        feed(d, '192.0.2.55', 'POST', '/wp-login.php', '302')
        d._pending_logins[('192.0.2.55', SITE)] = time.time() - 6 * 3600
        feed(d, '192.0.2.55', 'POST', '/wp-login.php', '302')
        self.assertEqual(db.rows['192.0.2.55']['hits'], 1)

    def test_candidates_on_different_sites_are_independent(self):
        d, db, blocker = make_detector()
        feed(d, '192.0.2.56', 'POST', '/wp-login.php', '302', site=SITE)
        feed(d, '192.0.2.56', 'POST', '/wp-login.php', '302', site=OTHER_SITE)
        self.assertNotIn('192.0.2.56', db.rows)

    def test_repeat_candidate_from_an_authenticated_ip_skips_login_isolation(self):
        d, db, blocker = make_detector()
        db.auth_ips['192.0.2.57'] = int(time.time())
        feed(d, '192.0.2.57', 'POST', '/wp-login.php', '302', count=6)
        self.assertEqual(blocker.blocked, [])
        self.assertNotIn('192.0.2.57', db.rows)

    def test_repeated_postpass_is_still_ordinary_traffic(self):
        """postpass is not a candidate at all, so it never reaches the
        brute-force branch through the repeat path (login isolation counts it
        like any wp-login hit, as before)."""
        d, db, blocker = make_detector()
        feed(d, '192.0.2.58', 'GET', '/wp-content/themes/x/style.css', '200')
        feed(d, '192.0.2.58', 'POST', '/wp-login.php?action=postpass', '302', count=30)
        self.assertEqual(blocker.blocked, [])
        self.assertEqual(d._pending_logins, {})

    def test_whitelisted_ip_repeats_are_ignored(self):
        wl = FakeWhitelist(['198.51.100.7'])
        d, db, blocker = make_detector(whitelist=wl)
        feed(d, '198.51.100.7', 'POST', '/wp-login.php', '302', count=30)
        self.assertEqual(blocker.blocked, [])
        self.assertNotIn('198.51.100.7', db.rows)


class TestPendingLoginBound(unittest.TestCase):

    def _fill(self, d, count, prefix='s'):
        for i in range(count):
            feed(d, '192.0.2.40', 'POST', '/wp-login.php', '302',
                 site='{p}{i}.example.com'.format(p=prefix, i=i))

    def test_map_never_grows_past_the_cap(self):
        d, db, blocker = make_detector()
        self._fill(d, MAX_PENDING_LOGINS + 50)
        self.assertLessEqual(len(d._pending_logins), MAX_PENDING_LOGINS)

    def test_expired_entries_are_dropped_first(self):
        d, db, blocker = make_detector()
        self._fill(d, MAX_PENDING_LOGINS, prefix='old')
        old = time.time() - LOGIN_CONFIRM_WINDOW - 10
        for key in list(d._pending_logins):
            d._pending_logins[key] = old
        feed(d, '192.0.2.41', 'POST', '/wp-login.php', '302', site='new.example.com')
        self.assertEqual(list(d._pending_logins), [('192.0.2.41', 'new.example.com')])

    def test_oldest_half_is_dropped_when_nothing_has_expired(self):
        d, db, blocker = make_detector()
        self._fill(d, MAX_PENDING_LOGINS, prefix='a')
        now = time.time()
        # Distinct, strictly increasing ages, all still inside the window.
        for n, key in enumerate(sorted(d._pending_logins)):
            d._pending_logins[key] = now - 60 + n * 1e-3
        newest = max(d._pending_logins, key=d._pending_logins.get)
        feed(d, '192.0.2.42', 'POST', '/wp-login.php', '302', site='new.example.com')
        self.assertLessEqual(len(d._pending_logins), MAX_PENDING_LOGINS // 2 + 1)
        self.assertIn(('192.0.2.42', 'new.example.com'), d._pending_logins)
        self.assertIn(newest, d._pending_logins)


class TestWebshellsUnderSafePaths(unittest.TestCase):

    def test_webshell_probe_under_wp_includes_blocks_instantly(self):
        d, db, blocker = make_detector()
        feed(d, '203.0.113.10', 'GET', '/wp-includes/c99.php', '404', count=100)
        self.assertEqual(blocker.blocked[0]['rule'], 'instant')

    def test_webshell_probe_under_wp_admin_blocks_instantly(self):
        d, db, blocker = make_detector()
        feed(d, '203.0.113.11', 'GET', '/wp-admin/alfa.php', '200')
        self.assertEqual(blocker.rules(), ['instant'])

    def test_webshell_in_subdirectory_wp_admin_blocks(self):
        d, db, blocker = make_detector()
        feed(d, '203.0.113.12', 'GET', '/blog/wp-admin/includes/r57.php', '404')
        self.assertEqual(blocker.rules(), ['instant'])

    def test_authenticated_ip_is_blocked_for_a_webshell_in_wp_admin(self):
        d, db, blocker = make_detector()
        db.auth_ips['203.0.113.13'] = int(time.time())
        feed(d, '203.0.113.13', 'GET', '/wp-admin/wso.php', '200')
        self.assertEqual(blocker.rules(), ['instant'])

    def test_authenticated_ip_is_blocked_for_a_webshell_anywhere(self):
        d, db, blocker = make_detector()
        db.auth_ips['203.0.113.14'] = int(time.time())
        feed(d, '203.0.113.14', 'GET', '/alfa.php', '404')
        self.assertEqual(blocker.rules(), ['instant'])

    def test_structural_tripwire_keeps_its_authenticated_exemption(self):
        d, db, blocker = make_detector()
        db.auth_ips['203.0.113.15'] = int(time.time())
        feed(d, '203.0.113.15', 'GET', '/wp-content/uploads/2026/10/x.php', '200')
        self.assertEqual(blocker.blocked, [])

    def test_webshell_name_only_matches_php(self):
        d, db, blocker = make_detector()
        feed(d, '203.0.113.16', 'GET', '/wp-includes/c99.txt', '404', count=5)
        self.assertEqual(blocker.blocked, [])


class TestPhpScanUnderSafePaths(unittest.TestCase):

    def _scan(self, d, ip, directory='/wp-admin', status='404', count=20):
        for i in range(count):
            feed(d, ip, 'GET', '{d}/q{i}zx.php'.format(d=directory, i=i), status)

    def test_wp_admin_php_404s_block_at_threshold(self):
        d, db, blocker = make_detector()
        self._scan(d, '203.0.113.20', count=19)
        self.assertEqual(blocker.blocked, [], 'one below the threshold')
        self._scan(d, '203.0.113.20', count=1)
        self.assertEqual(blocker.rules(), ['php_scan'])
        self.assertEqual(blocker.blocked[0]['reason'], 'PHP scanning (20 404s in 300s)')

    def test_wp_includes_php_404s_block(self):
        d, db, blocker = make_detector()
        self._scan(d, '203.0.113.21', directory='/wp-includes')
        self.assertEqual(blocker.rules(), ['php_scan'])

    def test_subdirectory_wp_admin_php_404s_block(self):
        d, db, blocker = make_detector()
        self._scan(d, '203.0.113.22', directory='/blog/wp-admin')
        self.assertEqual(blocker.rules(), ['php_scan'])

    def test_401_counts_like_404(self):
        d, db, blocker = make_detector()
        self._scan(d, '203.0.113.23', status='401')
        self.assertEqual(blocker.rules(), ['php_scan'])

    def test_authenticated_ip_is_not_blocked(self):
        d, db, blocker = make_detector()
        db.auth_ips['203.0.113.24'] = int(time.time())
        self._scan(d, '203.0.113.24', count=60)
        self.assertEqual(blocker.blocked, [])

    def test_403_does_not_count(self):
        """Sites with an .htaccess IP restriction on wp-admin answer the
        operator's own secondary address with 403."""
        d, db, blocker = make_detector()
        feed(d, '203.0.113.25', 'GET', '/wp-admin/x.php', '403', count=50)
        self.assertEqual(blocker.blocked, [])

    def test_admin_ajax_400s_do_not_count(self):
        d, db, blocker = make_detector()
        feed(d, '203.0.113.26', 'POST', '/wp-admin/admin-ajax.php', '400', count=100)
        self.assertEqual(blocker.blocked, [])

    def test_public_ajax_endpoints_answering_401_do_not_count(self):
        """Front-end plugins poll these for anonymous visitors; some say 401."""
        d, db, blocker = make_detector()
        feed(d, '203.0.113.30', 'POST', '/wp-admin/admin-ajax.php', '401', count=60)
        feed(d, '203.0.113.30', 'POST', '/wp-admin/admin-post.php', '401', count=60)
        feed(d, '203.0.113.31', 'POST', '/blog/wp-admin/admin-ajax.php', '401', count=60)
        self.assertEqual(blocker.blocked, [])

    def test_non_php_404s_under_safe_paths_do_not_count(self):
        d, db, blocker = make_detector()
        for i in range(60):
            feed(d, '203.0.113.27', 'GET', '/wp-admin/css/q{i}.css'.format(i=i), '404')
        self.assertEqual(blocker.blocked, [])

    def test_successful_php_under_safe_paths_does_not_count(self):
        d, db, blocker = make_detector()
        feed(d, '203.0.113.28', 'GET', '/wp-admin/load-styles.php', '200', count=60)
        self.assertEqual(blocker.blocked, [])

    def test_threshold_follows_the_configured_value(self):
        d, db, blocker = make_detector(php_404_threshold=5)
        self._scan(d, '203.0.113.29', count=5)
        self.assertEqual(blocker.rules(), ['php_scan'])


if __name__ == '__main__':
    unittest.main()
