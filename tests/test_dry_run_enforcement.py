"""A dry run must never create enforcement state, and a missing backend is an outage.

Background. Blocker.block() in dry-run used to call db.record_block(), which
sets ip_history.current_tier exactly like a real block. block() skips any IP
with current_tier > 0 ("already blocked"), determine_tier() read the simulated
row as escalation evidence, and count_blocked_in_subnet() counted it toward
CIDR aggregation. A simulated detection could therefore leave a real attacker
unblocked (tier 3 = forever) and escalate every later real block.

Second hazard: a firewall backend that failed to initialise silently flipped
dry_run on for the whole uptime, with no alert.

Stdlib unittest on purpose (the daemon runs on Python 3.6). Run from the repo
root:

    python3 -m unittest discover -s tests -v
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fakes_enforcement import (  # noqa: E402
    DBFixture, FakeFirewall, FakeTelegram,
)
from modules import migrator  # noqa: E402
from modules.blocker import UNAVAILABLE_MSG  # noqa: E402
from modules.compromise import CompromiseAction  # noqa: E402

IP = '192.0.2.10'
WEEK = 7 * 86400

MIGRATIONS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'migrations')


class TestDryRunCreatesNoEnforcementState(unittest.TestCase):
    def setUp(self):
        self.fx = DBFixture()

    def tearDown(self):
        self.fx.close()

    def test_dry_run_block_logs_a_review_row_but_sets_no_tier(self):
        blocker = self.fx.blocker(dry_run=True)

        self.assertTrue(blocker.block(IP, 'Tripwire: /alfa.php', service='web'))

        rows = self.fx.block_log(IP)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['blocker'], 'dry-run')
        self.assertEqual(rows[0]['tier'], 1)
        ip_row = self.fx.db.get_ip(IP)
        self.assertEqual(ip_row['current_tier'], 0)
        self.assertEqual(ip_row['block_count'], 0)

    def test_live_blocker_blocks_the_ip_a_dry_run_only_simulated(self):
        self.fx.blocker(dry_run=True).block(IP, 'Tripwire')

        firewall = FakeFirewall()
        live = self.fx.blocker(firewall=firewall)
        self.assertTrue(live.block(IP, 'Tripwire'))

        self.assertEqual(firewall.blocked, [(IP, 1)],
                         "a simulated detection must not make the IP look blocked")
        self.assertEqual(self.fx.tier(IP), 1)

    def test_dry_run_rows_are_not_escalation_evidence(self):
        # A dry run that "reached" tier 2 must not push the first real block
        # of this IP past tier 1.
        self.fx.db.track_ip(IP)
        self.fx.db.record_simulated_block(IP, 2, 'r', 'web', '30d')

        self.assertIsNone(self.fx.db.get_recent_block(IP, WEEK))
        self.assertEqual(self.fx.db.determine_tier(IP, WEEK), 1)

        firewall = FakeFirewall()
        self.fx.blocker(firewall=firewall).block(IP, 'Tripwire')
        self.assertEqual(firewall.blocked, [(IP, 1)])

    def test_real_blocks_still_escalate(self):
        # Control for the filter above: it must only drop dry-run rows.
        firewall = FakeFirewall()
        blocker = self.fx.blocker(firewall=firewall)
        blocker.block(IP, 'Tripwire')
        self.fx.db.expire_block_tier(IP)       # what the reaper does
        blocker.block(IP, 'Tripwire')
        self.assertEqual(firewall.blocked, [(IP, 1), (IP, 2)])

    def test_a_later_dry_run_row_does_not_mask_a_real_one(self):
        firewall = FakeFirewall()
        blocker = self.fx.blocker(firewall=firewall)
        blocker.block(IP, 'Tripwire')
        self.fx.db.expire_block_tier(IP)
        self.fx.db.record_simulated_block(IP, 1, 'r', 'web', '24h')

        blocker.block(IP, 'Tripwire')

        self.assertEqual(firewall.blocked[-1], (IP, 2),
                         "the real tier-1 block is still the escalation evidence")

    def test_dry_run_does_not_feed_cidr_aggregation(self):
        blocker = self.fx.blocker(dry_run=True)
        for n in range(10, 16):
            blocker.block('192.0.2.%d' % n, 'Tripwire')

        self.assertEqual(self.fx.db.count_blocked_in_subnet('192.0.2.'), 0)
        self.assertEqual(self.fx.db.get_blocked_ips_in_subnet('192.0.2.'), [])

    def test_dry_run_unblock_changes_nothing(self):
        firewall = FakeFirewall()
        self.fx.blocker(firewall=firewall).block(IP, 'Tripwire')
        firewall.unblocked = []

        dry = self.fx.blocker(dry_run=True, firewall=firewall)
        self.assertTrue(dry.unblock(IP))

        self.assertEqual(firewall.unblocked, [])
        self.assertEqual(self.fx.tier(IP), 1)
        self.assertIsNotNone(self.fx.db.get_recent_block(IP, WEEK))


class TestDryRunDedupe(unittest.TestCase):
    """No tier is recorded any more, so repeats need their own brake."""

    def setUp(self):
        self.fx = DBFixture()

    def tearDown(self):
        self.fx.close()

    def test_repeat_detection_inside_tier1_window_logs_once(self):
        blocker = self.fx.blocker(dry_run=True)

        self.assertTrue(blocker.block(IP, 'Tripwire'))
        self.assertTrue(blocker.block(IP, 'Tripwire'))
        self.assertTrue(blocker.block(IP, 'Tripwire'))

        self.assertEqual(len(self.fx.block_log(IP)), 1)

    def test_logs_again_once_the_window_has_passed(self):
        blocker = self.fx.blocker(dry_run=True)
        blocker.block(IP, 'Tripwire')
        blocker._dry_run_seen[IP] = time.time() - 1   # window elapsed

        blocker.block(IP, 'Tripwire')

        self.assertEqual(len(self.fx.block_log(IP)), 2)

    def test_dedupe_is_per_ip(self):
        blocker = self.fx.blocker(dry_run=True)
        blocker.block(IP, 'Tripwire')
        blocker.block('192.0.2.11', 'Tripwire')
        self.assertEqual(len(self.fx.block_log()), 2)

    def test_manual_blocks_are_always_logged(self):
        # A deliberate operator action is not a repeat detection.
        blocker = self.fx.blocker(dry_run=True)
        ok1, msg1 = blocker.block_manual('192.0.2.50', duration='24h')
        ok2, msg2 = blocker.block_manual('192.0.2.50', duration='perm')

        self.assertTrue(ok1 and ok2)
        self.assertTrue(msg1.startswith('[DRY-RUN] Would block'))
        self.assertEqual(len(self.fx.block_log('192.0.2.50')), 2)

    def test_seen_dict_is_pruned_when_it_grows_past_the_cap(self):
        blocker = self.fx.blocker(dry_run=True)
        blocker._dry_run_seen_max = 3
        past = time.time() - 10
        for n in range(4):
            blocker._dry_run_seen['198.51.100.%d' % n] = past

        blocker.block(IP, 'Tripwire')

        self.assertEqual(list(blocker._dry_run_seen), [IP],
                         "expired entries go, the live one stays")


class TestMigration012(unittest.TestCase):
    """Reset the tiers that pre-fix dry runs left behind."""

    def setUp(self):
        self.fx = DBFixture()
        self.db = self.fx.db

    def tearDown(self):
        self.fx.close()

    def _poison(self, ip, blocker_name, tier=1):
        """What the old record_block() path produced."""
        self.db.track_ip(ip)
        self.db.record_block(ip, tier, 'r', 'web', blocker_name, '24h')

    def _run_migration(self):
        """Roll the stamp back to 11 and let the real runner apply 012."""
        self.db.conn.execute("DELETE FROM schema_version")
        self.db.conn.commit()
        migrator._record_version(self.db.conn, 11, 'pre-012 database')
        return migrator.run_migrations(self.db.conn, MIGRATIONS_DIR)

    def test_resets_poisoned_tiers_and_leaves_real_blocks_alone(self):
        self._poison('192.0.2.10', 'dry-run', tier=1)       # poisoned
        self._poison('192.0.2.11', 'dry-run', tier=3)       # poisoned, "permanent"
        self._poison('192.0.2.20', 'firewalld', tier=1)     # genuinely blocked
        self._poison('192.0.2.21', 'mikrotik', tier=3)      # genuinely permanent
        self._poison('192.0.2.30', 'firewalld', tier=1)     # real, then a dry run
        self._poison('192.0.2.30', 'dry-run', tier=2)
        self._poison('192.0.2.31', 'dry-run', tier=1)       # dry run, then real
        self._poison('192.0.2.31', 'firewalld', tier=2)

        # 012, plus every newer migration (013 in v1.7.19): the runner applies
        # all that are pending after the rolled-back stamp.
        self.assertGreaterEqual(self._run_migration(), 1)

        self.assertEqual(self.fx.tier('192.0.2.10'), 0)
        self.assertEqual(self.fx.tier('192.0.2.11'), 0)
        self.assertEqual(self.fx.tier('192.0.2.20'), 1)
        self.assertEqual(self.fx.tier('192.0.2.21'), 3)
        self.assertEqual(self.fx.tier('192.0.2.30'), 0,
                         "latest row is the dry run: the tier is its doing")
        self.assertEqual(self.fx.tier('192.0.2.31'), 2,
                         "latest row is a real block: keep it")

    def test_latest_row_is_by_timestamp_before_id(self):
        # Row 2 has the higher id but is OLDER; the real block at row 1 is the
        # latest event, so the IP stays blocked.
        self.db.track_ip(IP)
        now = int(time.time())
        self.db.conn.execute(
            "UPDATE ip_history SET current_tier = 1 WHERE ip = ?", (IP,))
        for ts, blocker_name in ((now, 'firewalld'), (now - 1000, 'dry-run')):
            self.db.conn.execute(
                "INSERT INTO block_log (ip, timestamp, tier, reason, service, "
                "blocker, duration) VALUES (?, ?, 1, 'r', 'web', ?, '24h')",
                (IP, ts, blocker_name))
        self.db.conn.commit()

        self._run_migration()

        self.assertEqual(self.fx.tier(IP), 1)

    def test_ip_with_no_block_history_and_unblocked_ips_are_untouched(self):
        self.db.track_ip(IP)
        self.db.conn.execute(
            "UPDATE ip_history SET current_tier = 2 WHERE ip = ?", (IP,))
        self.db.conn.commit()
        self._poison('192.0.2.11', 'dry-run', tier=1)
        self.db.expire_block_tier('192.0.2.11')

        self._run_migration()

        self.assertEqual(self.fx.tier(IP), 2, "no block_log row says it is simulated")
        self.assertEqual(self.fx.tier('192.0.2.11'), 0)

    def test_block_log_rows_survive(self):
        self._poison(IP, 'dry-run')
        before = len(self.fx.block_log(IP))
        self._run_migration()
        self.assertEqual(len(self.fx.block_log(IP)), before)

    def test_is_idempotent(self):
        self._poison('192.0.2.10', 'dry-run')
        self._poison('192.0.2.20', 'firewalld')
        self._run_migration()
        snapshot = (self.fx.tier('192.0.2.10'), self.fx.tier('192.0.2.20'))

        # Apply the same migration file a second time, outside the version gate.
        path = os.path.join(MIGRATIONS_DIR, '012_dry_run_tiers.sql')
        migrator._run_migration(self.db.conn, 12, path, 'dry run tiers')

        self.assertEqual(
            (self.fx.tier('192.0.2.10'), self.fx.tier('192.0.2.20')), snapshot)

    def test_schema_version_matches_the_newest_migration_file(self):
        newest = max(v for v, _, _ in migrator._discover_migrations(MIGRATIONS_DIR))
        self.assertEqual(newest, 13)
        self.assertEqual(migrator.CURRENT_SCHEMA_VERSION, newest)
        self.assertEqual(self.db.get_schema_version(), newest,
                         "a fresh database is stamped current")


class TestNoBackendIsAnOutageNotADryRun(unittest.TestCase):
    def setUp(self):
        self.fx = DBFixture()

    def tearDown(self):
        self.fx.close()

    def test_block_is_refused_and_nothing_is_recorded(self):
        telegram = FakeTelegram()
        blocker = self.fx.blocker(firewall=None, telegram=telegram)

        with self.assertLogs('wp-guardian.blocker', level='ERROR'):
            self.assertFalse(blocker.block(IP, 'Tripwire'))

        self.assertEqual(self.fx.block_log(), [], "no block_log row for a block that never happened")
        ip_row = self.fx.db.get_ip(IP)
        self.assertEqual(ip_row['current_tier'], 0)
        self.assertEqual(ip_row['block_count'], 0)
        self.assertEqual(telegram.sent, [], "no per-event Telegram")
        self.assertEqual(telegram.blocks, [])
        self.assertEqual(blocker.unenforced_count, 1)

    def test_error_is_logged_at_most_once_a_minute(self):
        blocker = self.fx.blocker(firewall=None)
        with self.assertLogs('wp-guardian.blocker', level='ERROR') as captured:
            for n in range(10, 15):
                blocker.block('192.0.2.%d' % n, 'Tripwire')
        self.assertEqual(len(captured.records), 1)
        self.assertEqual(blocker.unenforced_count, 5)

    def test_take_unenforced_reports_events_and_distinct_ips_then_resets(self):
        blocker = self.fx.blocker(firewall=None)
        with self.assertLogs('wp-guardian.blocker', level='ERROR'):
            blocker.block(IP, 'Tripwire')
            blocker.block(IP, 'Tripwire')
            blocker.block('192.0.2.11', 'Tripwire')

        self.assertEqual(blocker.take_unenforced(), (3, 2))
        self.assertEqual(blocker.take_unenforced(), (0, 0))
        self.assertEqual(blocker.unenforced_count, 0)

    def test_attaching_a_backend_restores_enforcement(self):
        blocker = self.fx.blocker(firewall=None)
        with self.assertLogs('wp-guardian.blocker', level='ERROR'):
            self.assertFalse(blocker.block(IP, 'Tripwire'))

        firewall = FakeFirewall()
        blocker.firewall = firewall
        self.assertTrue(blocker.block(IP, 'Tripwire'))

        self.assertEqual(firewall.blocked, [(IP, 1)])
        self.assertEqual(self.fx.tier(IP), 1)

    def test_manual_ip_block_says_the_backend_is_unavailable(self):
        blocker = self.fx.blocker(firewall=None)
        ok, msg = blocker.block_manual('192.0.2.50')
        self.assertFalse(ok)
        self.assertEqual(msg, UNAVAILABLE_MSG)
        self.assertNotIn('DRY-RUN', msg)
        self.assertNotIn('firewall error', msg)
        self.assertEqual(self.fx.block_log(), [])

    def test_manual_cidr_block_says_the_backend_is_unavailable(self):
        blocker = self.fx.blocker(firewall=None)
        ok, msg = blocker.block_manual('192.0.2.0/24')
        self.assertFalse(ok)
        self.assertEqual(msg, UNAVAILABLE_MSG)
        self.assertNotIn('DRY-RUN', msg)

    def test_manual_cidr_block_in_dry_run_is_still_a_simulation(self):
        blocker = self.fx.blocker(dry_run=True, firewall=None)
        ok, msg = blocker.block_manual('192.0.2.0/24')
        self.assertTrue(ok)
        self.assertIn('[DRY-RUN]', msg)

    def test_dry_run_without_a_backend_still_simulates_blocks(self):
        # The operator asked for dry-run: no outage handling, just the sim.
        blocker = self.fx.blocker(dry_run=True, firewall=None)
        self.assertTrue(blocker.block(IP, 'Tripwire'))
        self.assertEqual(blocker.unenforced_count, 0)
        self.assertEqual(self.fx.block_log(IP)[0]['blocker'], 'dry-run')

    def test_unblock_without_a_backend_fails_and_changes_nothing(self):
        firewall = FakeFirewall()
        self.fx.blocker(firewall=firewall).block(IP, 'Tripwire')

        blocker = self.fx.blocker(firewall=None)
        with self.assertLogs('wp-guardian.blocker', level='ERROR'):
            self.assertFalse(blocker.unblock(IP))

        self.assertEqual(self.fx.tier(IP), 1)


class TestUnblockReportsFailureHonestly(unittest.TestCase):
    def setUp(self):
        self.fx = DBFixture()

    def tearDown(self):
        self.fx.close()

    def _blocked(self, **firewall_kwargs):
        firewall = FakeFirewall(**firewall_kwargs)
        blocker = self.fx.blocker(firewall=firewall)
        # Block while the backend still works, then let unblock misbehave.
        firewall.block_ok = True
        blocker.block(IP, 'Tripwire')
        return blocker, firewall

    def test_backend_reporting_failure_leaves_state_untouched(self):
        blocker, firewall = self._blocked(unblock_ok=False)

        with self.assertLogs('wp-guardian.blocker', level='ERROR'):
            self.assertFalse(blocker.unblock(IP))

        self.assertEqual(firewall.unblocked, [IP])
        self.assertEqual(self.fx.tier(IP), 1, "still blocked, so still recorded as blocked")
        self.assertIsNotNone(self.fx.db.get_recent_block(IP, WEEK),
                             "escalation history not cleared")
        self.assertEqual(self.fx.block_log(IP)[0]['cleared_at'], 0)

    def test_backend_raising_leaves_state_untouched(self):
        blocker, _ = self._blocked(unblock_raises=RuntimeError('ssh to router timed out'))

        with self.assertLogs('wp-guardian.blocker', level='ERROR'):
            self.assertFalse(blocker.unblock(IP))

        self.assertEqual(self.fx.tier(IP), 1)
        self.assertEqual(self.fx.block_log(IP)[0]['cleared_at'], 0)

    def test_success_clears_tier_and_history(self):
        blocker, firewall = self._blocked()

        self.assertTrue(blocker.unblock(IP))

        self.assertEqual(firewall.unblocked, [IP])
        self.assertEqual(self.fx.tier(IP), 0)
        self.assertGreater(self.fx.block_log(IP)[0]['cleared_at'], 0)
        self.assertIsNone(self.fx.db.get_recent_block(IP, WEEK))


# ---------------------------------------------------------------------------
# CompromiseAction under the global dry-run flag
# ---------------------------------------------------------------------------
COUNTS = {'countries': 28, 'asns': 39, 'ips': 62}
OBSERVED = [{'ip': '192.0.2.1%d' % n, 'asn': 64500 + n} for n in range(3)]


class CAFakeBlocker(object):
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.blocks = []

    def block(self, ip, reason, service='', username='', rule='', **kwargs):
        self.blocks.append(ip)
        return True


class CAFakeMail(object):
    enabled = True

    def __init__(self):
        self.disabled = []
        self.reenabled = []

    def disable_mailbox(self, email):
        self.disabled.append(email)
        return True

    def enable_mailbox(self, email):
        self.reenabled.append(email)
        return True


class CAFakeTelegram(object):
    def __init__(self):
        self.compromise_alerts = []
        self.raw = []

    def alert_compromise(self, **kwargs):
        self.compromise_alerts.append(kwargs)

    def send(self, msg, priority=''):
        self.raw.append(msg)


class CAFakeDB(object):
    """Only what CompromiseAction touches."""

    def __init__(self, events=None, guardian_disabled=None):
        self.events = events or []
        self.guardian_disabled = set(guardian_disabled or [])
        self.mailbox_actions = []
        self.updates = []
        self.reversed_ids = []

    def recent_auth_ips_with_asn(self, username, window_seconds, limit=1000):
        return list(OBSERVED)

    def recent_auth_countries(self, username, window_seconds):
        return ['US']

    def insert_compromise_event(self, **kwargs):
        return 1

    def update_compromise_event(self, event_id, updates):
        self.updates.append((event_id, updates))

    def insert_mailbox_action(self, username, action, actor, **kwargs):
        self.mailbox_actions.append((username, action))

    def get_auto_reenable_candidates(self, cutoff, limit=50):
        return [e for e in self.events
                if e['detected_at'] <= cutoff and e['id'] not in self.reversed_ids][:limit]

    def is_mailbox_disabled_by_guardian(self, username):
        return username in self.guardian_disabled

    def mark_compromise_auto_reversed(self, event_id, note=''):
        self.reversed_ids.append(event_id)


def build_action(blocker, db=None, mail=None, telegram=None, **overrides):
    import configparser
    config = configparser.ConfigParser()
    config.add_section('compromise_detection')
    config.set('compromise_detection', 'action', 'full')
    for key, value in overrides.items():
        config.set('compromise_detection', key, str(value))
    return CompromiseAction(
        config,
        db if db is not None else CAFakeDB(),
        blocker,
        mail if mail is not None else CAFakeMail(),
        telegram if telegram is not None else CAFakeTelegram(),
    )


class TestCompromiseUnderDryRun(unittest.TestCase):
    USER = 'alice@example.com'

    def _handle(self, action):
        return action.handle(username=self.USER, service='imap',
                             trigger_rule='countries', counts=COUNTS,
                             window_seconds=3600)

    def test_dry_run_never_disables_the_mailbox(self):
        blocker, db, mail, tg = CAFakeBlocker(dry_run=True), CAFakeDB(), CAFakeMail(), CAFakeTelegram()
        action = build_action(blocker, db=db, mail=mail, telegram=tg)

        self._handle(action)

        self.assertEqual(mail.disabled, [], "the mail backend must not be called")
        self.assertEqual(db.mailbox_actions, [],
                         "a simulated disable must not look like a real one later")

    def test_dry_run_event_is_recorded_as_simulated(self):
        blocker, db = CAFakeBlocker(dry_run=True), CAFakeDB()
        action = build_action(blocker, db=db)

        self._handle(action)

        _, updates = db.updates[0]
        self.assertEqual(updates['mailbox_disabled'], 0,
                         "else the auto-reenable reaper would 'restore' a mailbox we never touched")
        self.assertEqual(updates['action_taken'], 'dry_run_full')

    def test_dry_run_alert_says_it_was_simulated(self):
        blocker, tg = CAFakeBlocker(dry_run=True), CAFakeTelegram()
        action = build_action(blocker, telegram=tg)

        self._handle(action)

        self.assertEqual(len(tg.compromise_alerts), 1)
        sent = tg.compromise_alerts[0]
        self.assertTrue(sent['dry_run'])
        self.assertTrue(sent['mailbox_simulated'],
                        "else the alert says 'NOT disabled (disable manually)'")
        self.assertFalse(sent['mailbox_disabled'])

    def test_dry_run_alert_text(self):
        """The real formatter, not the fake: both halves say 'simulated'."""
        from actions.telegram import TelegramAlerter
        alerter = TelegramAlerter.__new__(TelegramAlerter)
        captured = []
        alerter.send = lambda msg, priority='': captured.append(msg)
        alerter.alert_compromise(
            username=self.USER, service='imap', trigger_rule='countries',
            counts=COUNTS, ips_blocked=3, mailbox_disabled=False, event_id=7,
            action='full', dry_run=True, mailbox_simulated=True)
        msg = captured[0]
        self.assertIn('[DRY-RUN]', msg)
        self.assertIn('would have been disabled', msg)
        self.assertIn('3 (simulated)', msg)
        self.assertNotIn('disable manually', msg)
        self.assertNotIn('/confirm', msg)

    def test_live_run_is_unchanged(self):
        blocker, db, mail, tg = CAFakeBlocker(dry_run=False), CAFakeDB(), CAFakeMail(), CAFakeTelegram()
        action = build_action(blocker, db=db, mail=mail, telegram=tg)

        self._handle(action)

        self.assertEqual(mail.disabled, [self.USER])
        self.assertEqual(db.updates[0][1]['action_taken'], 'full')
        self.assertEqual(db.updates[0][1]['mailbox_disabled'], 1)
        self.assertEqual(len(tg.compromise_alerts), 1)
        self.assertEqual(tg.raw, [])

    def test_flag_is_read_at_call_time_not_at_construction(self):
        blocker, mail = CAFakeBlocker(dry_run=False), CAFakeMail()
        action = build_action(blocker, mail=mail)

        blocker.dry_run = True
        self._handle(action)
        self.assertEqual(mail.disabled, [])

        blocker.dry_run = False
        self._handle(action)
        self.assertEqual(mail.disabled, [self.USER])

    def test_alert_only_rule_in_dry_run_keeps_the_normal_alert(self):
        # Nothing to simulate: no mailbox action was going to happen.
        blocker, tg = CAFakeBlocker(dry_run=True), CAFakeTelegram()
        action = build_action(blocker, telegram=tg, action='alert_only')

        self._handle(action)

        self.assertEqual(len(tg.compromise_alerts), 1)
        self.assertEqual(tg.raw, [])

    def test_summarize_keeps_its_old_two_argument_form(self):
        self.assertEqual(CompromiseAction._summarize(3, True), 'full')
        self.assertEqual(CompromiseAction._summarize(0, True), 'mailbox_disabled')
        self.assertEqual(CompromiseAction._summarize(3, False), 'ips_blocked')
        self.assertEqual(CompromiseAction._summarize(0, False), 'alert_only')


class TestMailboxReaperHonoursGlobalDryRun(unittest.TestCase):
    USER = 'bob@example.net'

    def _event(self):
        return {'id': 1, 'username': self.USER, 'service': 'imap',
                'trigger_rule': 'countries',
                'detected_at': int(time.time()) - 9 * 3600}

    def test_global_dry_run_blocks_the_reenable(self):
        blocker, mail = CAFakeBlocker(dry_run=True), CAFakeMail()
        db = CAFakeDB(events=[self._event()], guardian_disabled=[self.USER])
        action = build_action(blocker, db=db, mail=mail, auto_reenable_hours=4)

        result = action.reap_auto_disabled_mailboxes()   # no dry_run argument

        self.assertEqual(mail.reenabled, [])
        self.assertEqual(db.reversed_ids, [], "event must stay a candidate")
        self.assertEqual(db.mailbox_actions, [])
        self.assertEqual(result['restored'], 1, "reported as 'would restore'")

    def test_without_the_flag_the_reaper_still_restores(self):
        blocker, mail = CAFakeBlocker(dry_run=False), CAFakeMail()
        db = CAFakeDB(events=[self._event()], guardian_disabled=[self.USER])
        action = build_action(blocker, db=db, mail=mail, auto_reenable_hours=4)

        action.reap_auto_disabled_mailboxes()

        self.assertEqual(mail.reenabled, [self.USER])
        self.assertEqual(db.reversed_ids, [1])


if __name__ == '__main__':
    unittest.main()
