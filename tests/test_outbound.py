"""Tests for outbound send correlation and payload-phase corroboration (v1.7.15).

Two properties are load-bearing here.

**The queue-ID join.** Postfix's qmgr logs inbound and outbound mail in exactly
the same shape. Counting qmgr lines alone would measure how much mail the
server RECEIVES for an account and report it as sending — on the reference host
most sampled qmgr lines were inbound bounces and spam. A queue ID is only ours
going out if it was first seen on an authenticated smtpd line, so the tests
below feed inbound and outbound lines through the same detector and assert that
only the authenticated one is recorded.

**Fail toward no signal.** Same governing property as the rest of
`tests/test_corroboration.py`: a missing database, an exception, an empty
table, a young install — none of them may manufacture evidence, because a
signal here promotes enforcement up to disabling a paying client's mailbox.

Uses a real on-disk GuardianDB rather than a fake, so migration 011 and the
actual SQL are exercised. Stdlib unittest, no test dependencies.

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
from modules.database import GuardianDB  # noqa: E402
from modules.outbound import (  # noqa: E402
    OutboundTracker, parse_qmgr, parse_submission,
)


# Real lines from mail.maiahost.com, 2026-08-11.
SUBMISSION = ('Aug 11 14:22:31 mail postfix/smtps/smtpd[65793]: '
              '0F5B86C403F7: client=host[198.51.100.20], sasl_method=PLAIN, '
              'sasl_username=erin@example.com')
QMGR_OURS = ('Aug 11 14:22:32 mail postfix/qmgr[4031830]: '
             '0F5B86C403F7: from=<erin@example.com>, size=80933, '
             'nrcpt=1 (queue active)')
# Same shape, different queue ID, never authenticated here — inbound.
QMGR_INBOUND = ('Aug 11 14:23:02 mail postfix/qmgr[4031830]: '
                '4BAFB6C403F3: from=<bounce@amazonses.com>, size=12045, '
                'nrcpt=1 (queue active)')


def make_config(**overrides):
    config = configparser.ConfigParser()
    config.add_section('compromise_detection')
    config.add_section('mail_backend')
    config.add_section('database')
    config.add_section('thresholds')
    config.add_section('auth_tracking')
    for key, value in overrides.items():
        config.set('compromise_detection', key, str(value))
    return config


class TempDB(unittest.TestCase):
    """Base: a real migrated database in a temp directory."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.db = GuardianDB(os.path.join(self.root, 'state', 'guardian.db'))
        self.addCleanup(self.db.conn.close)

    def arm_observation(self, days=30):
        """One ancient row from an UNRELATED account.

        The volume baseline is gated on how long Guardian has been watching
        outbound at all, not on the account under test — that is what lets a
        genuinely silent mailbox be distinguished from a fresh install.
        """
        self.db.record_outbound('someone-else@example.com', '', 1, 0, 'OLD',
                                int(time.time()) - days * 86400)

    def bulk(self, rows):
        """Fixture fast path — (username, timestamp, nrcpt) tuples.

        Bypasses record_outbound deliberately: seeding thousands of rows one
        commit at a time is slow, and record_outbound has its own tests.
        """
        self.db.conn.executemany(
            "INSERT INTO outbound_activity "
            "(username, ip, timestamp, queue_id, nrcpt, size_bytes) "
            "VALUES (?, '', ?, '', ?, 1000)", rows)
        self.db.conn.commit()

    def seed(self, username, count, ago_seconds, nrcpt=1):
        """`count` messages, all at one instant `ago_seconds` ago."""
        stamp = int(time.time()) - ago_seconds
        self.bulk([(username, stamp, nrcpt)] * count)

    def seed_history(self, username, per_day, days, ending_hours_ago=12):
        """A steady daily send rate, ending before the recent window."""
        now = int(time.time())
        rows = []
        for d in range(days):
            stamp = now - ending_hours_ago * 3600 - d * 86400
            rows.extend([(username, stamp, 1)] * per_day)
        self.bulk(rows)


# ----------------------------------------------------------------------
# Parsing
# ----------------------------------------------------------------------
class TestParsing(unittest.TestCase):
    def test_submission_queue_id(self):
        self.assertEqual(parse_submission(SUBMISSION), '0F5B86C403F7')

    def test_qmgr_fields(self):
        self.assertEqual(parse_qmgr(QMGR_OURS), ('0F5B86C403F7', 80933, 1))

    def test_noqueue_is_not_a_queue_id(self):
        # NOQUEUE is alphanumeric and sits in the queue-ID position. Treated
        # as an ID it would become one bucket shared by every rejected
        # message on the host.
        line = ('Aug 11 14:22:31 mail postfix/smtpd[65793]: NOQUEUE: '
                'client=unknown[1.2.3.4], sasl_method=PLAIN, '
                'sasl_username=victim@example.com')
        self.assertEqual(parse_submission(line), '')

    def test_qmgr_removed_line_is_ignored(self):
        # The second qmgr line for every message. No nrcpt, so it cannot
        # match — which is what keeps this one row per message.
        line = ('Aug 11 14:22:40 mail postfix/qmgr[4031830]: '
                '0F5B86C403F7: removed')
        self.assertIsNone(parse_qmgr(line))

    def test_unrelated_lines_parse_to_nothing(self):
        for line in ('Aug 11 14:22:31 mail dovecot: imap-login: Login: '
                     'user=<a@b.com>, rip=1.2.3.4',
                     'random junk',
                     ''):
            self.assertEqual(parse_submission(line), '')
            self.assertIsNone(parse_qmgr(line))


# ----------------------------------------------------------------------
# Correlation
# ----------------------------------------------------------------------
class TestCorrelation(TempDB):
    def build(self, **overrides):
        return OutboundTracker(make_config(**overrides), self.db)

    def test_matched_pair_is_recorded(self):
        t = self.build()
        t.note_submission('QID1', 'erin@example.com', '198.51.100.20')
        self.assertTrue(t.note_delivery('QID1', 80933, 3))

        stats = self.db.outbound_window_stats('erin@example.com', 3600)
        self.assertEqual(stats['messages'], 1)
        self.assertEqual(stats['max_nrcpt'], 3)

    def test_unmatched_qmgr_records_nothing(self):
        # THE test. An inbound message must never be counted as the account's
        # sending, or the volume check measures the wrong thing entirely.
        t = self.build()
        self.assertFalse(t.note_delivery('NEVER-SEEN', 12045, 1))
        self.assertEqual(t.stats['unmatched'], 1)
        self.assertEqual(self.db.outbound_top_senders(days=1), [])

    def test_a_queue_id_is_consumed_once(self):
        # qmgr can log the same message again after a deferral. Popping the
        # pending entry is what keeps that from double-counting.
        t = self.build()
        t.note_submission('QID1', 'a@b.com', '1.2.3.4')
        self.assertTrue(t.note_delivery('QID1', 100, 1))
        self.assertFalse(t.note_delivery('QID1', 100, 1))
        self.assertEqual(self.db.outbound_window_stats('a@b.com', 3600)['messages'], 1)

    def test_expired_submission_is_not_recorded(self):
        # Queue IDs are reused over time. Recording against a stale pending
        # entry would attribute a stranger's message to this account.
        t = self.build(outbound_queue_ttl=300)
        t.note_submission('QID1', 'a@b.com', '1.2.3.4', now=time.time() - 400)
        self.assertFalse(t.note_delivery('QID1', 100, 1))
        self.assertEqual(t.stats['expired'], 1)
        self.assertEqual(self.db.outbound_top_senders(days=1), [])

    def test_pending_map_is_capped(self):
        t = self.build(outbound_max_pending=10)
        for i in range(25):
            t.note_submission('Q{i}'.format(i=i), 'a@b.com', '1.2.3.4')
        self.assertLessEqual(t.pending_count(), 10)
        self.assertEqual(t.stats['dropped'], 15)
        # The oldest were evicted, so their qmgr lines no longer match. Losing
        # a send record fails toward no signal, which is the safe direction.
        self.assertFalse(t.note_delivery('Q0', 100, 1))
        self.assertTrue(t.note_delivery('Q24', 100, 1))

    def test_disabled_tracker_records_nothing(self):
        t = self.build(outbound_monitoring='false')
        t.note_submission('QID1', 'a@b.com', '1.2.3.4')
        self.assertFalse(t.note_delivery('QID1', 100, 1))
        self.assertEqual(self.db.outbound_top_senders(days=1), [])

    def test_submission_without_username_is_ignored(self):
        t = self.build()
        t.note_submission('QID1', '', '1.2.3.4')
        self.assertFalse(t.note_delivery('QID1', 100, 1))

    def test_database_error_does_not_propagate(self):
        # This runs inside the mail tailer thread. An exception escaping here
        # would take down brute-force blocking along with it.
        class Exploding:
            def record_outbound(self, **kwargs):
                raise RuntimeError("disk full")

        t = OutboundTracker(make_config(), Exploding())
        t.note_submission('QID1', 'a@b.com', '1.2.3.4')
        self.assertFalse(t.note_delivery('QID1', 100, 1))
        self.assertEqual(t.stats['errors'], 1)


# ----------------------------------------------------------------------
# End to end through the detector
# ----------------------------------------------------------------------
class FakeBlocker:
    def __init__(self):
        self.blocks = []

    def block(self, ip, reason, **kwargs):
        self.blocks.append(ip)
        return True

    def alert_trusted_skip(self, *a, **kw):
        pass

    def alert_guardian_disabled_skip(self, *a, **kw):
        pass


class TestDetectorWiring(TempDB):
    def setUp(self):
        TempDB.setUp(self)
        from detectors.mail import MailDetector
        config = make_config()
        self.tracker = OutboundTracker(config, self.db)
        self.detector = MailDetector(config, FakeBlocker(), self.db,
                                     outbound_tracker=self.tracker)

    def test_authenticated_submission_is_counted(self):
        self.detector.process_line(SUBMISSION)
        self.detector.process_line(QMGR_OURS)
        stats = self.db.outbound_window_stats('erin@example.com', 3600)
        self.assertEqual(stats['messages'], 1)
        self.assertEqual(stats['recipients'], 1)

    def test_inbound_mail_is_not_counted(self):
        # Fed WITHOUT a preceding authenticated smtpd line, exactly as an
        # inbound bounce arrives on a real host.
        self.detector.process_line(QMGR_INBOUND)
        self.assertEqual(self.db.outbound_top_senders(days=1), [])
        self.assertEqual(self.tracker.stats['unmatched'], 1)

    def test_interleaved_streams_attribute_correctly(self):
        self.detector.process_line(SUBMISSION)
        self.detector.process_line(QMGR_INBOUND)      # someone else's mail
        self.detector.process_line(QMGR_OURS)
        senders = self.db.outbound_top_senders(days=1)
        self.assertEqual(len(senders), 1)
        self.assertEqual(senders[0]['username'], 'erin@example.com')
        self.assertEqual(senders[0]['messages'], 1)

    def test_auth_success_is_still_recorded(self):
        # The queue-ID capture rides the existing auth branch — it must not
        # disturb what that branch already does.
        self.detector.process_line(SUBMISSION)
        self.assertTrue(self.db.is_ip_authenticated('198.51.100.20', 3600))

    def test_detector_without_a_tracker_still_works(self):
        from detectors.mail import MailDetector
        d = MailDetector(make_config(), FakeBlocker(), self.db)
        d.process_line(SUBMISSION)
        d.process_line(QMGR_OURS)
        self.assertTrue(self.db.is_ip_authenticated('198.51.100.20', 3600))


# ----------------------------------------------------------------------
# Volume corroboration
# ----------------------------------------------------------------------
class TestOutboundVolume(TempDB):
    def build(self, **overrides):
        opts = {'outbound_window_hours': 6, 'outbound_volume_floor': 100,
                'outbound_volume_multiplier': 10,
                'outbound_min_observation_days': 14,
                'outbound_fanout_threshold': 0}   # isolate the volume check
        opts.update(overrides)
        return AbuseCorroborator(make_config(**opts), self.db)

    def test_burst_from_a_silent_account_is_a_signal(self):
        self.arm_observation(days=30)
        self.seed('victim@example.com', 300, ago_seconds=600)
        signals = self.build().evaluate('victim@example.com')
        self.assertEqual(len(signals), 1)
        self.assertIn('no send history', signals[0])

    def test_burst_far_above_the_accounts_own_rate_is_a_signal(self):
        self.arm_observation(days=30)
        # A quiet mailbox: 10 a day for 25 days, about 0.4/h.
        self.seed_history('victim@example.com', per_day=10, days=25)
        # Then 300 in six hours — 50/h, well over a hundred times its normal.
        self.seed('victim@example.com', 300, ago_seconds=600)
        signals = self.build().evaluate('victim@example.com')
        self.assertEqual(len(signals), 1)
        self.assertIn('outbound volume', signals[0])

    def test_busy_account_within_its_own_rate_is_silent(self):
        # The comparison is against the account itself, not a server-wide
        # number. A booking address that sends 200 a day is not anomalous for
        # doing 300 in six hours, even though that would be a huge spike for
        # the mailbox in the test above.
        self.arm_observation(days=30)
        self.seed_history('busy@example.com', per_day=200, days=25)
        self.seed('busy@example.com', 300, ago_seconds=600)
        self.assertEqual(self.build().evaluate('busy@example.com'), [])

    def test_below_the_floor_is_silent(self):
        # An enormous ratio on a small absolute number is where every
        # plausible false positive for this check comes from.
        self.arm_observation(days=30)
        self.seed('victim@example.com', 50, ago_seconds=600)
        self.assertEqual(self.build().evaluate('victim@example.com'), [])

    def test_check_is_inert_before_enough_history_accrues(self):
        # A fresh install has an empty table, in which every account looks
        # anomalous. This is the whole reason the volume check cannot be the
        # only outbound signal.
        self.arm_observation(days=3)
        self.seed('victim@example.com', 500, ago_seconds=600)
        self.assertEqual(self.build().evaluate('victim@example.com'), [])

    def test_observation_is_global_not_per_account(self):
        # The ancient row belongs to a different account. Guardian has been
        # watching for 30 days, so this account's silence is real history.
        self.arm_observation(days=30)
        self.seed('victim@example.com', 300, ago_seconds=600)
        self.assertTrue(self.build().evaluate('victim@example.com'))

    def test_baseline_excludes_the_recent_window(self):
        # If the burst counted toward the baseline it is measured against, it
        # would raise its own bar — the check would quietly stop working at
        # exactly the volumes that matter most.
        self.seed('victim@example.com', 500, ago_seconds=600)        # the burst
        self.seed('victim@example.com', 10, ago_seconds=48 * 3600)   # real history
        baseline = self.db.outbound_baseline(
            'victim@example.com', 30 * 86400, exclude_recent_seconds=6 * 3600)
        self.assertEqual(baseline['messages'], 10)

    def test_a_large_burst_still_signals_against_a_real_baseline(self):
        self.arm_observation(days=30)
        self.seed_history('victim@example.com', per_day=10, days=25)
        self.seed('victim@example.com', 5000, ago_seconds=600)
        self.assertTrue(self.build().evaluate('victim@example.com'))

    def test_other_accounts_traffic_does_not_count(self):
        self.arm_observation(days=30)
        self.seed('someone-else@example.com', 500, ago_seconds=600)
        self.assertEqual(self.build().evaluate('victim@example.com'), [])


# ----------------------------------------------------------------------
# Fan-out corroboration
# ----------------------------------------------------------------------
class TestOutboundFanout(TempDB):
    def build(self, **overrides):
        opts = {'outbound_window_hours': 6, 'outbound_fanout_threshold': 50,
                'outbound_volume_floor': 999999}   # isolate the fan-out check
        opts.update(overrides)
        return AbuseCorroborator(make_config(**opts), self.db)

    def test_large_fanout_is_a_signal_with_no_history_at_all(self):
        # The point of shipping fan-out alongside volume: it is armed on the
        # day of installation and covers the weeks the baseline needs.
        self.seed('victim@example.com', 1, ago_seconds=600, nrcpt=200)
        signals = self.build().evaluate('victim@example.com')
        self.assertEqual(len(signals), 1)
        self.assertIn('fan-out', signals[0])
        self.assertIn('200', signals[0])

    def test_below_threshold_is_silent(self):
        self.seed('victim@example.com', 20, ago_seconds=600, nrcpt=10)
        self.assertEqual(self.build().evaluate('victim@example.com'), [])

    def test_recipients_are_not_summed_across_messages(self):
        # Fan-out is about ONE message to many people. Many small messages is
        # the volume check's business, and conflating them would make fan-out
        # fire on ordinary traffic while the baseline is still inert.
        self.seed('victim@example.com', 100, ago_seconds=600, nrcpt=10)
        self.assertEqual(self.build().evaluate('victim@example.com'), [])

    def test_old_fanout_is_outside_the_window(self):
        self.seed('victim@example.com', 1, ago_seconds=48 * 3600, nrcpt=200)
        self.assertEqual(self.build().evaluate('victim@example.com'), [])

    def test_zero_threshold_disables_the_check(self):
        self.seed('victim@example.com', 1, ago_seconds=600, nrcpt=5000)
        self.assertEqual(
            self.build(outbound_fanout_threshold=0).evaluate('victim@example.com'), [])


# ----------------------------------------------------------------------
# Fail safety
# ----------------------------------------------------------------------
class TestOutboundFailSafety(unittest.TestCase):
    def test_no_database_produces_no_signal(self):
        c = AbuseCorroborator(make_config(), db=None)
        self.assertEqual(c.evaluate('office@example.com'), [])

    def test_a_raising_database_produces_no_signal(self):
        class Exploding:
            def outbound_observation_days(self):
                raise RuntimeError("database on fire")

            def outbound_window_stats(self, username, window):
                raise RuntimeError("database on fire")

        c = AbuseCorroborator(make_config(), db=Exploding())
        self.assertEqual(c.evaluate('office@example.com'), [])

    def test_empty_table_produces_no_signal(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        db = GuardianDB(os.path.join(root, 'state', 'guardian.db'))
        self.addCleanup(db.conn.close)
        c = AbuseCorroborator(make_config(), db)
        self.assertEqual(c.evaluate('office@example.com'), [])
        self.assertEqual(db.outbound_observation_days(), 0.0)

    def test_disabled_corroborator_skips_outbound_too(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        db = GuardianDB(os.path.join(root, 'state', 'guardian.db'))
        self.addCleanup(db.conn.close)
        db.record_outbound('victim@example.com', '', 5000, 0, 'Q', int(time.time()))
        c = AbuseCorroborator(make_config(corroboration_enabled='false'), db)
        self.assertEqual(c.evaluate('victim@example.com'), [])


# ----------------------------------------------------------------------
# Backfill replay
# ----------------------------------------------------------------------
class TestBackfillReplay(TempDB):
    """The backfill replays history through the real tracker.

    That is only sound because note_submission/note_delivery take an explicit
    `now`. Replaying against the wall clock would make every pending entry look
    infinitely expired and the whole backfill would record nothing.
    """

    def test_ttl_is_measured_in_log_time_not_wall_clock(self):
        t = OutboundTracker(make_config(outbound_queue_ttl=300), self.db)
        base = time.time() - 30 * 86400          # a month-old log
        t.note_submission('Q1', 'a@b.com', '1.2.3.4', now=base)
        self.assertTrue(t.note_delivery('Q1', 500, 2, now=base + 2))
        # The row carries the LOG timestamp, not now(), or the baseline would
        # see a month of history compressed into one instant.
        row = self.db.conn.execute(
            "SELECT timestamp FROM outbound_activity").fetchone()
        self.assertAlmostEqual(row['timestamp'], base + 2, delta=2)

    def test_ttl_still_expires_within_log_time(self):
        t = OutboundTracker(make_config(outbound_queue_ttl=300), self.db)
        base = time.time() - 30 * 86400
        t.note_submission('Q1', 'a@b.com', '1.2.3.4', now=base)
        self.assertFalse(t.note_delivery('Q1', 500, 2, now=base + 400))

    def test_replay_is_idempotent_via_outbound_exists(self):
        stamp = int(time.time()) - 3600
        self.db.record_outbound('a@b.com', '1.2.3.4', 1, 100, 'Q1', stamp)
        self.assertTrue(self.db.outbound_exists('Q1', stamp))
        self.assertTrue(self.db.outbound_exists('Q1', stamp + 1))   # tolerance
        self.assertFalse(self.db.outbound_exists('Q1', stamp + 900))
        self.assertFalse(self.db.outbound_exists('OTHER', stamp))

    def test_empty_queue_id_never_matches(self):
        # Live rows may carry an empty queue_id. Treating '' as a key would
        # make one such row suppress every later backfill insert.
        self.db.record_outbound('a@b.com', '', 1, 0, '', int(time.time()))
        self.assertFalse(self.db.outbound_exists('', int(time.time())))

    def test_pending_map_survives_a_file_boundary(self):
        # logrotate can split a message's submission line from its qmgr line
        # across two files. One tracker for the whole run is what makes the
        # join land anyway.
        t = OutboundTracker(make_config(), self.db)
        base = time.time() - 7 * 86400
        t.note_submission('Q1', 'a@b.com', '1.2.3.4', now=base)   # end of file N
        self.assertTrue(t.note_delivery('Q1', 500, 1, now=base + 3))  # file N+1


# ----------------------------------------------------------------------
# Retention
# ----------------------------------------------------------------------
class TestRetention(TempDB):
    def test_old_records_are_purged(self):
        self.seed('a@b.com', 3, ago_seconds=40 * 86400)
        self.seed('a@b.com', 2, ago_seconds=600)
        self.db.cleanup_expired(auth_retention_days=90,
                                history_retention_days=180,
                                outbound_retention_days=30)
        row = self.db.conn.execute(
            "SELECT COUNT(*) AS n FROM outbound_activity").fetchone()
        self.assertEqual(row['n'], 2)

    def test_default_retention_keeps_the_baseline_window(self):
        self.seed('a@b.com', 2, ago_seconds=20 * 86400)
        self.db.cleanup_expired()
        row = self.db.conn.execute(
            "SELECT COUNT(*) AS n FROM outbound_activity").fetchone()
        self.assertEqual(row['n'], 2)


if __name__ == '__main__':
    unittest.main()
