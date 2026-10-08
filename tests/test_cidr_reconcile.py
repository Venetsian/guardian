"""Startup import and reconciliation of subnet blocks (v1.7.19).

On the first start after the upgrade cidr_blocks is empty while production
hosts already hold hundreds of subnet blocks, so the records are rebuilt from
blocked.log*. Every start after that, a backend that can list its CIDR entries
(firewalld) is checked against the table: strays are adopted as permanent,
missing blocks are re-applied.

Stdlib unittest on purpose (the daemon runs on Python 3.6). Run from the repo
root:

    python3 -m unittest discover -s tests -v
"""

import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fakes_cidr import (  # noqa: E402
    DAY, NET_A, NET_B, NET_C, CidrFirewall, DBFixture, FakeTelegram, add_row,
    cidr_config, rows, stamp, statuses, write_log,
)
from modules.blocker import CIDR_REAP_BATCH  # noqa: E402

NOW = int(time.time())


def auto_line(subnet, epoch, duration='30d', count=5):
    return '{} CIDR-BLOCKED subnet={} count={} duration={} IPs=198.51.100.1,198.51.100.2'.format(
        stamp(epoch), subnet, count, duration)


def manual_line(subnet, epoch, duration='perm'):
    return ('{} MANUAL-CIDR-BLOCKED subnet={} duration={} via=firewalld '
            'reason=manual block via test').format(stamp(epoch), subnet, duration)


class Base(unittest.TestCase):
    def setUp(self):
        self.fx = DBFixture()
        self.db = self.fx.db
        self.tg = FakeTelegram()
        self.logdir = tempfile.mkdtemp(prefix='wpg-logs-')

    def tearDown(self):
        self.fx.close()
        shutil.rmtree(self.logdir, ignore_errors=True)

    def make(self, firewall, dry_run=False, **cidr):
        return self.fx.blocker(dry_run=dry_run, firewall=firewall,
                               telegram=self.tg, cidr=cidr_config(**cidr))

    def reconcile(self, firewall, **cidr):
        return self.make(firewall, **cidr).reconcile_cidrs(self.logdir)

    def row(self, subnet):
        found = rows(self.db, subnet)
        self.assertEqual(len(found), 1, '{}: {}'.format(subnet, statuses(self.db, subnet)))
        return found[0]


class TestParsingBlockedLog(Base):
    def test_auto_and_manual_lines_become_import_rows(self):
        write_log(self.logdir, 'blocked.log', [
            auto_line(NET_A, NOW - 10 * DAY),
            manual_line(NET_B, NOW - 5 * DAY, 'perm'),
        ])

        result = self.reconcile(CidrFirewall())

        self.assertEqual(result['imported'], 2)
        a = self.row(NET_A)
        self.assertEqual((a['source'], a['status'], a['duration']), ('import', 'active', '30d'))
        self.assertAlmostEqual(a['blocked_at'], NOW - 10 * DAY, delta=3600)
        self.assertAlmostEqual(a['expires_at'], NOW - 10 * DAY + 30 * DAY, delta=3600)
        b = self.row(NET_B)
        self.assertEqual((b['expires_at'], b['duration']), (0, 'permanent'))
        self.assertEqual(b['backend'], 'fake')

    def test_dry_run_and_unrelated_lines_are_ignored(self):
        write_log(self.logdir, 'blocked.log', [
            '{} DRY-RUN CIDR subnet={} count=5'.format(stamp(NOW - DAY), NET_A),
            '{} DRY-RUN MANUAL-CIDR subnet={} duration=7d'.format(stamp(NOW - DAY), NET_B),
            '{} BLOCKED ip=198.51.100.1 tier=1 duration=24h via=firewalld service=web reason=x'
            .format(stamp(NOW - DAY)),
            '{} CIDR-EXPIRED subnet={} age=3d source=auto'.format(stamp(NOW - DAY), NET_C),
            'CIDR-BLOCKED subnet=203.0.113.0/24 duration=30d',          # no timestamp
            'total garbage',
            '',
        ])
        result = self.reconcile(CidrFirewall())
        self.assertEqual(result['imported'], 0)
        self.assertEqual(rows(self.db), [])

    def test_latest_event_per_subnet_wins_across_files(self):
        write_log(self.logdir, 'blocked.log', [auto_line(NET_A, NOW - 2 * DAY, '7d')])
        write_log(self.logdir, 'blocked.log.1', [auto_line(NET_A, NOW - 20 * DAY, '30d')])
        write_log(self.logdir, 'blocked.log.2.gz', [auto_line(NET_A, NOW - 40 * DAY, '24h')])

        self.reconcile(CidrFirewall())

        row = self.row(NET_A)
        self.assertEqual(row['duration'], '7d')
        self.assertAlmostEqual(row['blocked_at'], NOW - 2 * DAY, delta=3600)

    def test_latest_event_wins_inside_one_file_even_out_of_order(self):
        write_log(self.logdir, 'blocked.log', [
            auto_line(NET_A, NOW - 3 * DAY, '14d'),
            auto_line(NET_A, NOW - 30 * DAY, '30d'),
        ])
        self.reconcile(CidrFirewall())
        self.assertEqual(self.row(NET_A)['duration'], '14d')

    def test_rotated_gzip_logs_are_read(self):
        write_log(self.logdir, 'blocked.log-20260901.gz', [auto_line(NET_B, NOW - 33 * DAY)])
        write_log(self.logdir, 'blocked.log', [auto_line(NET_A, NOW - DAY)])
        result = self.reconcile(CidrFirewall())
        self.assertEqual(result['imported'], 2)
        self.assertEqual(self.row(NET_B)['source'], 'import')

    def test_an_unreadable_file_is_skipped_and_the_rest_imported(self):
        with open(os.path.join(self.logdir, 'blocked.log.3.gz'), 'wb') as handle:
            handle.write(b'this is not gzip data')
        write_log(self.logdir, 'blocked.log', [auto_line(NET_A, NOW - DAY)])

        with self.assertLogs('wp-guardian.blocker', level='WARNING') as cm:
            result = self.reconcile(CidrFirewall())

        self.assertEqual(result['imported'], 1)
        self.assertTrue(any('blocked.log.3.gz' in r.getMessage() for r in cm.records))

    def test_a_failure_part_way_leaves_nothing_behind_so_the_import_can_retry(self):
        write_log(self.logdir, 'blocked.log', [
            auto_line(NET_A, NOW - 3 * DAY), auto_line(NET_B, NOW - 2 * DAY)])
        blocker = self.make(CidrFirewall())
        original = self.db.insert_cidr_block
        calls = []

        def second_one_fails(*args, **kwargs):
            calls.append(args[0])
            if len(calls) == 2:
                raise RuntimeError('disk full')
            return original(*args, **kwargs)
        self.db.insert_cidr_block = second_one_fails

        with self.assertRaises(RuntimeError):
            blocker.reconcile_cidrs(self.logdir)

        self.assertEqual(rows(self.db), [], "all or nothing")
        self.assertTrue(self.db.cidr_table_empty())

        self.db.insert_cidr_block = original
        self.assertEqual(blocker.reconcile_cidrs(self.logdir)['imported'], 2)

    def test_a_missing_log_directory_is_not_an_error(self):
        result = self.make(CidrFirewall()).reconcile_cidrs(
            os.path.join(self.logdir, 'does-not-exist'))
        self.assertEqual(result['imported'], 0)

    def test_missing_duration_falls_back_to_the_configured_one(self):
        write_log(self.logdir, 'blocked.log', [
            '{} CIDR-BLOCKED subnet={} count=5'.format(stamp(NOW - DAY), NET_A)])
        self.reconcile(CidrFirewall(), duration='14d')
        row = self.row(NET_A)
        self.assertEqual(row['duration'], '14d')
        self.assertAlmostEqual(row['expires_at'], NOW - DAY + 14 * DAY, delta=3600)

    def test_unparseable_duration_falls_back_too(self):
        write_log(self.logdir, 'blocked.log', [auto_line(NET_A, NOW - DAY, 'soon')])
        self.reconcile(CidrFirewall(), duration='14d')
        self.assertEqual(self.row(NET_A)['duration'], '14d')

    def test_perm_and_permanent_both_mean_no_expiry(self):
        write_log(self.logdir, 'blocked.log', [
            manual_line(NET_A, NOW - DAY, 'perm'),
            manual_line(NET_B, NOW - DAY, 'permanent'),
        ])
        self.reconcile(CidrFirewall())
        self.assertEqual(self.row(NET_A)['expires_at'], 0)
        self.assertEqual(self.row(NET_B)['expires_at'], 0)

    def test_a_manual_duration_in_days_or_hours(self):
        write_log(self.logdir, 'blocked.log', [
            manual_line(NET_A, NOW - DAY, '7d'), manual_line(NET_B, NOW - DAY, '48h')])
        self.reconcile(CidrFirewall())
        self.assertAlmostEqual(self.row(NET_A)['expires_at'], NOW - DAY + 7 * DAY, delta=3600)
        self.assertAlmostEqual(self.row(NET_B)['expires_at'], NOW - DAY + 2 * DAY, delta=3600)

    def test_bad_subnets_are_skipped_and_host_bits_normalised(self):
        write_log(self.logdir, 'blocked.log', [
            auto_line('not-a-subnet', NOW - DAY),
            auto_line('2001:db8::/32', NOW - DAY),
            auto_line('198.51.100.77/24', NOW - DAY),
        ])
        result = self.reconcile(CidrFirewall())
        self.assertEqual(result['imported'], 1)
        self.assertEqual(self.row(NET_A)['status'], 'active')


class TestStatusByBackendKind(Base):
    """What an imported record becomes depends on what the backend can tell us."""

    def setUp(self):
        Base.setUp(self)
        write_log(self.logdir, 'blocked.log', [
            auto_line(NET_A, NOW - 10 * DAY),                  # due in 20 days
            auto_line(NET_B, NOW - 50 * DAY),                  # 20 days overdue
            manual_line(NET_C, NOW - 90 * DAY, 'perm'),        # permanent
        ])

    def test_a_listing_backend_trusts_the_set(self):
        # firewalld never expires entries: in the set means enforced, even
        # when overdue, and missing means somebody removed it by hand.
        fw = CidrFirewall(lists=True)
        fw.entries.update([NET_A, NET_B])                      # NET_C is not there
        before = int(time.time())

        result = self.reconcile(fw)

        self.assertEqual(self.row(NET_A)['status'], 'active')
        overdue = self.row(NET_B)
        self.assertEqual(overdue['status'], 'active', "the reaper releases it on schedule")
        self.assertLess(overdue['expires_at'], before)
        by_hand = self.row(NET_C)
        self.assertEqual(by_hand['status'], 'removed')
        self.assertGreaterEqual(by_hand['ended_at'], before)
        self.assertEqual((result['active'], result['overdue'], result['removed'],
                          result['expired']), (2, 1, 1, 0))

    def test_a_self_expiring_backend_decides_by_the_clock(self):
        fw = CidrFirewall(self_expiring=True)

        result = self.reconcile(fw)

        self.assertEqual(self.row(NET_A)['status'], 'active')
        self.assertEqual(self.row(NET_C)['status'], 'active', "permanent stays active")
        gone = self.row(NET_B)
        self.assertEqual(gone['status'], 'expired', "the router already dropped it")
        self.assertEqual(gone['ended_at'], gone['expires_at'])
        self.assertEqual((result['active'], result['overdue'], result['expired'],
                          result['removed']), (2, 0, 1, 0))

    def test_an_expired_import_is_a_repeat_offender_candidate(self):
        fw = CidrFirewall(self_expiring=True)
        blocker = self.make(fw)
        blocker.reconcile_cidrs(self.logdir)

        blocker.block('203.0.113.9', 'Tripwire')

        self.assertEqual(len(fw.cidr_blocked), 1)
        self.assertEqual(rows(self.db, NET_B)[-1]['source'], 'reoffend')

    def test_a_removed_import_is_not(self):
        fw = CidrFirewall(lists=True)
        fw.entries.update([NET_A, NET_B])
        blocker = self.make(fw)
        blocker.reconcile_cidrs(self.logdir)

        blocker.block('192.0.2.9', 'Tripwire')                 # NET_C was removed by hand

        self.assertEqual(fw.cidr_blocked, [])

    def test_a_backend_that_cannot_say_keeps_everything_active(self):
        # pfSense: the reaper will call unblock_cidr (idempotent) when due.
        fw = CidrFirewall()
        result = self.reconcile(fw)
        self.assertEqual([self.row(n)['status'] for n in (NET_A, NET_B, NET_C)],
                         ['active', 'active', 'active'])
        self.assertEqual(result['overdue'], 1)

    def test_the_overdue_import_is_then_released_by_the_reaper(self):
        fw = CidrFirewall(lists=True)
        fw.entries.update([NET_A, NET_B, NET_C])
        blocker = self.make(fw)
        blocker.reconcile_cidrs(self.logdir)

        result = blocker.reap_expired_cidrs()

        self.assertEqual(result['expired'], 1)
        self.assertEqual(fw.cidr_unblocked, [NET_B])
        self.assertEqual(self.row(NET_B)['status'], 'expired')
        self.assertEqual(self.row(NET_C)['status'], 'active')


class TestSummaryAlert(Base):
    def setUp(self):
        Base.setUp(self)
        write_log(self.logdir, 'blocked.log', [
            auto_line(NET_A, NOW - 10 * DAY),
            auto_line(NET_B, NOW - 50 * DAY),
            manual_line(NET_C, NOW - 90 * DAY, 'perm'),
        ])

    def test_one_summary_on_the_first_run_none_on_the_second(self):
        fw = CidrFirewall(lists=True)
        fw.entries.update([NET_A, NET_B, '192.0.2.128/25'])

        first = self.make(fw)
        first.reconcile_cidrs(self.logdir)

        self.assertEqual(len(self.tg.sent), 1)
        message, priority = self.tg.sent[0]
        self.assertEqual(priority, 'HIGH')
        self.assertIn('Imported 3 subnet block(s)', message)
        self.assertIn('2 active (of which 1 already past expiry, released {} per hour)'
                      .format(CIDR_REAP_BATCH), message)
        self.assertIn('0 expired (repeat-offender watch)', message)
        self.assertIn('1 removed by hand', message)
        self.assertIn('1 entries of unknown origin', message)
        self.assertIn('adopted as permanent', message)

        # The next start: new Blocker, same database.
        second = self.make(fw)
        result = second.reconcile_cidrs(self.logdir)

        self.assertEqual(len(self.tg.sent), 1, "no second summary")
        self.assertFalse(result['import_ran'])
        self.assertEqual(len(rows(self.db)), 4, "nothing imported twice")

    def test_no_summary_when_there_is_nothing_to_report(self):
        os.remove(os.path.join(self.logdir, 'blocked.log'))
        result = self.reconcile(CidrFirewall(lists=True))      # no logs, empty set
        self.assertEqual(result['imported'] + result['adopted'], 0)
        self.assertEqual(self.tg.sent, [])

    def test_a_failing_telegram_does_not_break_the_import(self):
        class Boom(FakeTelegram):
            def send(self, message, priority='INFO'):
                raise RuntimeError('telegram down')
        self.tg = Boom()
        with self.assertLogs('wp-guardian.blocker', level='ERROR'):
            result = self.reconcile(CidrFirewall())
        self.assertEqual(result['imported'], 3)

    def test_the_log_carries_the_summary_too(self):
        with self.assertLogs('wp-guardian.blocker', level='INFO') as cm:
            self.reconcile(CidrFirewall())
        self.assertTrue(any('CIDR import summary' in r.getMessage() for r in cm.records))


class TestNeverRunsWhenItShould_nt(Base):
    def setUp(self):
        Base.setUp(self)
        write_log(self.logdir, 'blocked.log', [auto_line(NET_A, NOW - DAY)])

    def test_dry_run(self):
        fw = CidrFirewall(lists=True)
        result = self.make(fw, dry_run=True).reconcile_cidrs(self.logdir)
        self.assertFalse(result['import_ran'])
        self.assertEqual(rows(self.db), [])
        self.assertEqual(self.tg.sent, [])

    def test_no_backend(self):
        result = self.make(None).reconcile_cidrs(self.logdir)
        self.assertFalse(result['import_ran'])
        self.assertEqual(rows(self.db), [])

    def test_a_backend_without_cidr_support(self):
        fw = CidrFirewall()
        fw.supports_cidr = False
        result = self.make(fw).reconcile_cidrs(self.logdir)
        self.assertFalse(result['import_ran'])
        self.assertEqual(rows(self.db), [])

    def test_a_listing_failure_does_nothing_and_is_retried(self):
        fw = CidrFirewall(lists=True)
        fw.list_raises = RuntimeError('firewall-cmd could not list wp_guardian_cidr')
        blocker = self.make(fw)

        with self.assertLogs('wp-guardian.blocker', level='WARNING'):
            result = blocker.reconcile_cidrs(self.logdir)

        self.assertFalse(result['import_ran'])
        self.assertEqual(rows(self.db), [], "a failed listing must never read as 'empty set'")
        self.assertEqual(self.tg.sent, [])

        fw.list_raises = None
        fw.entries.add(NET_A)
        result = blocker.reconcile_cidrs(self.logdir)
        self.assertTrue(result['import_ran'])
        self.assertEqual(self.row(NET_A)['status'], 'active')

    def test_the_import_runs_only_while_the_table_is_empty(self):
        add_row(self.db, NET_B, status='removed', ended_days_ago=1)
        result = self.reconcile(CidrFirewall())
        self.assertFalse(result['import_ran'])
        self.assertEqual(statuses(self.db, NET_A), [])


class TestEntryReconciliation(Base):
    """Every start, on a backend that can list its CIDR entries."""

    def test_an_entry_nobody_has_a_record_of_is_adopted_as_permanent(self):
        fw = CidrFirewall(lists=True)
        fw.entries.add(NET_A)
        add_row(self.db, NET_B)                      # table not empty: no import

        with self.assertLogs('wp-guardian.blocker', level='WARNING') as cm:
            result = self.reconcile(fw)

        self.assertEqual(result['adopted'], 1)
        row = self.row(NET_A)
        self.assertEqual((row['source'], row['status'], row['expires_at']),
                         ('adopted', 'active', 0))
        self.assertTrue(any('ADOPTED' in r.getMessage() and NET_A in r.getMessage()
                            for r in cm.records))
        self.assertEqual(self.tg.sent, [], "adoption after the first run is quiet")

    def test_an_entry_that_is_not_a_network_is_ignored_not_adopted(self):
        fw = CidrFirewall(lists=True)
        fw.entries.update([NET_A, 'not-a-network', '2001:db8::/32'])
        add_row(self.db, NET_B)
        with self.assertLogs('wp-guardian.blocker', level='WARNING'):
            result = self.reconcile(fw)
        self.assertEqual(result['adopted'], 1)
        self.assertEqual(statuses(self.db, NET_A), ['active'])
        self.assertEqual(statuses(self.db, 'not-a-network'), [])

    def test_an_adopted_entry_is_never_auto_released(self):
        fw = CidrFirewall(lists=True)
        fw.entries.add(NET_A)
        add_row(self.db, NET_B)
        blocker = self.make(fw)
        blocker.reconcile_cidrs(self.logdir)

        result = blocker.reap_expired_cidrs()

        self.assertEqual(result['expired'], 0)
        self.assertIn(NET_A, fw.entries)

    def test_a_removed_record_with_the_entry_back_in_the_set_is_adopted_again(self):
        fw = CidrFirewall(lists=True)
        fw.entries.add(NET_A)
        add_row(self.db, NET_A, status='removed', ended_days_ago=3)
        self.reconcile(fw)
        self.assertEqual(statuses(self.db, NET_A), ['removed', 'active'])

    def test_an_expired_record_back_in_the_set_is_released_again_not_adopted(self):
        """firewalld removed the runtime entry, failed on the permanent one, and
        a reload restored it. Adopting it would make an expired block permanent."""
        fw = CidrFirewall(lists=True)
        fw.entries.add(NET_A)
        add_row(self.db, NET_A, status='expired', ended_days_ago=2)

        with self.assertLogs('wp-guardian.blocker', level='WARNING') as cm:
            result = self.reconcile(fw)

        self.assertEqual((result['rereleased'], result['adopted']), (1, 0))
        self.assertNotIn(NET_A, fw.entries)
        self.assertEqual(statuses(self.db, NET_A), ['expired'],
                         "still a repeat-offender candidate, no new row")
        self.assertTrue(any('RE-RELEASED' in r.getMessage() for r in cm.records))

    def test_a_record_missing_from_the_set_is_reapplied_for_its_remaining_time(self):
        fw = CidrFirewall(lists=True)
        add_row(self.db, NET_A, expires_in_days=10)
        add_row(self.db, NET_B, permanent=True)
        blocker = self.make(fw)

        with self.assertLogs('wp-guardian.blocker', level='WARNING'):
            result = blocker.reconcile_cidrs(self.logdir)

        self.assertEqual(result['reapplied'], 2)
        durations = dict((c[0], c[3]) for c in fw.cidr_blocked)
        self.assertEqual(durations[NET_B], 'permanent')
        seconds = int(durations[NET_A].rstrip('s'))
        self.assertAlmostEqual(seconds, 10 * DAY, delta=120)
        self.assertEqual(fw.entries, {NET_A, NET_B})
        self.assertEqual(statuses(self.db, NET_A), ['active'], "same record, no new row")

    def test_a_failed_reapply_leaves_it_active_for_the_next_start(self):
        fw = CidrFirewall(lists=True)
        fw.block_cidr_ok = False
        add_row(self.db, NET_A, expires_in_days=10)
        blocker = self.make(fw)

        with self.assertLogs('wp-guardian.blocker', level='ERROR'):
            result = blocker.reconcile_cidrs(self.logdir)

        self.assertEqual((result['reapplied'], result['reapply_failed']), (0, 1))
        self.assertEqual(statuses(self.db, NET_A), ['active'])

        fw.block_cidr_ok = True
        self.assertEqual(blocker.reconcile_cidrs(self.logdir)['reapplied'], 1)

    def test_a_reapply_exception_is_a_failure_not_a_crash(self):
        fw = CidrFirewall(lists=True)
        add_row(self.db, NET_A, expires_in_days=10)

        def boom(*args, **kwargs):
            raise RuntimeError('firewall-cmd exploded')
        fw.block_cidr = boom
        with self.assertLogs('wp-guardian.blocker', level='ERROR'):
            result = self.reconcile(fw)
        self.assertEqual(result['reapply_failed'], 1)

    def test_an_overdue_record_is_not_reapplied_only_to_be_released(self):
        fw = CidrFirewall(lists=True)
        add_row(self.db, NET_A, expires_in_days=-3)
        result = self.reconcile(fw)
        self.assertEqual(fw.cidr_blocked, [])
        self.assertEqual(result['skipped'], 1)

    def test_agreeing_state_changes_nothing(self):
        fw = CidrFirewall(lists=True)
        fw.entries.add(NET_A)
        add_row(self.db, NET_A)
        result = self.reconcile(fw)
        self.assertEqual((result['adopted'], result['reapplied']), (0, 0))
        self.assertEqual(fw.cidr_blocked, [])
        self.assertEqual(len(rows(self.db)), 1)

    def test_a_backend_that_cannot_list_is_left_alone(self):
        fw = CidrFirewall(self_expiring=True)
        add_row(self.db, NET_A)
        result = self.reconcile(fw)
        self.assertEqual((result['adopted'], result['reapplied']), (0, 0))
        self.assertEqual(fw.cidr_blocked, [])


if __name__ == '__main__':
    unittest.main()
