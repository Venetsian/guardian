"""Subnet (CIDR) block lifecycle (v1.7.19): record, expire, re-block, lift.

Background. firewalld's block_cidr() ignored its duration and nothing ever
removed a subnet: production hosts held 70, 726 and 29 /24s, ~800 of them past
their logged "30d", the oldest ~174 days. The blocker remembered subnets in an
in-memory set, which was lost on restart and, on backends that expire entries
themselves, kept suppressing re-aggregation after the router had already let
the entry go. Every subnet block is now a cidr_blocks row and an hourly reaper
ends the ones that fall due.

Stdlib unittest on purpose (the daemon runs on Python 3.6). Run from the repo
root:

    python3 -m unittest discover -s tests -v
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fakes_cidr import (  # noqa: E402
    DAY, NET_A, NET_B, CidrFirewall, DBFixture, FakeDigest, FakeRouter,
    FakeTelegram, add_row, block_n, cidr_config, rows, statuses,
)
from modules.blocker import (  # noqa: E402
    CIDR_REAP_BATCH, UNAVAILABLE_UNBLOCK_MSG, format_cidr_expiry,
)

PREFIX_A = '198.51.100'


def blocked_log_lines(cm):
    return [r.getMessage() for r in cm.records]


class Base(unittest.TestCase):
    def setUp(self):
        self.fx = DBFixture()
        self.db = self.fx.db
        self.tg = FakeTelegram()

    def tearDown(self):
        self.fx.close()

    def make(self, firewall=None, dry_run=False, **cidr):
        blocker = self.fx.blocker(
            dry_run=dry_run, firewall=firewall, telegram=self.tg,
            cidr=cidr_config(**cidr))
        return blocker


class TestAggregationRecordsTheBlock(Base):
    def test_threshold_blocks_the_range_and_records_an_auto_row(self):
        fw = CidrFirewall()
        blocker = self.make(fw)
        before = int(time.time())

        block_n(blocker, PREFIX_A, 5)

        self.assertEqual([c[0] for c in fw.cidr_blocked], [NET_A])
        self.assertEqual(fw.cidr_blocked[0][3], '30d')
        row, = rows(self.db, NET_A)
        self.assertEqual(row['source'], 'auto')
        self.assertEqual(row['status'], 'active')
        self.assertEqual(row['duration'], '30d')
        self.assertAlmostEqual(row['expires_at'], before + 30 * DAY, delta=60)
        self.assertEqual(row['backend'], 'fake')
        self.assertIn('5 blocked IPs', row['reason'])

    def test_below_the_threshold_nothing_happens(self):
        fw = CidrFirewall()
        blocker = self.make(fw)
        block_n(blocker, PREFIX_A, 4)
        self.assertEqual(fw.cidr_blocked, [])
        self.assertEqual(rows(self.db), [])
        self.assertEqual(fw.is_cidr_calls, 0, "no backend round-trip below the threshold")

    def test_blocked_log_line_keeps_its_format_and_gains_the_source_at_the_end(self):
        blocker = self.make(CidrFirewall())
        with self.assertLogs('wp-guardian.blocks', level='INFO') as cm:
            block_n(blocker, PREFIX_A, 5)
        line, = [m for m in blocked_log_lines(cm) if m.startswith('CIDR-BLOCKED')]
        self.assertTrue(line.startswith(
            'CIDR-BLOCKED subnet=198.51.100.0/24 count=5 duration=30d IPs='), line)
        self.assertTrue(line.endswith(' source=auto'), line)

    def test_permanent_duration_is_recorded_as_expires_at_zero(self):
        fw = CidrFirewall()
        blocker = self.make(fw, duration='permanent')
        block_n(blocker, PREFIX_A, 5)
        row, = rows(self.db, NET_A)
        self.assertEqual(row['expires_at'], 0)
        self.assertEqual(fw.cidr_blocked[0][3], 'permanent')

    def test_the_original_cidr_alert_is_sent_for_an_auto_block(self):
        blocker = self.make(CidrFirewall())
        block_n(blocker, PREFIX_A, 5)
        msg, priority = self.tg.sent[-1]
        self.assertIn('CIDR /24 Block', msg)
        self.assertIn(NET_A, msg)
        self.assertEqual(priority, 'HIGH')

    def test_a_failed_firewall_call_records_nothing(self):
        fw = CidrFirewall()
        fw.block_cidr_ok = False
        blocker = self.make(fw)
        with self.assertLogs('wp-guardian.blocker', level='WARNING'):
            block_n(blocker, PREFIX_A, 5)
        self.assertEqual(rows(self.db), [])
        self.assertFalse(any('CIDR' in m for m, _ in self.tg.sent))

    def test_a_recording_failure_does_not_lose_the_alert(self):
        fw = CidrFirewall()
        blocker = self.make(fw)
        block_n(blocker, PREFIX_A, 4)

        def boom(*args, **kwargs):
            raise RuntimeError('database is locked')
        self.db.insert_cidr_block = boom
        with self.assertLogs('wp-guardian.blocker', level='ERROR'):
            block_n(blocker, PREFIX_A, 1, start=5)

        self.assertEqual(len(fw.cidr_blocked), 1, "it IS blocked on the firewall")
        self.assertTrue(any('CIDR /24 Block' in m for m, _ in self.tg.sent))

    def test_aggregation_off_blocks_no_subnet_at_all(self):
        fw = CidrFirewall()
        blocker = self.make(fw, enabled='false')
        block_n(blocker, PREFIX_A, 8)
        # Reoffend trigger is part of aggregation: still nothing.
        add_row(self.db, '203.0.113.0/24', status='expired', ended_days_ago=1)
        blocker.block('203.0.113.9', 'Tripwire')
        self.assertEqual(fw.cidr_blocked, [])

    def test_ipv6_and_junk_are_ignored(self):
        fw = CidrFirewall()
        blocker = self.make(fw)
        blocker._check_cidr_aggregation('2001:db8::1', 'web')
        blocker._check_cidr_aggregation('not-an-ip', 'web')
        self.assertEqual(fw.cidr_blocked, [])


class TestAggregationSkipsWhatIsAlreadyBlocked(Base):
    def test_an_active_record_means_no_backend_call_at_all(self):
        fw = CidrFirewall()
        add_row(self.db, NET_A)
        blocker = self.make(fw)

        block_n(blocker, PREFIX_A, 6)

        self.assertEqual(fw.cidr_blocked, [])
        self.assertEqual(fw.is_cidr_calls, 0)
        self.assertEqual(statuses(self.db, NET_A), ['active'])

    def test_a_wider_manual_block_also_covers_the_range(self):
        fw = CidrFirewall()
        add_row(self.db, '198.51.100.0/22', source='manual', permanent=True)
        blocker = self.make(fw)
        block_n(blocker, PREFIX_A, 6)
        self.assertEqual(fw.cidr_blocked, [])
        self.assertEqual(fw.is_cidr_calls, 0)

    def test_the_record_survives_a_restart(self):
        # The old in-memory set did not: a new Blocker has no memory at all.
        fw = CidrFirewall()
        first = self.make(fw)
        block_n(first, PREFIX_A, 5)
        self.assertEqual(len(fw.cidr_blocked), 1)

        second = self.make(fw)          # "restart"
        block_n(second, PREFIX_A, 3, start=6)

        self.assertEqual(len(fw.cidr_blocked), 1)
        self.assertEqual(fw.is_cidr_calls, 1, "only the first block ever asked the firewall")

    def test_a_pre_upgrade_entry_with_no_record_is_adopted_with_a_full_duration(self):
        fw = CidrFirewall(self_expiring=True)
        fw.entries.add(NET_A)
        blocker = self.make(fw)
        before = int(time.time())

        block_n(blocker, PREFIX_A, 5)

        self.assertEqual(fw.cidr_blocked, [], "it is already on the firewall")
        row, = rows(self.db, NET_A)
        self.assertEqual(row['source'], 'adopted')
        self.assertEqual(row['status'], 'active')
        self.assertAlmostEqual(row['expires_at'], before + 30 * DAY, delta=60)

    def test_an_overdue_record_with_the_entry_still_present_is_left_for_the_reaper(self):
        fw = CidrFirewall()
        fw.entries.add(NET_A)
        add_row(self.db, NET_A, expires_in_days=-2)
        blocker = self.make(fw, reblock_repeat_offenders='false')

        block_n(blocker, PREFIX_A, 5)

        self.assertEqual(fw.cidr_blocked, [])
        self.assertEqual(statuses(self.db, NET_A), ['active'], "no duplicate row")


class TestExpiryOnASelfExpiringBackend(Base):
    """The old _blocked_subnets cache kept suppressing re-aggregation after the
    router had expired the entry, until the daemon restarted."""

    def expire_on_router(self, fw):
        fw.entries.discard(NET_A)
        self.db.conn.execute(
            "UPDATE cidr_blocks SET expires_at = ? WHERE subnet = ? AND status = 'active'",
            (int(time.time()) - 3600, NET_A))
        self.db.conn.commit()

    def test_threshold_aggregation_works_again_after_the_entry_expired(self):
        fw = CidrFirewall(self_expiring=True)
        blocker = self.make(fw, reblock_repeat_offenders='false')
        block_n(blocker, PREFIX_A, 5)
        self.assertEqual(len(fw.cidr_blocked), 1)
        self.expire_on_router(fw)
        blocker.reap_expired_cidrs()
        self.assertEqual(statuses(self.db, NET_A), ['expired'])

        block_n(blocker, PREFIX_A, 1, start=6)

        self.assertEqual(len(fw.cidr_blocked), 2, "same blocker, no restart")
        self.assertEqual(statuses(self.db, NET_A), ['expired', 'active'])

    def test_even_without_the_reaper_an_expired_entry_is_blocked_again(self):
        fw = CidrFirewall(self_expiring=True)
        blocker = self.make(fw, reblock_repeat_offenders='false')
        block_n(blocker, PREFIX_A, 5)
        self.expire_on_router(fw)

        block_n(blocker, PREFIX_A, 1, start=6)

        self.assertEqual(len(fw.cidr_blocked), 2)
        self.assertEqual(statuses(self.db, NET_A), ['expired', 'active'],
                         "the stale overdue row is closed as expired, not removed")


class TestRepeatOffender(Base):
    def expired_a(self, **kwargs):
        defaults = dict(status='expired', age_days=40, ended_days_ago=10)
        defaults.update(kwargs)
        return add_row(self.db, NET_A, **defaults)

    def test_one_new_blocked_ip_reblocks_an_expired_range(self):
        fw = CidrFirewall()
        self.expired_a()
        blocker = self.make(fw)

        blocker.block('198.51.100.9', 'Tripwire')

        self.assertEqual([c[0] for c in fw.cidr_blocked], [NET_A])
        old, new = rows(self.db, NET_A)
        self.assertEqual((old['status'], new['status'], new['source']),
                         ('expired', 'active', 'reoffend'))
        self.assertIn('Repeat offender', new['reason'])
        self.assertIn('198.51.100.9 blocked again', new['reason'])
        self.assertIn(NET_A, new['reason'])

    def test_the_log_line_carries_the_reoffend_source(self):
        self.expired_a()
        blocker = self.make(CidrFirewall())
        with self.assertLogs('wp-guardian.blocks', level='INFO') as cm:
            blocker.block('198.51.100.9', 'Tripwire')
        line, = [m for m in blocked_log_lines(cm) if m.startswith('CIDR-BLOCKED')]
        self.assertTrue(line.startswith('CIDR-BLOCKED subnet=198.51.100.0/24 count=1 '))
        self.assertTrue(line.endswith(' source=reoffend'), line)

    def test_alert_goes_through_the_router_under_cidr_reoffend(self):
        self.expired_a()
        router = FakeRouter()
        blocker = self.make(CidrFirewall())
        blocker.set_router(router)

        blocker.block('198.51.100.9', 'Tripwire')

        self.assertIn('cidr_reoffend', [c[0] for c in router.calls])
        self.assertNotIn('cidr', [c[0] for c in router.calls])
        msg, priority = self.tg.sent[-1]
        self.assertIn('re-instated: repeat offender', msg)
        self.assertIn(NET_A, msg)
        self.assertIn('198.51.100.9', msg)
        self.assertEqual(priority, 'HIGH')
        self.assertIn(time.strftime('%Y-%m-%d', time.localtime(time.time() - 40 * DAY)), msg,
                      "the previous block date is in the text")

    def test_digest_level_queues_instead_of_sending(self):
        self.expired_a()
        digest = FakeDigest()
        blocker = self.make(CidrFirewall())
        blocker.set_router(FakeRouter({'cidr_reoffend': 'digest'}))
        blocker.set_digest_buffer(digest)

        blocker.block('198.51.100.9', 'Tripwire')

        self.assertEqual(len(digest.queued), 1)
        self.assertEqual(digest.queued[0][0], 'cidr_reoffend')
        self.assertFalse(any('re-instated' in m for m, _ in self.tg.sent))

    def test_silent_level_sends_nothing_but_still_blocks(self):
        self.expired_a()
        fw = CidrFirewall()
        blocker = self.make(fw)
        blocker.set_router(FakeRouter({'cidr_reoffend': 'silent'}))

        blocker.block('198.51.100.9', 'Tripwire')

        self.assertEqual(len(fw.cidr_blocked), 1)
        self.assertEqual([m for m, _ in self.tg.sent if 'CIDR' in m], [])

    def test_a_removed_record_does_not_trigger(self):
        add_row(self.db, NET_A, status='removed', ended_days_ago=3)
        fw = CidrFirewall()
        blocker = self.make(fw)
        blocker.block('198.51.100.9', 'Tripwire')
        self.assertEqual(fw.cidr_blocked, [])

    def test_an_unblock_cidr_clears_the_memory(self):
        self.expired_a()
        fw = CidrFirewall()
        blocker = self.make(fw)

        ok, _ = blocker.unblock_cidr_manual(NET_A)
        blocker.block('198.51.100.9', 'Tripwire')

        self.assertTrue(ok)
        fw.cidr_blocked = []
        blocker.block('198.51.100.10', 'Tripwire')
        self.assertEqual(fw.cidr_blocked, [])

    def test_disabled_by_config(self):
        self.expired_a()
        fw = CidrFirewall()
        blocker = self.make(fw, reblock_repeat_offenders='false')
        blocker.block('198.51.100.9', 'Tripwire')
        self.assertEqual(fw.cidr_blocked, [])

    def test_disabled_repeat_offender_still_allows_the_threshold(self):
        self.expired_a()
        fw = CidrFirewall()
        blocker = self.make(fw, reblock_repeat_offenders='false')
        block_n(blocker, PREFIX_A, 5)
        self.assertEqual(len(fw.cidr_blocked), 1)
        self.assertEqual(rows(self.db, NET_A)[-1]['source'], 'auto')

    def test_enabled_by_default(self):
        self.expired_a()
        fw = CidrFirewall()
        blocker = self.fx.blocker(firewall=fw, telegram=self.tg,
                                  cidr={'enabled': 'true'})
        self.assertTrue(blocker.cidr_reblock_repeat)
        blocker.block('198.51.100.9', 'Tripwire')
        self.assertEqual(len(fw.cidr_blocked), 1)

    def test_a_live_block_is_not_reblocked(self):
        self.expired_a()
        add_row(self.db, NET_A)
        fw = CidrFirewall()
        blocker = self.make(fw)
        blocker.block('198.51.100.9', 'Tripwire')
        self.assertEqual(fw.cidr_blocked, [])

    def test_a_second_ip_after_the_reblock_does_nothing_more(self):
        self.expired_a()
        fw = CidrFirewall()
        blocker = self.make(fw)
        blocker.block('198.51.100.9', 'Tripwire')
        blocker.block('198.51.100.10', 'Tripwire')
        self.assertEqual(len(fw.cidr_blocked), 1)


class TestSafetyChecks(Base):
    def test_a_whitelisted_ip_in_the_range_refuses_the_block(self):
        self.db.add_whitelist('198.51.100.200', 'permanent', None, 'office', 'test')
        fw = CidrFirewall()
        blocker = self.make(fw)
        with self.assertLogs('wp-guardian.blocker', level='WARNING') as cm:
            block_n(blocker, PREFIX_A, 5)
        self.assertEqual(fw.cidr_blocked, [])
        self.assertEqual(rows(self.db), [])
        self.assertTrue(any('whitelisted' in m for m in blocked_log_lines(cm)))

    def test_the_refusal_is_cached_so_the_whitelist_is_not_rescanned(self):
        self.db.add_whitelist('198.51.100.200', 'permanent', None, 'office', 'test')
        blocker = self.make(CidrFirewall())
        scans = []
        original = self.fx.whitelist.contains_whitelisted_ip
        self.fx.whitelist.contains_whitelisted_ip = \
            lambda prefix: (scans.append(prefix), original(prefix))[1]

        with self.assertLogs('wp-guardian.blocker', level='WARNING'):
            block_n(blocker, PREFIX_A, 8)

        self.assertEqual(len(scans), 1, "blocks 6-8 hit the negative cache")

    def test_the_cache_expires(self):
        self.db.add_whitelist('198.51.100.200', 'permanent', None, 'office', 'test')
        fw = CidrFirewall()
        blocker = self.make(fw)
        with self.assertLogs('wp-guardian.blocker', level='WARNING'):
            block_n(blocker, PREFIX_A, 5)
        self.db.remove_whitelist('198.51.100.200')

        # Inside the hour the old decision stands.
        block_n(blocker, PREFIX_A, 1, start=6)
        self.assertEqual(fw.cidr_blocked, [])
        # After it, the whitelist is read again and the range is blocked.
        blocker._cidr_skip[NET_A] = time.time() - 1
        block_n(blocker, PREFIX_A, 1, start=7)
        self.assertEqual(len(fw.cidr_blocked), 1)

    def test_a_friendly_subnet_refuses_the_block(self):
        fw = CidrFirewall(friendly=[NET_A])
        blocker = self.make(fw)
        with self.assertLogs('wp-guardian.blocker', level='WARNING') as cm:
            block_n(blocker, PREFIX_A, 5)
        self.assertEqual(fw.cidr_blocked, [])
        self.assertTrue(any('friendly' in m for m in blocked_log_lines(cm)))

    def test_the_repeat_offender_path_honours_the_same_safety(self):
        add_row(self.db, NET_A, status='expired', ended_days_ago=3)
        self.db.add_whitelist('198.51.100.200', 'permanent', None, 'office', 'test')
        fw = CidrFirewall()
        blocker = self.make(fw)
        with self.assertLogs('wp-guardian.blocker', level='WARNING'):
            blocker.block('198.51.100.9', 'Tripwire')
        self.assertEqual(fw.cidr_blocked, [])


class TestDryRunAggregation(Base):
    def prime(self, blocker):
        """Real blocks first (as if before a --dry-run restart), then a dry blocker."""
        for i in range(1, 6):
            self.db.track_ip('198.51.100.{}'.format(i))
            self.db.record_block('198.51.100.{}'.format(i), 1, 'r', 'web', 'fake', '24h')

    def test_dry_run_logs_once_and_changes_nothing(self):
        fw = CidrFirewall()
        blocker = self.make(fw, dry_run=True)
        self.prime(blocker)

        with self.assertLogs('wp-guardian.blocker', level='INFO') as cm:
            for _ in range(3):
                blocker._check_cidr_aggregation('198.51.100.5', 'web')

        self.assertEqual(rows(self.db), [])
        self.assertEqual(fw.cidr_blocked, [])
        would = [m for m in blocked_log_lines(cm) if 'Would CIDR block' in m]
        self.assertEqual(len(would), 1, "deduped in memory")
        self.assertEqual(self.tg.sent, [])

    def test_dry_run_does_not_adopt_an_existing_entry(self):
        fw = CidrFirewall()
        fw.entries.add(NET_A)
        blocker = self.make(fw, dry_run=True)
        self.prime(blocker)
        blocker._check_cidr_aggregation('198.51.100.5', 'web')
        self.assertEqual(rows(self.db), [])


class TestReaperOnABackendThatCannotExpireEntries(Base):
    """firewalld / pfSense: nothing else will ever remove the entry."""

    def test_overdue_blocks_are_unblocked_and_marked_expired(self):
        fw = CidrFirewall()
        fw.entries.update([NET_A, NET_B])
        add_row(self.db, NET_A, age_days=40, expires_in_days=-10)
        add_row(self.db, NET_B, age_days=35, expires_in_days=-5)
        blocker = self.make(fw, enabled='false')       # must run with aggregation off
        before = int(time.time())

        with self.assertLogs('wp-guardian.blocks', level='INFO') as cm:
            result = blocker.reap_expired_cidrs()

        self.assertEqual(result, {'expired': 2, 'failed': 0, 'remaining': 0})
        self.assertEqual(sorted(fw.cidr_unblocked), [NET_A, NET_B])
        self.assertEqual(fw.entries, set())
        for net in (NET_A, NET_B):
            row, = rows(self.db, net)
            self.assertEqual(row['status'], 'expired')
            self.assertGreaterEqual(row['ended_at'], before,
                                    "enforced until the sweep, so it ended now")
        lines = blocked_log_lines(cm)
        self.assertIn('CIDR-EXPIRED subnet=198.51.100.0/24 age=40d source=auto', lines)
        self.assertIn('CIDR-EXPIRED subnet=203.0.113.0/24 age=35d source=auto', lines)

    def test_no_telegram_per_subnet(self):
        fw = CidrFirewall()
        add_row(self.db, NET_A, expires_in_days=-1)
        self.make(fw).reap_expired_cidrs()
        self.assertEqual(self.tg.sent, [])

    def test_a_backend_failure_leaves_the_block_active_for_the_next_sweep(self):
        fw = CidrFirewall()
        fw.unblock_cidr_ok = False
        add_row(self.db, NET_A, expires_in_days=-1)
        blocker = self.make(fw)

        result = blocker.reap_expired_cidrs()

        self.assertEqual(result, {'expired': 0, 'failed': 1, 'remaining': 1})
        self.assertEqual(statuses(self.db, NET_A), ['active'])

        fw.unblock_cidr_ok = True
        self.assertEqual(blocker.reap_expired_cidrs()['expired'], 1)
        self.assertEqual(statuses(self.db, NET_A), ['expired'])

    def test_a_backend_exception_is_a_failure_not_a_crash(self):
        fw = CidrFirewall()
        fw.unblock_cidr_raises = RuntimeError('ssh down')
        add_row(self.db, NET_A, expires_in_days=-1)
        with self.assertLogs('wp-guardian.blocker', level='ERROR'):
            result = self.make(fw).reap_expired_cidrs()
        self.assertEqual((result['expired'], result['failed']), (0, 1))
        self.assertEqual(statuses(self.db, NET_A), ['active'])

    def test_one_failure_does_not_stop_the_rest(self):
        fw = CidrFirewall()
        original = fw.unblock_cidr
        fw.unblock_cidr = lambda s: False if s == NET_A else original(s)
        add_row(self.db, NET_A, expires_in_days=-9)
        add_row(self.db, NET_B, expires_in_days=-1)
        result = self.make(fw).reap_expired_cidrs()
        self.assertEqual((result['expired'], result['failed']), (1, 1))
        self.assertEqual(statuses(self.db, NET_B), ['expired'])

    def test_the_default_batch_is_fifty_oldest_first(self):
        self.assertEqual(CIDR_REAP_BATCH, 50)
        fw = CidrFirewall()
        for i in range(55):
            add_row(self.db, '198.51.100.{}/32'.format(i), expires_in_days=-(i + 1))
        blocker = self.make(fw)

        result = blocker.reap_expired_cidrs()

        self.assertEqual(result, {'expired': 50, 'failed': 0, 'remaining': 5})
        self.assertEqual(len(fw.cidr_unblocked), 50)
        self.assertEqual(fw.cidr_unblocked[0], '198.51.100.54/32', "longest overdue first")
        self.assertEqual(self.db.cidr_counts()['overdue'], 5)

        self.assertEqual(blocker.reap_expired_cidrs()['expired'], 5)

    def test_an_explicit_limit(self):
        fw = CidrFirewall()
        for i in range(7):
            add_row(self.db, '198.51.100.{}/32'.format(i), expires_in_days=-1)
        result = self.make(fw).reap_expired_cidrs(limit=3)
        self.assertEqual(result, {'expired': 3, 'failed': 0, 'remaining': 4})
        self.assertEqual(self.make(fw).reap_expired_cidrs(limit=0)['expired'], 0)

    def test_permanent_and_future_blocks_are_never_touched(self):
        fw = CidrFirewall()
        add_row(self.db, NET_A, permanent=True, age_days=400)
        add_row(self.db, NET_B, expires_in_days=5)
        result = self.make(fw).reap_expired_cidrs()
        self.assertEqual(result, {'expired': 0, 'failed': 0, 'remaining': 0})
        self.assertEqual(fw.cidr_unblocked, [])

    def test_global_dry_run_unblocks_nothing(self):
        fw = CidrFirewall()
        fw.entries.add(NET_A)
        add_row(self.db, NET_A, expires_in_days=-1)
        with self.assertLogs('wp-guardian.blocker', level='INFO') as cm:
            result = self.make(fw, dry_run=True).reap_expired_cidrs()
        self.assertEqual(result['expired'], 1, "counted as would-expire")
        self.assertEqual(fw.cidr_unblocked, [])
        self.assertEqual(statuses(self.db, NET_A), ['active'])
        self.assertTrue(any('[DRY-RUN] would expire' in m for m in blocked_log_lines(cm)))

    def test_dry_run_argument_unblocks_nothing(self):
        fw = CidrFirewall()
        add_row(self.db, NET_A, expires_in_days=-1)
        self.make(fw).reap_expired_cidrs(dry_run=True)
        self.assertEqual(fw.cidr_unblocked, [])
        self.assertEqual(statuses(self.db, NET_A), ['active'])

    def test_no_backend_does_nothing(self):
        add_row(self.db, NET_A, expires_in_days=-1)
        result = self.make(None).reap_expired_cidrs()
        self.assertEqual(result, {'expired': 0, 'failed': 0, 'remaining': 0})
        self.assertEqual(statuses(self.db, NET_A), ['active'])

    def test_a_row_lifted_meanwhile_is_not_unblocked_again(self):
        # An operator re-applied the block (old row closed, new row live)
        # between the candidate query and the release: the reaper must not
        # drop the block that was just renewed.
        fw = CidrFirewall()
        stale = add_row(self.db, NET_A, expires_in_days=-1)
        blocker = self.make(fw)
        original = self.db.get_overdue_cidr_blocks

        def lift_then_report(now, limit):
            found = original(now, limit)
            self.db.end_cidr_block(stale, 'removed')
            return found
        self.db.get_overdue_cidr_blocks = lift_then_report

        result = blocker.reap_expired_cidrs()

        self.assertEqual(fw.cidr_unblocked, [])
        self.assertEqual(result['expired'], 0)
        self.assertEqual(statuses(self.db, NET_A), ['removed'])


class TestReaperOnASelfExpiringBackend(Base):
    def test_the_record_is_closed_without_calling_the_backend(self):
        fw = CidrFirewall(self_expiring=True)
        add_row(self.db, NET_A, age_days=40, expires_in_days=-10)
        blocker = self.make(fw)

        result = blocker.reap_expired_cidrs()

        self.assertEqual(result['expired'], 1)
        self.assertEqual(fw.cidr_unblocked, [])
        row, = rows(self.db, NET_A)
        self.assertEqual(row['status'], 'expired')
        self.assertEqual(row['ended_at'], row['expires_at'],
                         "it ended when the router let it go")

    def test_it_becomes_a_repeat_offender_candidate(self):
        fw = CidrFirewall(self_expiring=True)
        add_row(self.db, NET_A, age_days=40, expires_in_days=-10)
        blocker = self.make(fw)
        blocker.reap_expired_cidrs()

        blocker.block('198.51.100.9', 'Tripwire')

        self.assertEqual(len(fw.cidr_blocked), 1)
        self.assertEqual(rows(self.db, NET_A)[-1]['source'], 'reoffend')


class TestManualBlock(Base):
    def test_a_manual_block_is_recorded_with_its_requested_duration(self):
        fw = CidrFirewall()
        blocker = self.make(fw)
        before = int(time.time())

        ok, msg = blocker.block_manual(NET_A, duration='7d')

        self.assertTrue(ok, msg)
        self.assertEqual(fw.cidr_blocked[0][0], NET_A)
        self.assertEqual(fw.cidr_blocked[0][3], '7d')
        row, = rows(self.db, NET_A)
        self.assertEqual((row['source'], row['status'], row['duration']),
                         ('manual', 'active', '7d'))
        self.assertAlmostEqual(row['expires_at'], before + 7 * DAY, delta=60)

    def test_permanent_by_default(self):
        blocker = self.make(CidrFirewall())
        ok, msg = blocker.block_manual(NET_A)
        self.assertTrue(ok, msg)
        row, = rows(self.db, NET_A)
        self.assertEqual((row['expires_at'], row['duration']), (0, 'permanent'))

    def test_blocked_log_line_is_unchanged(self):
        blocker = self.make(CidrFirewall())
        with self.assertLogs('wp-guardian.blocks', level='INFO') as cm:
            blocker.block_manual(NET_A, duration='7d', reason='testing')
        self.assertIn(
            'MANUAL-CIDR-BLOCKED subnet=198.51.100.0/24 duration=7d via=fake reason=testing',
            blocked_log_lines(cm))

    def test_reapply_on_a_self_expiring_backend_removes_then_adds(self):
        fw = CidrFirewall(self_expiring=True)
        blocker = self.make(fw)
        blocker.block_manual(NET_A, duration='7d')
        order = []
        original_unblock, original_block = fw.unblock_cidr, fw.block_cidr
        fw.unblock_cidr = lambda s: (order.append('unblock'), original_unblock(s))[1]
        fw.block_cidr = lambda *a, **k: (order.append('block'), original_block(*a, **k))[1]

        ok, msg = blocker.block_manual(NET_A, duration='30d')

        self.assertTrue(ok, msg)
        self.assertIn('Re-applied', msg)
        self.assertIn('30d', msg)
        self.assertEqual(order, ['unblock', 'block'], "the router TTL is fixed at insert")
        self.assertEqual(statuses(self.db, NET_A), ['removed', 'active'])
        self.assertEqual(rows(self.db, NET_A)[-1]['duration'], '30d')

    def test_reapply_on_firewalld_keeps_the_entry_and_swaps_the_record(self):
        fw = CidrFirewall()
        blocker = self.make(fw)
        blocker.block_manual(NET_A, duration='7d')

        ok, msg = blocker.block_manual(NET_A, duration='perm')

        self.assertTrue(ok, msg)
        self.assertIn('Re-applied', msg)
        self.assertEqual(fw.cidr_unblocked, [], "the set entry stays")
        self.assertIn(NET_A, fw.entries)
        self.assertEqual(statuses(self.db, NET_A), ['removed', 'active'])
        self.assertEqual(rows(self.db, NET_A)[-1]['expires_at'], 0)

    def test_reapply_fails_cleanly_when_the_old_entry_cannot_be_removed(self):
        fw = CidrFirewall(self_expiring=True)
        blocker = self.make(fw)
        blocker.block_manual(NET_A, duration='7d')
        fw.unblock_cidr_ok = False
        calls = len(fw.cidr_blocked)

        ok, msg = blocker.block_manual(NET_A, duration='30d')

        self.assertFalse(ok)
        self.assertEqual(len(fw.cidr_blocked), calls)
        self.assertEqual(statuses(self.db, NET_A), ['active'], "old block untouched")
        self.assertEqual(rows(self.db, NET_A)[0]['duration'], '7d')

    def test_reapply_whose_block_fails_after_the_removal_closes_the_old_record(self):
        fw = CidrFirewall(self_expiring=True)
        blocker = self.make(fw)
        blocker.block_manual(NET_A, duration='7d')
        fw.block_cidr_ok = False

        ok, msg = blocker.block_manual(NET_A, duration='30d')

        self.assertFalse(ok)
        self.assertNotIn(NET_A, fw.entries, "it really is unblocked now")
        self.assertEqual(statuses(self.db, NET_A), ['removed'])

    def test_a_failed_first_block_records_nothing(self):
        fw = CidrFirewall()
        fw.block_cidr_ok = False
        ok, _ = self.make(fw).block_manual(NET_A, duration='7d')
        self.assertFalse(ok)
        self.assertEqual(rows(self.db), [])

    def test_an_entry_with_no_record_gets_one(self):
        fw = CidrFirewall()
        fw.entries.add(NET_A)
        ok, msg = self.make(fw).block_manual(NET_A, duration='7d')
        self.assertTrue(ok, msg)
        self.assertEqual(statuses(self.db, NET_A), ['active'])

    def test_dry_run_and_no_backend_record_nothing(self):
        ok, msg = self.make(None, dry_run=True).block_manual(NET_A)
        self.assertTrue(ok)
        self.assertIn('[DRY-RUN]', msg)
        ok, msg = self.make(None).block_manual(NET_A)
        self.assertFalse(ok)
        self.assertEqual(rows(self.db), [])

    def test_refusals_are_unchanged(self):
        fw = CidrFirewall(friendly=[NET_B])
        blocker = self.make(fw)
        self.db.add_whitelist('192.0.2.5', 'permanent', None, 'office', 'test')
        self.assertFalse(blocker.block_manual('0.0.0.0/0')[0])
        self.assertFalse(blocker.block_manual('192.0.2.0/24')[0])
        self.assertFalse(blocker.block_manual(NET_B)[0])
        self.assertFalse(blocker.block_manual(NET_A, duration='soon')[0])
        self.assertFalse(blocker.block_manual('2001:db8::/32')[0])
        self.assertEqual(rows(self.db), [])
        self.assertEqual(fw.cidr_blocked, [])


class TestManualUnblock(Base):
    def test_lifting_a_block_closes_the_record_as_removed(self):
        fw = CidrFirewall()
        blocker = self.make(fw)
        blocker.block_manual(NET_A, duration='7d')

        ok, msg = blocker.unblock_cidr_manual(NET_A)

        self.assertTrue(ok, msg)
        self.assertIn('Unblocked', msg)
        self.assertEqual(fw.cidr_unblocked, [NET_A])
        row, = rows(self.db, NET_A)
        self.assertEqual(row['status'], 'removed')
        self.assertGreater(row['ended_at'], 0)

    def test_a_removed_range_is_not_a_repeat_offender(self):
        fw = CidrFirewall()
        blocker = self.make(fw)
        blocker.block_manual(NET_A, duration='7d')
        blocker.unblock_cidr_manual(NET_A)

        blocker.block('198.51.100.50', 'Tripwire')

        self.assertEqual(fw.cidr_blocked[1:], [], "operator-cleared, like a false positive")
        self.assertEqual(statuses(self.db, NET_A), ['removed'])

    def test_an_auto_block_the_operator_lifts_can_still_come_back_by_threshold(self):
        # Lifting the subnet does not forgive the IPs inside it: they are still
        # blocked, so the threshold rule fires again on the next block. What a
        # 'removed' row must not do is mark the range as a repeat offender.
        fw = CidrFirewall()
        blocker = self.make(fw)
        block_n(blocker, PREFIX_A, 5)
        blocker.unblock_cidr_manual(NET_A)

        blocker.block('198.51.100.50', 'Tripwire')

        self.assertEqual(rows(self.db, NET_A)[-1]['source'], 'auto')

    def test_a_backend_failure_keeps_the_record(self):
        fw = CidrFirewall()
        blocker = self.make(fw)
        blocker.block_manual(NET_A, duration='7d')
        fw.unblock_cidr_ok = False

        with self.assertLogs('wp-guardian.blocker', level='ERROR'):
            ok, msg = blocker.unblock_cidr_manual(NET_A)

        self.assertFalse(ok)
        self.assertIn('FAILED', msg)
        self.assertEqual(statuses(self.db, NET_A), ['active'])

    def test_a_backend_exception_keeps_the_record(self):
        fw = CidrFirewall()
        blocker = self.make(fw)
        blocker.block_manual(NET_A, duration='7d')
        fw.unblock_cidr_raises = RuntimeError('boom')
        with self.assertLogs('wp-guardian.blocker', level='ERROR'):
            ok, _ = blocker.unblock_cidr_manual(NET_A)
        self.assertFalse(ok)
        self.assertEqual(statuses(self.db, NET_A), ['active'])

    def test_with_no_record_the_backend_removal_is_still_tried(self):
        fw = CidrFirewall()
        fw.entries.add(NET_A)
        ok, msg = self.make(fw).unblock_cidr_manual(NET_A)
        self.assertTrue(ok, msg)
        self.assertEqual(fw.cidr_unblocked, [NET_A])
        self.assertNotIn(NET_A, fw.entries)
        self.assertEqual(rows(self.db), [])

    def test_a_watch_only_subnet_can_be_cleared(self):
        add_row(self.db, NET_A, status='expired', ended_days_ago=4)
        fw = CidrFirewall()
        ok, msg = self.make(fw).unblock_cidr_manual(NET_A)
        self.assertTrue(ok, msg)
        self.assertIn('repeat-offender watch', msg)
        self.assertEqual(self.db.cidr_counts()['watch'], 0)

    def test_no_backend_is_reported_not_pretended(self):
        add_row(self.db, NET_A)
        ok, msg = self.make(None).unblock_cidr_manual(NET_A)
        self.assertFalse(ok)
        self.assertEqual(msg, UNAVAILABLE_UNBLOCK_MSG)
        self.assertEqual(statuses(self.db, NET_A), ['active'])

    def test_dry_run_changes_nothing(self):
        fw = CidrFirewall()
        add_row(self.db, NET_A)
        ok, msg = self.make(fw, dry_run=True).unblock_cidr_manual(NET_A)
        self.assertTrue(ok)
        self.assertIn('[DRY-RUN]', msg)
        self.assertEqual(fw.cidr_unblocked, [])
        self.assertEqual(statuses(self.db, NET_A), ['active'])

    def test_validation(self):
        blocker = self.make(CidrFirewall())
        self.assertEqual(blocker.unblock_cidr_manual('nonsense/24'),
                         (False, 'Invalid CIDR: nonsense/24'))
        self.assertFalse(blocker.unblock_cidr_manual('2001:db8::/32')[0])

    def test_a_host_bits_form_is_normalised(self):
        fw = CidrFirewall()
        blocker = self.make(fw)
        blocker.block_manual(NET_A, duration='7d')
        ok, _ = blocker.unblock_cidr_manual('198.51.100.77/24')
        self.assertTrue(ok)
        self.assertEqual(fw.cidr_unblocked, [NET_A])

    def test_a_narrower_unblock_points_at_the_covering_block(self):
        fw = CidrFirewall()
        blocker = self.make(fw)
        blocker.block_manual(NET_A, duration='7d')
        ok, msg = blocker.unblock_cidr_manual('198.51.100.0/25')
        self.assertTrue(ok)
        self.assertIn('still inside subnet block ' + NET_A, msg)
        self.assertEqual(statuses(self.db, NET_A), ['active'])

    def test_the_blocked_log_records_it(self):
        blocker = self.make(CidrFirewall())
        blocker.block_manual(NET_A, duration='7d')
        with self.assertLogs('wp-guardian.blocks', level='INFO') as cm:
            blocker.unblock_cidr_manual(NET_A, actor='cli')
        self.assertIn('CIDR-UNBLOCKED subnet=198.51.100.0/24 source=manual actor=cli',
                      blocked_log_lines(cm))


class TestCoverNoteAndStatusLine(Base):
    def test_note_for_an_ip_inside_a_timed_block(self):
        add_row(self.db, NET_A, expires_in_days=12)
        note = self.make(CidrFirewall()).cidr_cover_note('198.51.100.9')
        expires = time.strftime('%Y-%m-%d', time.localtime(time.time() + 12 * DAY))
        self.assertEqual(
            note,
            'Note: 198.51.100.9 is still covered by subnet block 198.51.100.0/24 '
            '(expires {}) — /unblock 198.51.100.0/24 to lift it.'.format(expires))

    def test_note_for_a_permanent_block(self):
        add_row(self.db, '198.51.100.0/22', source='manual', permanent=True)
        note = self.make(CidrFirewall()).cidr_cover_note('198.51.100.9')
        self.assertIn('subnet block 198.51.100.0/22 (permanent)', note)

    def test_no_note_when_nothing_covers_the_ip(self):
        add_row(self.db, NET_A)
        add_row(self.db, NET_B, status='expired', ended_days_ago=1)
        blocker = self.make(CidrFirewall())
        self.assertEqual(blocker.cidr_cover_note('192.0.2.9'), '')
        self.assertEqual(blocker.cidr_cover_note('203.0.113.9'), '')
        self.assertEqual(blocker.cidr_cover_note('2001:db8::9'), '')

    def test_an_overdue_row_still_counts_where_the_backend_cannot_expire_it(self):
        add_row(self.db, NET_A, expires_in_days=-2)
        note = self.make(CidrFirewall()).cidr_cover_note('198.51.100.9')
        self.assertIn('release pending', note)

    def test_an_overdue_row_does_not_count_on_a_self_expiring_backend(self):
        add_row(self.db, NET_A, expires_in_days=-2)
        note = self.make(CidrFirewall(self_expiring=True)).cidr_cover_note('198.51.100.9')
        self.assertEqual(note, '', "the router already dropped it")

    def test_status_line(self):
        add_row(self.db, NET_A)
        add_row(self.db, NET_B, expires_in_days=-1)
        add_row(self.db, '192.0.2.0/25', permanent=True)
        add_row(self.db, '192.0.2.128/25', status='expired', ended_days_ago=1)
        blocker = self.make(CidrFirewall())
        self.assertEqual(
            blocker.cidr_status_line(7),
            'CIDR blocks: 3 active (1 permanent, 1 overdue) · backend: 7 '
            '· repeat-offender watch: 1')
        self.assertIn('backend: n/a', blocker.cidr_status_line(None))

    def test_expiry_wording(self):
        now = 1000000
        self.assertEqual(format_cidr_expiry(0, now), 'permanent')
        self.assertEqual(format_cidr_expiry(now + 3 * DAY, now), 'in 3d')
        self.assertEqual(format_cidr_expiry(now + 5 * 3600, now), 'in 5h')
        self.assertEqual(format_cidr_expiry(now + 60, now), 'in 1m')
        self.assertEqual(format_cidr_expiry(now + 3 * DAY - 1, now), 'in 3d')
        self.assertEqual(format_cidr_expiry(now - 2 * DAY, now), 'overdue 2d')


class TestVerbosityRule(unittest.TestCase):
    def test_cidr_reoffend_is_immediate_by_default_and_mutable(self):
        from modules.verbosity import ALWAYS_IMMEDIATE_RULES, DEFAULTS, VerbosityRouter
        import configparser
        import shutil
        import tempfile

        self.assertEqual(DEFAULTS['cidr_reoffend'], 'immediate')
        self.assertNotIn('cidr_reoffend', ALWAYS_IMMEDIATE_RULES)
        self.assertIn('cidr', ALWAYS_IMMEDIATE_RULES, "the original rule stays locked")

        tmp = tempfile.mkdtemp(prefix='wpg-test-')
        try:
            router = VerbosityRouter(configparser.ConfigParser(), tmp)
            self.assertEqual(router.route('cidr_reoffend'), 'immediate')
            ok, _ = router.set_override('cidr_reoffend', 'digest')
            self.assertTrue(ok)
            self.assertEqual(router.route('cidr_reoffend'), 'digest')
            ok, _ = router.set_override('cidr', 'digest')
            self.assertFalse(ok)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
