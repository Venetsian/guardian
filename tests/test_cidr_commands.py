"""Operator surfaces for subnet blocks (v1.7.19): Telegram, CLI, --status and
the daemon wiring (startup reconcile, hourly reaper).

Before this release /unblock was IP-only, so a subnet block could not be lifted
at all, and lifting or whitelisting an IP that sat inside one looked like it
worked while the subnet block kept dropping the address.

wp-guardian.py has a hyphen in its name, so it is loaded by path (see
test_firewall_outage.guardian_module). Stdlib unittest on purpose. Run from the
repo root:

    python3 -m unittest discover -s tests -v
"""

import configparser
import contextlib
import io
import logging
import os
import shutil
import signal
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fakes_cidr import (  # noqa: E402
    DAY, NET_A, NET_B, NET_C, CidrFirewall, DBFixture, FakeTelegram, add_row,
    cidr_config, rows, stamp, statuses, write_log,
)
from test_firewall_outage import bare_guardian, guardian_module  # noqa: E402

from actions.telegram_commands import TelegramCommander  # noqa: E402
from modules.database import GuardianDB  # noqa: E402

IP_IN_A = '198.51.100.9'


def make_commander(fx, blocker, firewall=None):
    config = configparser.ConfigParser()
    config.add_section('telegram')
    config.set('telegram', 'commands_enabled', 'true')
    config.set('telegram', 'bot_token', 'test-token')
    config.set('telegram', 'chat_id', '12345')
    commander = TelegramCommander(config, fx.db, blocker, fx.whitelist, firewall=firewall)
    commander.replies = []
    commander._reply = commander.replies.append        # never touch the network
    return commander


def block_in_db(db, ip, tier=1):
    db.track_ip(ip)
    db.record_block(ip, tier, 'Tripwire', 'web', 'fake', '24h')


class TelegramBase(unittest.TestCase):
    def setUp(self):
        self.fx = DBFixture()
        self.db = self.fx.db
        self.fw = CidrFirewall()
        self.blocker = self.fx.blocker(firewall=self.fw, telegram=FakeTelegram(),
                                       cidr=cidr_config())
        self.c = make_commander(self.fx, self.blocker, self.fw)

    def tearDown(self):
        self.fx.close()


class TestUnblockIpNote(TelegramBase):
    def test_unblocking_an_ip_inside_a_subnet_block_says_so(self):
        add_row(self.db, NET_A, expires_in_days=12)
        block_in_db(self.db, IP_IN_A)

        self.c._cmd_unblock([IP_IN_A])

        reply, = self.c.replies
        self.assertIn('Unblocked <code>198.51.100.9</code>', reply)
        self.assertIn('Note: 198.51.100.9 is still covered by subnet block '
                      '198.51.100.0/24 (expires ', reply)
        self.assertIn('/unblock 198.51.100.0/24 to lift it.', reply)

    def test_permanent_subnet_block(self):
        add_row(self.db, NET_A, permanent=True)
        block_in_db(self.db, IP_IN_A)
        self.c._cmd_unblock([IP_IN_A])
        self.assertIn('(permanent)', self.c.replies[0])

    def test_the_note_also_goes_on_an_ip_that_is_not_blocked_itself(self):
        add_row(self.db, NET_A)
        self.c._cmd_unblock([IP_IN_A])
        reply, = self.c.replies
        self.assertIn('is not currently blocked', reply)
        self.assertIn('still covered by subnet block', reply)

    def test_no_note_without_a_covering_block(self):
        block_in_db(self.db, IP_IN_A)
        self.c._cmd_unblock([IP_IN_A])
        self.assertNotIn('Note:', self.c.replies[0])

    def test_no_note_for_a_subnet_that_already_ended(self):
        add_row(self.db, NET_A, status='expired', ended_days_ago=2)
        block_in_db(self.db, IP_IN_A)
        self.c._cmd_unblock([IP_IN_A])
        self.assertNotIn('Note:', self.c.replies[0])

    def test_the_note_survives_a_failed_unblock(self):
        add_row(self.db, NET_A)
        block_in_db(self.db, IP_IN_A)
        self.fw.unblock_ok = False
        self.c._cmd_unblock([IP_IN_A])
        self.assertIn('Failed to unblock', self.c.replies[0])
        self.assertIn('still covered by subnet block', self.c.replies[0])

    def test_a_broken_lookup_never_breaks_the_command(self):
        block_in_db(self.db, IP_IN_A)
        self.blocker.cidr_cover_note = lambda ip: 1 / 0
        self.c._cmd_unblock([IP_IN_A])
        self.assertIn('Unblocked', self.c.replies[0])


class TestWhitelistNote(TelegramBase):
    def test_whitelisting_an_ip_inside_a_subnet_block_says_it_is_still_blocked(self):
        add_row(self.db, NET_A, expires_in_days=5)

        self.c._cmd_whitelist([IP_IN_A])

        reply, = self.c.replies
        self.assertIn('Whitelisted <code>198.51.100.9</code>', reply)
        self.assertIn('still covered by subnet block 198.51.100.0/24', reply)
        self.assertTrue(self.fx.whitelist.is_whitelisted(IP_IN_A))

    def test_no_note_otherwise(self):
        self.c._cmd_whitelist([IP_IN_A, '24h'])
        self.assertNotIn('Note:', self.c.replies[0])


class TestUnblockCidr(TelegramBase):
    def test_a_slash_goes_to_the_subnet_path(self):
        self.blocker.block_manual(NET_A, duration='7d')

        self.c._cmd_unblock([NET_A])

        reply, = self.c.replies
        self.assertTrue(reply.startswith('✅ Unblocked 198.51.100.0/24'), reply)
        self.assertEqual(self.fw.cidr_unblocked, [NET_A])
        self.assertEqual(statuses(self.db, NET_A), ['removed'])

    def test_a_failure_is_reported_honestly(self):
        self.blocker.block_manual(NET_A, duration='7d')
        self.fw.unblock_cidr_ok = False
        with self.assertLogs('wp-guardian.blocker', level='ERROR'):
            self.c._cmd_unblock([NET_A])
        self.assertTrue(self.c.replies[0].startswith('⚠️ '), self.c.replies[0])
        self.assertIn('FAILED', self.c.replies[0])
        self.assertEqual(statuses(self.db, NET_A), ['active'])

    def test_an_invalid_cidr_is_rejected_with_the_text_escaped(self):
        self.c._cmd_unblock(['<b>/24'])
        self.assertIn('Invalid CIDR', self.c.replies[0])
        self.assertNotIn('<b>', self.c.replies[0], "user text must not reach Telegram's HTML parser")

    def test_dry_run_is_a_simulation(self):
        add_row(self.db, NET_A)
        blocker = self.fx.blocker(dry_run=True, firewall=self.fw, telegram=FakeTelegram())
        make_commander(self.fx, blocker, self.fw)._cmd_unblock([NET_A])
        self.assertEqual(self.fw.cidr_unblocked, [])
        self.assertEqual(statuses(self.db, NET_A), ['active'])

    def test_an_ip_still_takes_the_ip_path(self):
        block_in_db(self.db, IP_IN_A)
        self.c._cmd_unblock([IP_IN_A])
        self.assertEqual(self.fw.unblocked, [IP_IN_A])
        self.assertEqual(self.fw.cidr_unblocked, [])

    def test_usage_mentions_cidr(self):
        self.c._cmd_unblock([])
        self.assertIn('ip|cidr', self.c.replies[0])

    def test_dispatch_routes_the_command(self):
        add_row(self.db, NET_A)
        self.c._dispatch_command('/unblock ' + NET_A, 12345)
        self.assertEqual(self.fw.cidr_unblocked, [NET_A])


class TestCidrsCommand(TelegramBase):
    def test_overview(self):
        add_row(self.db, NET_A, expires_in_days=3, source='auto')
        add_row(self.db, NET_B, expires_in_days=20, source='manual')
        add_row(self.db, '192.0.2.0/25', permanent=True, source='manual')
        add_row(self.db, '192.0.2.128/25', expires_in_days=-4, source='import')
        add_row(self.db, NET_C, status='expired', ended_days_ago=3)

        self.c._dispatch_command('/cidrs', 12345)

        reply, = self.c.replies
        self.assertIn('Active: 4 (1 permanent)', reply)
        self.assertIn('Overdue, awaiting release: 1', reply)
        self.assertIn('Repeat-offender watch: 1', reply)
        self.assertIn('<code>198.51.100.0/24</code> auto — in 3d', reply)
        self.assertIn('<code>203.0.113.0/24</code> manual — in 20d', reply)
        self.assertIn('<code>192.0.2.0/25</code> manual — permanent', reply)
        self.assertNotIn('192.0.2.128/25</code>', reply, "overdue ones are counted, not listed")
        self.assertLess(reply.index('198.51.100.0/24'), reply.index('203.0.113.0/24'),
                        "soonest first")

    def test_lists_at_most_ten(self):
        for i in range(14):
            add_row(self.db, '203.0.113.{}/32'.format(i), expires_in_days=i + 1)
        self.c._cmd_cidrs([])
        self.assertEqual(self.c.replies[0].count('<code>'), 10)

    def test_empty(self):
        self.c._cmd_cidrs([])
        self.assertIn('Active: 0 (0 permanent)', self.c.replies[0])
        self.assertNotIn('Soonest', self.c.replies[0])

    def test_help_lists_the_new_command_and_the_cidr_form(self):
        self.c._cmd_help([])
        self.assertIn('/cidrs', self.c.replies[0])
        self.assertIn('/unblock &lt;ip|cidr&gt;', self.c.replies[0])


class TestStatusCommand(TelegramBase):
    def test_status_has_the_subnet_line_with_the_backend_count(self):
        add_row(self.db, NET_A)
        add_row(self.db, NET_B, permanent=True)
        add_row(self.db, NET_C, expires_in_days=-1)
        add_row(self.db, '192.0.2.0/25', status='expired', ended_days_ago=1)
        self.fw.counts = {'cidr': 9, 'ips': 100}

        self.c._cmd_status([])

        self.assertIn('CIDR blocks: 3 active (1 permanent, 1 overdue) · backend: 9 '
                      '· repeat-offender watch: 1', self.c.replies[0])

    def test_status_survives_a_backend_that_cannot_count(self):
        def boom():
            raise RuntimeError('router unreachable')
        self.fw.get_block_counts = boom
        self.c._cmd_status([])
        self.assertIn('CIDR blocks: 0 active', self.c.replies[0])
        self.assertIn('backend: n/a', self.c.replies[0])


class GuardianBase(unittest.TestCase):
    """Guardian wiring, built as bare as test_firewall_outage builds it."""

    def setUp(self):
        self.fx = DBFixture()
        self.tmp = tempfile.mkdtemp(prefix='wpg-test-')
        os.makedirs(os.path.join(self.tmp, 'logs'))

    def tearDown(self):
        self.fx.close()
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestAttachFirewallReconciles(GuardianBase):
    def guardian(self):
        g = bare_guardian(self.fx)
        g.base_dir = self.tmp
        g.blocker = self.fx.blocker(firewall=None, telegram=g.telegram, cidr=cidr_config())
        return g

    def test_records_are_reconciled_before_the_blocker_sees_the_backend(self):
        write_log(os.path.join(self.tmp, 'logs'), 'blocked.log',
                  ['{} CIDR-BLOCKED subnet={} count=5 duration=30d IPs=x'.format(
                      stamp(time.time() - DAY), NET_A)])
        g = self.guardian()
        seen = []

        class Spy(CidrFirewall):
            def list_cidr_entries(inner):
                seen.append(g.blocker.firewall)
                return set([NET_A])

        fw = Spy(lists=True)
        g._attach_firewall(fw)

        self.assertEqual(seen, [None], "no block can race the import")
        self.assertIs(g.blocker.firewall, fw)
        self.assertEqual(statuses(self.fx.db, NET_A), ['active'])
        self.assertEqual(len(g.telegram.sent), 1, "one import summary")

    def test_a_failing_reconcile_does_not_stop_the_attach(self):
        g = self.guardian()

        def boom(*args, **kwargs):
            raise RuntimeError('database is locked')
        g.blocker.reconcile_cidrs = boom
        fw = CidrFirewall()

        with self.assertLogs('wp-guardian.test-outage', level='ERROR'):
            g._attach_firewall(fw)

        self.assertIs(g.blocker.firewall, fw)

    def test_a_backend_without_cidr_support_is_not_reconciled(self):
        g = self.guardian()
        called = []
        g.blocker.reconcile_cidrs = lambda *a, **k: called.append(1)
        fw = CidrFirewall()
        fw.supports_cidr = False
        g._attach_firewall(fw)
        self.assertEqual(called, [])


class TestStatusOutput(GuardianBase):
    def test_status_prints_the_subnet_line(self):
        g = bare_guardian(self.fx)
        g.firewall = CidrFirewall()
        g.firewall.counts = {'cidr': 4}
        add_row(self.fx.db, NET_A)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            g.status()
        self.assertIn('CIDR blocks: 1 active (0 permanent, 0 overdue) · backend: 4 '
                      '· repeat-offender watch: 0', out.getvalue())


class MainBase(unittest.TestCase):
    """The real Guardian.__init__ and main(), with the backend factory faked."""

    def setUp(self):
        self.mod = guardian_module()
        self.tmp = tempfile.mkdtemp(prefix='wpg-test-')
        os.makedirs(os.path.join(self.tmp, 'logs'))
        self.db_path = os.path.join(self.tmp, 'state', 'guardian.db')
        self.weblog = os.path.join(self.tmp, 'site.access_log')
        open(self.weblog, 'w').close()
        self.config_path = os.path.join(self.tmp, 'wp-guardian.conf')
        with open(self.config_path, 'w') as f:
            # Everything the constructor would read from the repo or the host is
            # pointed at the temp dir, and no log the host might really have is
            # tailed. '%%' is configparser's literal percent.
            f.write(
                "[database]\npath = {db}\n"
                "[firewall]\nbackend = firewalld\n"
                "[whitelist]\nfile = {wl}\n"
                "[general]\nlogfiles_list = {lf}\n"
                "[log_paths]\nmail_log = {nope}\nsecure_log = {nope}\nroundcube_log = {nope}\n"
                "[cidr]\nenabled = true\nthreshold = 5\nduration = 30d\n".format(
                    db=self.db_path.replace('%', '%%'),
                    wl=os.path.join(self.tmp, 'whitelist.conf').replace('%', '%%'),
                    lf=os.path.join(self.tmp, 'logfiles.txt').replace('%', '%%'),
                    nope=os.path.join(self.tmp, 'absent.log').replace('%', '%%'),
                ))
        with open(os.path.join(self.tmp, 'logfiles.txt'), 'w') as f:
            f.write(self.weblog + '\n')

        self.fw = CidrFirewall(lists=True)
        self._orig = (self.mod.create_backend, self.mod.setup_logging,
                      self.mod.LogTailer, self.mod.time.sleep,
                      signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT))
        self.mod.create_backend = lambda config: self.fw
        self.mod.setup_logging = lambda config, base_dir=None: logging.getLogger('wp-guardian')

    def tearDown(self):
        (self.mod.create_backend, self.mod.setup_logging, self.mod.LogTailer,
         self.mod.time.sleep, term, intr) = self._orig
        for signum, handler in ((signal.SIGTERM, term), (signal.SIGINT, intr)):
            if handler is not None:       # None: not installed from Python
                signal.signal(signum, handler)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def seed(self):
        """A GuardianDB on the daemon's database file, for setup and checks."""
        return GuardianDB(self.db_path, base_dir=self.tmp)

    def run_main(self, *argv):
        out = io.StringIO()
        old_argv = sys.argv
        sys.argv = ['wp-guardian.py', '--config', self.config_path] + list(argv)
        code = 0
        try:
            with contextlib.redirect_stdout(out):
                try:
                    self.mod.main()
                except SystemExit as e:
                    code = e.code
        finally:
            sys.argv = old_argv
        return code, out.getvalue()


class TestCli(MainBase):
    def test_unblock_cidr_lifts_the_subnet_block(self):
        db = self.seed()
        add_row(db, NET_A, source='manual', permanent=True)
        db.close()
        self.fw.entries.add(NET_A)

        code, out = self.run_main('--unblock', NET_A)

        self.assertEqual(code, 0)
        self.assertIn('Unblocked 198.51.100.0/24', out)
        self.assertEqual(self.fw.cidr_unblocked, [NET_A])
        db = self.seed()
        self.assertEqual(statuses(db, NET_A), ['removed'])
        db.close()

    def test_unblock_cidr_failure_exits_non_zero(self):
        db = self.seed()
        add_row(db, NET_A)
        db.close()
        self.fw.unblock_cidr_ok = False

        with self.assertLogs('wp-guardian.blocker', level='ERROR'):
            code, out = self.run_main('--unblock', NET_A)

        self.assertEqual(code, 1)
        self.assertIn('FAILED', out)

    def test_unblock_ip_prints_the_covering_note(self):
        db = self.seed()
        add_row(db, NET_A, expires_in_days=9)
        block_in_db(db, IP_IN_A)
        db.close()

        code, out = self.run_main('--unblock', IP_IN_A)

        self.assertEqual(code, 0)
        self.assertIn('Unblocked 198.51.100.9', out)
        self.assertIn('Note: 198.51.100.9 is still covered by subnet block 198.51.100.0/24', out)
        self.assertEqual(self.fw.cidr_unblocked, [], "the subnet is left alone")

    def test_unblock_ip_without_a_covering_block_prints_no_note(self):
        db = self.seed()
        block_in_db(db, IP_IN_A)
        db.close()
        code, out = self.run_main('--unblock', IP_IN_A)
        self.assertEqual(code, 0)
        self.assertNotIn('Note:', out)

    def test_status_shows_the_subnet_line(self):
        db = self.seed()
        add_row(db, NET_A)
        add_row(db, NET_B, expires_in_days=-1)
        db.close()
        self.fw.counts = {'cidr': 2}

        code, out = self.run_main('--status')

        self.assertEqual(code, 0)
        self.assertIn('CIDR blocks: 2 active (0 permanent, 1 overdue) · backend: 2 '
                      '· repeat-offender watch: 0', out)

    def test_cli_invocations_do_not_import_or_reconcile(self):
        # --status must not mutate anything: reconcile belongs to the daemon.
        write_log(os.path.join(self.tmp, 'logs'), 'blocked.log',
                  ['{} CIDR-BLOCKED subnet={} count=5 duration=30d IPs=x'.format(
                      stamp(time.time() - DAY), NET_A)])
        self.fw.entries.add(NET_A)
        self.run_main('--status')
        db = self.seed()
        self.assertEqual(rows(db), [])
        db.close()


class FakeTailer(object):
    """Records what the cidr_blocks table held at the moment a tailer started."""
    db_path = None
    seen = []

    def __init__(self, log_files, detector, name='tailer', track_site=False):
        self.log_files = log_files
        self.detector = detector
        self.name = name

    def start(self):
        import sqlite3
        conn = sqlite3.connect(FakeTailer.db_path)
        FakeTailer.seen.append(conn.execute("SELECT COUNT(*) FROM cidr_blocks").fetchone()[0])
        conn.close()

    def stop(self):
        pass


class TestDaemonStart(MainBase):
    """Guardian.start(): reconcile first, then tailers; hourly tick reaps subnets."""

    def start_daemon(self):
        g = self.mod.Guardian(self.config_path)
        g.base_dir = self.tmp                      # logs/ here, not the repo's
        g.posture_auditor = None                   # no host probing under test
        g.tmp_cleanup = None
        FakeTailer.db_path = self.db_path
        FakeTailer.seen = []
        self.mod.LogTailer = FakeTailer

        def one_pass(seconds):
            g.running = False                      # leave after the first loop pass
        self.mod.time.sleep = one_pass
        g.start()
        return g

    def test_the_import_finishes_before_the_first_tailer_starts(self):
        write_log(os.path.join(self.tmp, 'logs'), 'blocked.log',
                  ['{} CIDR-BLOCKED subnet={} count=5 duration=30d IPs=x'.format(
                      stamp(time.time() - DAY), NET_A)])
        self.fw.entries.add(NET_A)

        g = self.start_daemon()
        try:
            self.assertEqual(FakeTailer.seen, [1],
                             "the table was already populated when the web tailer started")
            self.assertEqual(statuses(g.db, NET_A), ['active'])
        finally:
            g.db.close()

    def test_the_hourly_tick_releases_overdue_subnet_blocks(self):
        db = self.seed()
        add_row(db, NET_A, age_days=40, expires_in_days=-10)
        add_row(db, NET_B, expires_in_days=10)
        db.close()
        self.fw.entries.update([NET_A, NET_B])

        g = self.start_daemon()
        try:
            self.assertEqual(self.fw.cidr_unblocked, [NET_A])
            self.assertEqual(statuses(g.db, NET_A), ['expired'])
            self.assertEqual(statuses(g.db, NET_B), ['active'])
        finally:
            g.db.close()

    def test_reaping_can_be_switched_off_like_the_ip_reaper(self):
        with open(self.config_path, 'a') as f:
            f.write("[escalation]\nreap_enabled = false\n")
        db = self.seed()
        add_row(db, NET_A, age_days=40, expires_in_days=-10)
        db.close()
        self.fw.entries.add(NET_A)

        g = self.start_daemon()
        try:
            self.assertEqual(self.fw.cidr_unblocked, [])
        finally:
            g.db.close()

    def test_a_dry_run_start_reconciles_nothing(self):
        write_log(os.path.join(self.tmp, 'logs'), 'blocked.log',
                  ['{} CIDR-BLOCKED subnet={} count=5 duration=30d IPs=x'.format(
                      stamp(time.time() - DAY), NET_A)])
        self.fw.entries.add(NET_A)
        g = self.mod.Guardian(self.config_path, dry_run=True)
        g.base_dir = self.tmp
        g.posture_auditor = None
        g.tmp_cleanup = None
        FakeTailer.db_path = self.db_path
        FakeTailer.seen = []
        self.mod.LogTailer = FakeTailer
        self.mod.time.sleep = lambda s: setattr(g, 'running', False)
        try:
            g.start()
            self.assertEqual(rows(g.db), [])
        finally:
            g.db.close()


if __name__ == '__main__':
    unittest.main()
