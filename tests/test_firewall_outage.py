"""A firewall backend that fails to initialise is an outage, not a dry run.

Guardian.__init__ used to catch a create_backend() failure, set firewall=None
and flip [general] dry_run on, silently, for the whole uptime. With a systemd
unit ordered only After=network.target, a boot where Guardian beat firewalld (or
the MikroTik router) to readiness ran in dry-run until the next restart, with
no alert. Now: the dry-run flag is left alone, one CRITICAL alert goes out, the
blocker refuses (and does not record) blocks, and the main loop retries the
backend with a 60s -> 600s backoff, announcing recovery once.

Also covers --dry-run being in force before any component is built.

wp-guardian.py has a hyphen in its name, so it is loaded by path. Stdlib
unittest on purpose. Run from the repo root:

    python3 -m unittest discover -s tests -v
"""

import contextlib
import importlib.util
import io
import logging
import os
import sys
import tempfile
import time
import types
import unittest
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fakes_enforcement import DBFixture, FakeFirewall, FakeTelegram  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IP = '192.0.2.10'

_MODULE = None


def guardian_module():
    """Load wp-guardian.py once, as a module."""
    global _MODULE
    if _MODULE is not None:
        return _MODULE

    spec = importlib.util.spec_from_file_location(
        'wp_guardian_main', os.path.join(REPO, 'wp-guardian.py'))
    module = importlib.util.module_from_spec(spec)

    # modules/mail_backend.py imports `crypt`, which Python 3.13 removed. The
    # hosts run 3.9; on a newer dev machine a stand-in is enough because the
    # module is only used when a mailbox password is actually hashed.
    stubbed = False
    if 'crypt' not in sys.modules:
        try:
            import crypt  # noqa: F401
        except ImportError:
            sys.modules['crypt'] = types.ModuleType('crypt')
            stubbed = True
    try:
        spec.loader.exec_module(module)
    finally:
        if stubbed:
            del sys.modules['crypt']

    _MODULE = module
    return module


class FriendlyFirewall(FakeFirewall):
    supports_friendly_list = True


class CmdHolder(object):
    """Stands in for TelegramCommander: only the attribute under test."""

    def __init__(self):
        self.firewall = None


def bare_guardian(fx, backend='firewalld'):
    """A Guardian with the outage state initialised and nothing else built."""
    mod = guardian_module()
    g = mod.Guardian.__new__(mod.Guardian)
    g.logger = logging.getLogger('wp-guardian.test-outage')
    g.config = _config_with_backend(backend)
    g.db = fx.db
    g.version = 'test'
    g.telegram = FakeTelegram()
    g.whitelist = fx.whitelist
    g.blocker = fx.blocker(firewall=None, telegram=g.telegram)
    g.telegram_cmd = CmdHolder()
    g.firewall = None
    g._fw_init_error = 'connection refused'
    g._fw_outage_since = time.time()
    g._fw_retry_delay = mod.Guardian.FW_RETRY_INITIAL
    g._fw_next_retry = 0
    return g


def _config_with_backend(backend):
    import configparser
    config = configparser.ConfigParser()
    config.add_section('firewall')
    config.set('firewall', 'backend', backend)
    return config


class TestAttachFirewall(unittest.TestCase):
    def setUp(self):
        self.fx = DBFixture()
        self.g = bare_guardian(self.fx)

    def tearDown(self):
        self.fx.close()

    def test_every_holder_gets_the_backend(self):
        fw = FriendlyFirewall()
        self.g._attach_firewall(fw)

        self.assertIs(self.g.firewall, fw)
        self.assertIs(self.g.blocker.firewall, fw)
        self.assertIs(self.g.whitelist.firewall, fw)
        self.assertIs(self.g.telegram_cmd.firewall, fw)

    def test_rules_are_ensured_and_the_friendly_list_refreshed(self):
        fw = FriendlyFirewall()
        self.g._attach_firewall(fw)
        self.assertEqual(fw.ensure_calls, 1)
        self.assertEqual(fw.friendly_refreshes, 1)

    def test_friendly_list_is_not_refreshed_when_unsupported(self):
        fw = FakeFirewall()
        self.g._attach_firewall(fw)
        self.assertEqual(fw.ensure_calls, 1)
        self.assertEqual(fw.friendly_refreshes, 0)

    def test_backend_setup_finishes_before_any_holder_can_use_it(self):
        g = self.g
        seen = []

        class Spy(FriendlyFirewall):
            def ensure_firewall_rules(self):
                seen.append(('ensure', g.blocker.firewall, g.whitelist.firewall))

            def refresh_friendly_list(self):
                seen.append(('friendly', g.blocker.firewall, g.whitelist.firewall))

        g._attach_firewall(Spy())

        self.assertEqual([s[0] for s in seen], ['ensure', 'friendly'])
        for _, blocker_fw, whitelist_fw in seen:
            self.assertIsNone(blocker_fw, "blocker must not see a half-set-up backend")
            self.assertIsNone(whitelist_fw)

    def test_failed_setup_attaches_nothing(self):
        class Broken(FakeFirewall):
            def ensure_firewall_rules(self):
                raise RuntimeError('cannot create ipset')

        with self.assertRaises(RuntimeError):
            self.g._attach_firewall(Broken())

        self.assertIsNone(self.g.firewall)
        self.assertIsNone(self.g.blocker.firewall)
        self.assertIsNone(self.g.whitelist.firewall)
        self.assertIsNone(self.g.telegram_cmd.firewall)


class TestRetryAndRecovery(unittest.TestCase):
    def setUp(self):
        self.fx = DBFixture()
        self.g = bare_guardian(self.fx)
        self.mod = guardian_module()
        self._orig_create = self.mod.create_backend

    def tearDown(self):
        self.mod.create_backend = self._orig_create
        self.fx.close()

    def _backend_down(self):
        def fail(config):
            raise RuntimeError('firewalld is not running')
        self.mod.create_backend = fail

    def _backend_up(self, fw=None):
        fw = fw or FakeFirewall()
        self.mod.create_backend = lambda config: fw
        return fw

    def test_backoff_doubles_from_60_to_a_600_second_cap(self):
        self._backend_down()
        delays = []
        with self.assertLogs('wp-guardian.test-outage', level='ERROR'):
            for _ in range(6):
                self.assertFalse(self.g._retry_firewall())
                delays.append(self.g._fw_retry_delay)

        self.assertEqual(delays, [120, 240, 480, 600, 600, 600])
        self.assertGreater(self.g._fw_next_retry, time.time() + 590)

    def test_failed_retries_do_not_alert_or_attach(self):
        self._backend_down()
        with self.assertLogs('wp-guardian.test-outage', level='ERROR'):
            for _ in range(4):
                self.g._retry_firewall()

        self.assertEqual(self.g.telegram.sent, [], "no repeated alerts per retry")
        self.assertIsNone(self.g.firewall)

    def test_recovery_attaches_resets_state_and_alerts_exactly_once(self):
        # Three block attempts from two IPs during the outage.
        with self.assertLogs('wp-guardian.blocker', level='ERROR'):
            self.g.blocker.block(IP, 'Tripwire')
            self.g.blocker.block(IP, 'Tripwire')
            self.g.blocker.block('192.0.2.11', 'Tripwire')
        self.g._fw_outage_since = time.time() - 600     # ten minutes ago
        self.g._fw_retry_delay = 480
        fw = self._backend_up(FriendlyFirewall())

        self.assertTrue(self.g._retry_firewall())

        self.assertIs(self.g.blocker.firewall, fw)
        self.assertEqual(fw.ensure_calls, 1)
        self.assertEqual(len(self.g.telegram.sent), 1)
        message, priority = self.g.telegram.sent[0]
        self.assertIn('recovered', message)
        self.assertIn('10 min', message)
        self.assertIn('3 block attempt', message)
        self.assertIn('2 distinct IP', message)
        self.assertEqual(self.g._fw_outage_since, 0)
        self.assertEqual(self.g._fw_retry_delay, self.mod.Guardian.FW_RETRY_INITIAL)
        self.assertEqual(self.g.blocker.take_unenforced(), (0, 0), "counters consumed")

    def test_blocking_works_again_after_recovery(self):
        fw = self._backend_up()
        self.g._retry_firewall()

        self.assertTrue(self.g.blocker.block(IP, 'Tripwire'))

        self.assertEqual(fw.blocked, [(IP, 1)])

    def test_recovery_survives_a_failing_telegram(self):
        class Boom(FakeTelegram):
            def send(self, message, priority='INFO'):
                raise RuntimeError('telegram down')

        self.g.telegram = Boom()
        fw = self._backend_up()

        self.assertTrue(self.g._retry_firewall())
        self.assertIs(self.g.firewall, fw)

    def test_setup_failure_on_a_reachable_backend_counts_as_a_failed_attempt(self):
        class Broken(FakeFirewall):
            def ensure_firewall_rules(self):
                raise RuntimeError('cannot create ipset')

        self.mod.create_backend = lambda config: Broken()
        with self.assertLogs('wp-guardian.test-outage', level='ERROR'):
            self.assertFalse(self.g._retry_firewall())
        self.assertIsNone(self.g.blocker.firewall)
        self.assertEqual(self.g._fw_retry_delay, 120)


class TestOutageAlert(unittest.TestCase):
    def setUp(self):
        self.fx = DBFixture()

    def tearDown(self):
        self.fx.close()

    def test_alert_is_critical_and_names_backend_and_error(self):
        g = bare_guardian(self.fx, backend='mikrotik')
        g._fw_init_error = 'Cannot connect to <router> & friends'

        g._alert_firewall_down()

        self.assertEqual(len(g.telegram.sent), 1)
        message, priority = g.telegram.sent[0]
        self.assertEqual(priority, 'CRITICAL')
        self.assertIn('mikrotik', message)
        self.assertIn('IP blocking is OFF', message)
        self.assertIn('Retrying', message)
        self.assertIn('&lt;router&gt; &amp; friends', message,
                      "the error text must be HTML-escaped for Telegram")


class TestStatusShowsTheOutage(unittest.TestCase):
    def setUp(self):
        self.fx = DBFixture()

    def tearDown(self):
        self.fx.close()

    def _status(self, g):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            g.status()
        return out.getvalue()

    def test_backend_none_and_not_dry_run_is_unavailable(self):
        g = bare_guardian(self.fx)
        self.assertIn('UNAVAILABLE', self._status(g))

    def test_dry_run_without_a_backend_is_not_called_unavailable(self):
        g = bare_guardian(self.fx)
        g.blocker = self.fx.blocker(dry_run=True, firewall=None)
        self.assertNotIn('UNAVAILABLE', self._status(g))

    def test_a_working_backend_is_not_called_unavailable(self):
        g = bare_guardian(self.fx)
        g.firewall = FakeFirewall()
        g.firewall.get_block_counts = lambda: {}
        self.assertNotIn('UNAVAILABLE', self._status(g))


class TestGuardianConstruction(unittest.TestCase):
    """The real Guardian.__init__, with the backend factory and logging faked."""

    def setUp(self):
        self.mod = guardian_module()
        self.tmp = tempfile.mkdtemp(prefix='wpg-test-')
        self.config_path = os.path.join(self.tmp, 'wp-guardian.conf')
        with open(self.config_path, 'w') as f:
            # Everything the constructor would otherwise read from the repo
            # (the operator's real whitelist, logfiles list) is pointed at the
            # temp dir. '%%' is configparser's literal percent.
            f.write(
                "[database]\npath = {db}\n"
                "[firewall]\nbackend = firewalld\n"
                "[whitelist]\nfile = {wl}\n"
                "[general]\nlogfiles_list = {lf}\n".format(
                    db=os.path.join(self.tmp, 'state', 'guardian.db').replace('%', '%%'),
                    wl=os.path.join(self.tmp, 'whitelist.conf').replace('%', '%%'),
                    lf=os.path.join(self.tmp, 'logfiles.txt').replace('%', '%%'),
                ))
        self._orig_create = self.mod.create_backend
        self._orig_logging = self.mod.setup_logging
        self.mod.setup_logging = lambda config, base_dir=None: logging.getLogger('wp-guardian')
        self.created = []
        self.guardians = []

    def tearDown(self):
        self.mod.create_backend = self._orig_create
        self.mod.setup_logging = self._orig_logging
        for g in self.guardians:
            g.db.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _build(self, backend, dry_run=False):
        """Construct a Guardian. backend: a FakeFirewall, or an Exception to raise."""
        def create(config):
            # What the backend factory saw of the dry-run flag AT THAT MOMENT.
            self.created.append(config.get('general', 'dry_run', fallback='unset'))
            if isinstance(backend, Exception):
                raise backend
            return backend
        self.mod.create_backend = create
        g = self.mod.Guardian(self.config_path, dry_run=dry_run)
        self.guardians.append(g)
        return g

    def test_dry_run_flag_is_in_force_before_the_backend_is_built(self):
        fw = FakeFirewall()
        g = self._build(fw, dry_run=True)

        self.assertEqual(self.created, ['true'])
        self.assertTrue(g.blocker.dry_run)
        self.assertTrue(g.config.getboolean('general', 'dry_run'))

    def test_dry_run_skips_startup_rule_setup(self):
        fw = FakeFirewall()
        g = self._build(fw, dry_run=True)
        self.assertIs(g.firewall, fw)
        self.assertEqual(fw.ensure_calls, 0)

    def test_live_start_still_ensures_rules(self):
        fw = FakeFirewall()
        g = self._build(fw)
        self.assertFalse(g.blocker.dry_run)
        self.assertEqual(fw.ensure_calls, 1)

    def test_backend_failure_does_not_flip_dry_run(self):
        g = self._build(RuntimeError('firewalld is not running'))

        self.assertIsNone(g.firewall)
        self.assertFalse(g.blocker.dry_run, "an outage is not a dry run")
        self.assertFalse(g.config.getboolean('general', 'dry_run', fallback=False))
        self.assertIn('firewalld is not running', g._fw_init_error)
        self.assertGreater(g._fw_outage_since, 0)
        self.assertIsNone(g.whitelist.firewall)
        self.assertIsNone(g.telegram_cmd.firewall)

    def test_blocks_are_refused_not_simulated_during_the_outage(self):
        g = self._build(RuntimeError('firewalld is not running'))

        with self.assertLogs('wp-guardian.blocker', level='ERROR'):
            self.assertFalse(g.blocker.block(IP, 'Tripwire'))

        rows = g.db.conn.execute("SELECT COUNT(*) FROM block_log").fetchone()[0]
        self.assertEqual(rows, 0)

    def test_backend_failure_under_requested_dry_run_is_not_an_outage(self):
        g = self._build(RuntimeError('firewalld is not running'), dry_run=True)

        self.assertIsNone(g.firewall)
        self.assertTrue(g.blocker.dry_run)
        self.assertIsNone(g._fw_init_error, "operator asked for dry-run: nothing to retry")
        self.assertEqual(g._fw_outage_since, 0)

    def test_status_after_a_failed_start_reports_unavailable(self):
        g = self._build(RuntimeError('firewalld is not running'))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            g.status()
        self.assertIn('UNAVAILABLE', out.getvalue())


class TestServiceUnitOrdering(unittest.TestCase):
    def test_unit_waits_for_the_network_and_firewalld(self):
        with open(os.path.join(REPO, 'wp-guardian.service')) as f:
            unit = f.read()
        self.assertIn('After=network-online.target firewalld.service', unit)
        self.assertIn('Wants=network-online.target', unit)
        # Ordering only: no hard dependency, so hosts without firewalld start.
        self.assertNotIn('Requires=firewalld', unit)


if __name__ == '__main__':
    unittest.main()
