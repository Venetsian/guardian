"""Regression tests for per-rule enforcement and provisional disables.

Guards the v1.7.11 false-positive fix. On 2026-08-09 a travelling client's
mailbox (bob@example.net) was auto-disabled for 16h04m and five of
his own IPs were firewall-blocked, because the `asns` rule fired on 5 of 5
distinct ASNs inside a single country — his phone roaming between AT&T pools
plus two rural ILECs. That rule had fired twice in production and been wrong
both times.

Stdlib unittest on purpose — the daemon runs on Python 3.6 and the repo has no
test dependencies. Run from the repo root:

    python3 -m unittest discover -s tests -v
"""

import configparser
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.compromise import CompromiseAction  # noqa: E402


# The real incident's window, for the tests that replay it.
FP_IPS = [
    {'ip': '192.0.2.10', 'asn': 397455},   # Hancock Telephone, NY
    {'ip': '192.0.2.11', 'asn': 400469},    # Claverack Communications, PA
    {'ip': '192.0.2.12', 'asn': 7018},     # AT&T
    {'ip': '192.0.2.13', 'asn': 6389},      # AT&T
    {'ip': '192.0.2.14', 'asn': 11351},       # Charter
]
FP_COUNTS = {'countries': 1, 'asns': 5, 'ips': 5}


class FakeBlocker:
    def __init__(self):
        self.blocks = []

    def block(self, ip, reason, service='', username='', rule='', **kwargs):
        self.blocks.append({'ip': ip, 'rule': rule})
        return True


class FakeMailBackend:
    def __init__(self, enabled=True, fail_on_enable=False):
        self.enabled = enabled
        self.fail_on_enable = fail_on_enable
        self.disabled = []
        self.reenabled = []

    def disable_mailbox(self, email):
        self.disabled.append(email)
        return True

    def enable_mailbox(self, email):
        if self.fail_on_enable:
            raise RuntimeError("mail backend down")
        self.reenabled.append(email)
        return True


class FakeTelegram:
    def __init__(self):
        self.alerts = []
        self.auto_reenabled = []

    def alert_compromise(self, **kwargs):
        self.alerts.append(kwargs)

    def alert_mailbox_auto_reenabled(self, **kwargs):
        self.auto_reenabled.append(kwargs)

    def send(self, msg, priority=''):
        self.alerts.append({'raw': msg})


class FakeDB:
    """Only the methods CompromiseAction actually touches."""

    def __init__(self, observed=None, events=None, guardian_disabled=None):
        self.observed = observed if observed is not None else list(FP_IPS)
        self.events = events or []          # rows for the reaper
        self.guardian_disabled = set(guardian_disabled or [])
        self.mailbox_actions = []
        self.inserted = []
        self.updates = []
        self.reversed_ids = []
        self._next_id = 1

    # --- handle() path ---
    def recent_auth_ips_with_asn(self, username, window_seconds, limit=1000):
        return list(self.observed)

    def recent_auth_countries(self, username, window_seconds):
        return ['US']

    def insert_compromise_event(self, **kwargs):
        event_id = self._next_id
        self._next_id += 1
        self.inserted.append(kwargs)
        return event_id

    def update_compromise_event(self, event_id, updates):
        self.updates.append((event_id, updates))

    def insert_mailbox_action(self, username, action, actor, **kwargs):
        self.mailbox_actions.append({
            'username': username, 'action': action, 'actor': actor,
            'success': kwargs.get('success', True),
        })

    # --- reaper path ---
    def get_auto_reenable_candidates(self, cutoff, limit=50):
        return [e for e in self.events
                if e['detected_at'] <= cutoff and e['id'] not in self.reversed_ids][:limit]

    def is_mailbox_disabled_by_guardian(self, username):
        return username in self.guardian_disabled

    def mark_compromise_auto_reversed(self, event_id, note=''):
        self.reversed_ids.append(event_id)


class FakeCorroborator:
    """Returns a fixed signal list; raises if constructed to."""

    def __init__(self, signals=None, explode=False):
        self.signals = signals or []
        self.explode = explode

    def evaluate(self, username):
        if self.explode:
            raise RuntimeError("corroboration subsystem down")
        return list(self.signals)


def build_action(db=None, mail_backend=None, telegram=None, blocker=None,
                 corroborator=None, **overrides):
    """CompromiseAction wired to fakes. Kwargs override [compromise_detection]."""
    config = configparser.ConfigParser()
    config.add_section('compromise_detection')
    for key, value in overrides.items():
        config.set('compromise_detection', key, str(value))
    return CompromiseAction(
        config,
        db if db is not None else FakeDB(),
        blocker if blocker is not None else FakeBlocker(),
        mail_backend if mail_backend is not None else FakeMailBackend(),
        telegram if telegram is not None else FakeTelegram(),
        corroborator=corroborator,
    )


class TestRuleActionResolution(unittest.TestCase):
    """§5.4 — action_<rule> overrides the global action."""

    def test_asns_defaults_to_alert_only_without_any_config(self):
        # The code default, not just the config default: an existing install
        # gets the protection on git pull + restart.
        action = build_action(action='full')
        self.assertEqual(action.resolve_action('asns'), 'alert_only')

    def test_countries_and_ips_inherit_global_action(self):
        action = build_action(action='full')
        self.assertEqual(action.resolve_action('countries'), 'full')
        self.assertEqual(action.resolve_action('ips'), 'full')

    def test_explicit_config_overrides_the_code_default(self):
        action = build_action(action='full', action_asns='full')
        self.assertEqual(action.resolve_action('asns'), 'full')

    def test_alert_is_accepted_as_an_alias_for_alert_only(self):
        action = build_action(action='full', action_countries='alert')
        self.assertEqual(action.resolve_action('countries'), 'alert_only')

    def test_invalid_value_fails_safe_toward_alert_only(self):
        # Never toward disabling a paying customer's mailbox.
        action = build_action(action='full', action_countries='enable_everything')
        self.assertEqual(action.resolve_action('countries'), 'alert_only')

    def test_invalid_global_action_fails_safe(self):
        action = build_action(action='nonsense')
        self.assertEqual(action.action, 'alert_only')

    def test_unknown_rule_falls_back_to_global_action(self):
        action = build_action(action='block_ips')
        self.assertEqual(action.resolve_action('some_future_rule'), 'block_ips')


class TestHandleEnforcement(unittest.TestCase):
    """The 2026-08-09 incident, replayed."""

    def test_asns_trigger_blocks_nothing_and_disables_nothing(self):
        db, mail, tg, blocker = FakeDB(), FakeMailBackend(), FakeTelegram(), FakeBlocker()
        action = build_action(db=db, mail_backend=mail, telegram=tg,
                              blocker=blocker, action='full')

        action.handle(username='bob@example.net', service='imap',
                      trigger_rule='asns', counts=FP_COUNTS, window_seconds=3600)

        self.assertEqual(mail.disabled, [], "mailbox must stay enabled")
        self.assertEqual(blocker.blocks, [],
                         "the client's own five IPs must not be firewall-blocked")

    def test_asns_trigger_still_records_the_event_and_alerts(self):
        # Weaker enforcement, not weaker visibility.
        db, tg = FakeDB(), FakeTelegram()
        action = build_action(db=db, telegram=tg, action='full')

        event_id = action.handle(username='bob@example.net', service='imap',
                                 trigger_rule='asns', counts=FP_COUNTS,
                                 window_seconds=3600)

        self.assertTrue(event_id)
        self.assertEqual(len(db.inserted), 1)
        self.assertEqual(len(tg.alerts), 1)
        self.assertEqual(tg.alerts[0]['action'], 'alert_only')

    def test_asns_event_records_all_sample_ips_for_forensics(self):
        db = FakeDB()
        action = build_action(db=db, action='full')
        action.handle(username='bob@example.net', service='imap',
                      trigger_rule='asns', counts=FP_COUNTS, window_seconds=3600)
        self.assertEqual(len(db.inserted[0]['sample_ips']), 5)

    def test_countries_trigger_still_enforces_fully(self):
        # Event 1 (alice@example.com): 28 countries / 39 ASNs / 62 IPs.
        db, mail, blocker = FakeDB(), FakeMailBackend(), FakeBlocker()
        action = build_action(db=db, mail_backend=mail, blocker=blocker, action='full')

        action.handle(username='alice@example.com', service='imap',
                      trigger_rule='countries',
                      counts={'countries': 28, 'asns': 39, 'ips': 62},
                      window_seconds=3600)

        self.assertEqual(mail.disabled, ['alice@example.com'])
        self.assertEqual(len(blocker.blocks), 5)

    def test_operator_can_re_arm_the_asns_rule(self):
        db, mail = FakeDB(), FakeMailBackend()
        action = build_action(db=db, mail_backend=mail, action='full', action_asns='full')
        action.handle(username='bob@example.net', service='imap',
                      trigger_rule='asns', counts=FP_COUNTS, window_seconds=3600)
        self.assertEqual(mail.disabled, ['bob@example.net'])


class TestCorroboration(unittest.TestCase):
    """Abuse evidence promotes a weak rule; its absence can gate a strong one."""

    SIEVE = ['sieve rule created/modified 3h ago']

    def test_corroboration_promotes_the_muted_asns_rule(self):
        # 5 ASNs alone is a travelling client. 5 ASNs plus a sieve rule
        # planted yesterday is a takeover, and the rule must not stay muted.
        db, mail, blocker = FakeDB(), FakeMailBackend(), FakeBlocker()
        action = build_action(db=db, mail_backend=mail, blocker=blocker,
                              action='full',
                              corroborator=FakeCorroborator(self.SIEVE))

        action.handle(username='bob@example.net', service='imap',
                      trigger_rule='asns', counts=FP_COUNTS, window_seconds=3600)

        self.assertEqual(mail.disabled, ['bob@example.net'])
        self.assertEqual(len(blocker.blocks), 5)

    def test_no_corroboration_leaves_asns_muted(self):
        db, mail, blocker = FakeDB(), FakeMailBackend(), FakeBlocker()
        action = build_action(db=db, mail_backend=mail, blocker=blocker,
                              action='full',
                              corroborator=FakeCorroborator([]))

        action.handle(username='bob@example.net', service='imap',
                      trigger_rule='asns', counts=FP_COUNTS, window_seconds=3600)

        self.assertEqual(mail.disabled, [])
        self.assertEqual(blocker.blocks, [])

    def test_promotion_target_is_configurable(self):
        db, mail, blocker = FakeDB(), FakeMailBackend(), FakeBlocker()
        action = build_action(db=db, mail_backend=mail, blocker=blocker,
                              action='full', corroborated_action='block_ips',
                              corroborator=FakeCorroborator(self.SIEVE))

        action.handle(username='bob@example.net', service='imap',
                      trigger_rule='asns', counts=FP_COUNTS, window_seconds=3600)

        self.assertEqual(mail.disabled, [], "block_ips must not disable")
        self.assertEqual(len(blocker.blocks), 5)

    def test_corroboration_never_weakens_a_rule(self):
        # A rule already at full stays at full even if corroborated_action
        # is set lower — promotion only ever moves upward.
        db, mail = FakeDB(), FakeMailBackend()
        action = build_action(db=db, mail_backend=mail, action='full',
                              corroborated_action='alert_only',
                              corroborator=FakeCorroborator(self.SIEVE))

        action.handle(username='alice@example.com', service='imap',
                      trigger_rule='countries',
                      counts={'countries': 28, 'asns': 39, 'ips': 62},
                      window_seconds=3600)

        self.assertEqual(mail.disabled, ['alice@example.com'])

    def test_require_corroboration_gates_the_disable(self):
        db, mail, blocker = FakeDB(), FakeMailBackend(), FakeBlocker()
        action = build_action(db=db, mail_backend=mail, blocker=blocker,
                              action='full', require_corroboration='true',
                              corroborator=FakeCorroborator([]))

        action.handle(username='erin@example.com', service='imap',
                      trigger_rule='countries',
                      counts={'countries': 6, 'asns': 6, 'ips': 8},
                      window_seconds=3600)

        self.assertEqual(mail.disabled, [], "no evidence, no disable")
        self.assertEqual(len(blocker.blocks), 5, "IPs are still blocked")

    def test_require_corroboration_is_off_by_default(self):
        # Gating would weaken `countries`, the one rule that has ever been
        # right. Operators opt in; it is not the shipped default.
        db, mail = FakeDB(), FakeMailBackend()
        action = build_action(db=db, mail_backend=mail, action='full',
                              corroborator=FakeCorroborator([]))
        self.assertFalse(action.require_corroboration)

        action.handle(username='alice@example.com', service='imap',
                      trigger_rule='countries',
                      counts={'countries': 28, 'asns': 39, 'ips': 62},
                      window_seconds=3600)
        self.assertEqual(mail.disabled, ['alice@example.com'])

    def test_broken_corroborator_does_not_promote(self):
        db, mail = FakeDB(), FakeMailBackend()
        action = build_action(db=db, mail_backend=mail, action='full',
                              corroborator=FakeCorroborator(explode=True))

        action.handle(username='bob@example.net', service='imap',
                      trigger_rule='asns', counts=FP_COUNTS, window_seconds=3600)

        self.assertEqual(mail.disabled, [], "an exception must not authorise a disable")

    def test_absent_corroborator_preserves_v1_7_11_behaviour(self):
        db, mail = FakeDB(), FakeMailBackend()
        action = build_action(db=db, mail_backend=mail, action='full',
                              corroborator=None)
        action.handle(username='bob@example.net', service='imap',
                      trigger_rule='asns', counts=FP_COUNTS, window_seconds=3600)
        self.assertEqual(mail.disabled, [])

    def test_signals_are_recorded_on_the_event(self):
        db, tg = FakeDB(), FakeTelegram()
        action = build_action(db=db, telegram=tg,
                              corroborator=FakeCorroborator(self.SIEVE))
        action.handle(username='bob@example.net', service='imap',
                      trigger_rule='asns', counts=FP_COUNTS, window_seconds=3600)

        self.assertIn('sieve', db.inserted[0]['notes'])
        self.assertEqual(tg.alerts[0]['corroboration'], self.SIEVE)

    def test_absence_is_recorded_too(self):
        db = FakeDB()
        action = build_action(db=db, corroborator=FakeCorroborator([]))
        action.handle(username='bob@example.net', service='imap',
                      trigger_rule='asns', counts=FP_COUNTS, window_seconds=3600)
        self.assertIn('none', db.inserted[0]['notes'])


class TestAutoReenableReaper(unittest.TestCase):
    """Provisional disables — bounding the outage from a detection error."""

    def _event(self, event_id=1, username='bob@example.net', age_hours=5):
        return {
            'id': event_id,
            'username': username,
            'service': 'imap',
            'trigger_rule': 'asns',
            'detected_at': int(time.time()) - age_hours * 3600,
        }

    def test_restores_a_mailbox_past_the_window(self):
        user = 'bob@example.net'
        db = FakeDB(events=[self._event(age_hours=5)], guardian_disabled=[user])
        mail, tg = FakeMailBackend(), FakeTelegram()
        action = build_action(db=db, mail_backend=mail, telegram=tg, auto_reenable_hours=4)

        result = action.reap_auto_disabled_mailboxes()

        self.assertEqual(mail.reenabled, [user])
        self.assertEqual(result['restored'], 1)
        self.assertEqual(len(tg.auto_reenabled), 1)

    def test_leaves_a_mailbox_inside_the_window_alone(self):
        user = 'bob@example.net'
        db = FakeDB(events=[self._event(age_hours=1)], guardian_disabled=[user])
        mail = FakeMailBackend()
        action = build_action(db=db, mail_backend=mail, auto_reenable_hours=4)

        result = action.reap_auto_disabled_mailboxes()

        self.assertEqual(mail.reenabled, [])
        self.assertEqual(result['restored'], 0)

    def test_zero_hours_disables_the_reaper_entirely(self):
        user = 'bob@example.net'
        db = FakeDB(events=[self._event(age_hours=99)], guardian_disabled=[user])
        mail = FakeMailBackend()
        action = build_action(db=db, mail_backend=mail, auto_reenable_hours=0)

        result = action.reap_auto_disabled_mailboxes()

        self.assertEqual(mail.reenabled, [])
        self.assertEqual(result, {'restored': 0, 'failed': 0, 'skipped': 0, 'remaining': 0})

    def test_skips_a_mailbox_the_operator_already_restored(self):
        # guardian_disabled is empty => operator ran /enable first.
        db = FakeDB(events=[self._event(age_hours=20)], guardian_disabled=[])
        mail = FakeMailBackend()
        action = build_action(db=db, mail_backend=mail, auto_reenable_hours=4)

        result = action.reap_auto_disabled_mailboxes()

        self.assertEqual(mail.reenabled, [])
        self.assertEqual(result['skipped'], 1)
        self.assertIn(1, db.reversed_ids, "must be stamped so it stops recurring")

    def test_dry_run_changes_nothing(self):
        user = 'bob@example.net'
        db = FakeDB(events=[self._event(age_hours=5)], guardian_disabled=[user])
        mail = FakeMailBackend()
        action = build_action(db=db, mail_backend=mail, auto_reenable_hours=4)

        result = action.reap_auto_disabled_mailboxes(dry_run=True)

        self.assertEqual(mail.reenabled, [])
        self.assertEqual(db.reversed_ids, [])
        self.assertEqual(result['restored'], 1)

    def test_backend_failure_leaves_the_event_unstamped_for_retry(self):
        # A mail-backend outage must not silently strand a disabled mailbox.
        user = 'bob@example.net'
        db = FakeDB(events=[self._event(age_hours=5)], guardian_disabled=[user])
        mail = FakeMailBackend(fail_on_enable=True)
        action = build_action(db=db, mail_backend=mail, auto_reenable_hours=4)

        result = action.reap_auto_disabled_mailboxes()

        self.assertEqual(result['failed'], 1)
        self.assertEqual(db.reversed_ids, [], "must retry on the next sweep")
        self.assertTrue(any(a['action'] == 'enable' and not a['success']
                            for a in db.mailbox_actions))

    def test_no_op_when_mail_backend_is_unavailable(self):
        user = 'bob@example.net'
        db = FakeDB(events=[self._event(age_hours=5)], guardian_disabled=[user])
        action = build_action(db=db, mail_backend=FakeMailBackend(enabled=False),
                              auto_reenable_hours=4)

        result = action.reap_auto_disabled_mailboxes()

        self.assertEqual(result['restored'], 0)
        self.assertEqual(db.reversed_ids, [])

    def test_batch_limit_caps_one_sweep(self):
        users = ['a@x.com', 'b@x.com', 'c@x.com']
        events = [self._event(event_id=i + 1, username=u, age_hours=9)
                  for i, u in enumerate(users)]
        db = FakeDB(events=events, guardian_disabled=users)
        mail = FakeMailBackend()
        action = build_action(db=db, mail_backend=mail, auto_reenable_hours=4,
                              auto_reenable_batch_limit=2)

        result = action.reap_auto_disabled_mailboxes()

        self.assertEqual(result['restored'], 2)
        self.assertEqual(result['remaining'], 1)


if __name__ == '__main__':
    unittest.main()
