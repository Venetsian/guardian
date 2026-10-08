"""Telegram commands: authorise the sender, not just the chat; honour dry-run.

TelegramCommander used to check only message.chat.id == chat_id. In a group
chat that id is shared by every member, so any member could run /block,
/unblock, /disable, /whitelist ... Now [telegram] allowed_user_ids names who may
command, and without it only a private chat is accepted.

Also covered: /unblock, /whitelist, /disable, /enable and /confirm under the
global dry-run flag, and /unblock reporting a failed firewall call honestly.

Stdlib unittest on purpose. Run from the repo root:

    python3 -m unittest discover -s tests -v
"""

import configparser
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from actions.telegram_commands import HAS_REQUESTS, TelegramCommander  # noqa: E402

PRIVATE_CHAT = 12345        # a private chat id is the user's own id
GROUP_CHAT = -1001234567890
ALICE = 111222333           # operator, listed
BOB = 444555666             # another group member, not listed


class FakeBlocker(object):
    def __init__(self, dry_run=False, unblock_result=True, unblock_raises=None):
        self.dry_run = dry_run
        self.unblock_result = unblock_result
        self.unblock_raises = unblock_raises
        self.unblocked = []

    def unblock(self, ip):
        self.unblocked.append(ip)
        if self.unblock_raises is not None:
            raise self.unblock_raises
        return self.unblock_result


class FakeMail(object):
    enabled = True

    def __init__(self):
        self.disabled = []
        self.enabled_calls = []

    def disable_mailbox(self, email):
        self.disabled.append(email)
        return True

    def enable_mailbox(self, email):
        self.enabled_calls.append(email)
        return True


class FakeWhitelist(object):
    def __init__(self):
        self.added = []

    def add(self, ip, **kwargs):
        self.added.append(ip)


class FakeDB(object):
    def __init__(self, tier=2, event=None):
        self.tier = tier
        self.event = event
        self.mailbox_actions = []
        self.confirmed = []

    def get_ip(self, ip):
        return {'current_tier': self.tier}

    def insert_mailbox_action(self, username, action, actor, **kwargs):
        self.mailbox_actions.append((username, action))

    def get_compromise_event(self, event_id):
        return self.event

    def confirm_compromise_event(self, event_id, confirmed_by='', note=''):
        self.confirmed.append(event_id)


def make_commander(chat_id=PRIVATE_CHAT, allowed='', blocker=None, db=None,
                   mail=None, whitelist=None):
    config = configparser.ConfigParser()
    config.add_section('telegram')
    config.set('telegram', 'commands_enabled', 'true')
    config.set('telegram', 'bot_token', 'test-token')
    config.set('telegram', 'chat_id', str(chat_id))
    config.set('telegram', 'allowed_user_ids', allowed)
    commander = TelegramCommander(
        config, db or FakeDB(), blocker or FakeBlocker(),
        whitelist or FakeWhitelist(), mail_backend=mail,
    )
    commander.replies = []
    commander.dispatched = []
    commander._reply = commander.replies.append     # never touch the network
    commander._dispatch_command = lambda text, chat: commander.dispatched.append(text)
    return commander


def update(text='/status', chat_id=PRIVATE_CHAT, chat_type='private',
           from_id=PRIVATE_CHAT, sender_chat=None, update_id=1):
    message = {'chat': {'id': chat_id, 'type': chat_type}, 'text': text}
    if from_id is not None:
        message['from'] = {'id': from_id}
    if sender_chat is not None:
        message['sender_chat'] = {'id': sender_chat}
    return {'update_id': update_id, 'message': message}


class TestSenderAuthorisation(unittest.TestCase):
    def test_private_chat_is_accepted_without_an_allowlist(self):
        c = make_commander(chat_id=PRIVATE_CHAT)
        c._process_update(update('/status'))
        self.assertEqual(c.dispatched, ['/status'])
        self.assertEqual(c.replies, [])

    def test_group_without_allowlist_is_refused_with_one_reply_only(self):
        c = make_commander(chat_id=GROUP_CHAT)
        c._process_update(update('/block 192.0.2.5', GROUP_CHAT, 'group', ALICE, update_id=1))
        c._process_update(update('/status', GROUP_CHAT, 'supergroup', BOB, update_id=2))
        c._process_update(update('/status', GROUP_CHAT, 'group', ALICE, update_id=3))

        self.assertEqual(c.dispatched, [])
        self.assertEqual(len(c.replies), 1, "explain once per process, not per message")
        self.assertIn('allowed_user_ids', c.replies[0])

    def test_non_text_group_traffic_does_not_trigger_the_explanation(self):
        c = make_commander(chat_id=GROUP_CHAT)
        joined = update('', GROUP_CHAT, 'group', BOB)
        c._process_update(joined)
        self.assertEqual(c.replies, [])

    def test_group_with_allowlist_accepts_a_listed_user(self):
        c = make_commander(chat_id=GROUP_CHAT, allowed=str(ALICE))
        c._process_update(update('/status', GROUP_CHAT, 'supergroup', ALICE))
        self.assertEqual(c.dispatched, ['/status'])

    def test_group_with_allowlist_rejects_everyone_else_silently(self):
        c = make_commander(chat_id=GROUP_CHAT, allowed=str(ALICE))
        c._process_update(update('/unblock 192.0.2.5', GROUP_CHAT, 'supergroup', BOB))
        self.assertEqual(c.dispatched, [])
        self.assertEqual(c.replies, [], "no reply: do not advertise the bot to members")

    def test_allowlist_accepts_comma_and_space_separated_ids(self):
        c = make_commander(chat_id=GROUP_CHAT, allowed='%d, %d' % (BOB, ALICE))
        c._process_update(update('/status', GROUP_CHAT, 'group', BOB, update_id=1))
        c._process_update(update('/status', GROUP_CHAT, 'group', ALICE, update_id=2))
        self.assertEqual(len(c.dispatched), 2)

    def test_allowlist_applies_in_a_private_chat_too(self):
        c = make_commander(chat_id=PRIVATE_CHAT, allowed=str(ALICE))
        c._process_update(update('/status', PRIVATE_CHAT, 'private', PRIVATE_CHAT))
        self.assertEqual(c.dispatched, [], "an explicit allowlist is authoritative")

    def test_sender_chat_is_rejected(self):
        # Anonymous group admins and channel identities have no user id.
        for allowed in ('', str(ALICE)):
            c = make_commander(chat_id=GROUP_CHAT, allowed=allowed)
            c._process_update(update('/status', GROUP_CHAT, 'supergroup', ALICE,
                                     sender_chat=GROUP_CHAT))
            self.assertEqual(c.dispatched, [])
            self.assertEqual(c.replies, [])

    def test_sender_chat_is_rejected_even_in_a_private_chat(self):
        c = make_commander(chat_id=PRIVATE_CHAT)
        c._process_update(update('/status', sender_chat=-100999))
        self.assertEqual(c.dispatched, [])

    def test_wrong_chat_is_rejected_even_for_a_listed_user(self):
        c = make_commander(chat_id=GROUP_CHAT, allowed=str(ALICE))
        c._process_update(update('/status', -100777, 'supergroup', ALICE))
        self.assertEqual(c.dispatched, [])
        self.assertEqual(c.replies, [])

    def test_missing_sender_is_rejected_when_an_allowlist_is_set(self):
        c = make_commander(chat_id=GROUP_CHAT, allowed=str(ALICE))
        c._process_update(update('/status', GROUP_CHAT, 'supergroup', from_id=None))
        self.assertEqual(c.dispatched, [])

    def test_update_offset_still_advances_for_refused_messages(self):
        c = make_commander(chat_id=GROUP_CHAT)
        c._process_update(update('/status', GROUP_CHAT, 'group', BOB, update_id=41))
        self.assertEqual(c._offset, 42)


class TestAllowedUserIdsParsing(unittest.TestCase):
    def test_parses_commas_spaces_newlines_and_comments(self):
        ids = TelegramCommander._parse_user_ids(
            "111, 222 333\n  444   # the operator\n# whole-line comment\n")
        self.assertEqual(ids, {'111', '222', '333', '444'})

    def test_invalid_entries_are_ignored_not_matched_loosely(self):
        with self.assertLogs('wp-guardian.telegram-cmd', level='WARNING'):
            ids = TelegramCommander._parse_user_ids("111, @alice, -100123, 12abc")
        self.assertEqual(ids, {'111'})

    def test_empty_is_an_empty_set(self):
        self.assertEqual(TelegramCommander._parse_user_ids(''), set())
        self.assertEqual(TelegramCommander._parse_user_ids(None), set())

    @unittest.skipUnless(HAS_REQUESTS, "commands need the requests module")
    def test_group_chat_id_without_allowlist_warns_at_startup(self):
        with self.assertLogs('wp-guardian.telegram-cmd', level='WARNING') as cm:
            make_commander(chat_id=GROUP_CHAT)
        self.assertTrue(any('allowed_user_ids' in r.getMessage() for r in cm.records))


class TestUnblockCommandIsHonest(unittest.TestCase):
    IP = '192.0.2.50'

    def test_failed_unblock_is_not_reported_as_success(self):
        c = make_commander(blocker=FakeBlocker(unblock_result=False))
        c._cmd_unblock([self.IP])
        self.assertEqual(len(c.replies), 1)
        self.assertIn('Failed to unblock', c.replies[0])
        self.assertNotIn('Unblocked', c.replies[0])

    def test_raising_unblock_is_reported_as_failure(self):
        c = make_commander(blocker=FakeBlocker(unblock_raises=RuntimeError('ssh down')))
        c._cmd_unblock([self.IP])
        self.assertIn('Failed to unblock', c.replies[0])

    def test_successful_unblock(self):
        c = make_commander()
        c._cmd_unblock([self.IP])
        self.assertTrue(c.replies[0].startswith('Unblocked'))

    def test_dry_run_unblock_is_marked(self):
        blocker = FakeBlocker(dry_run=True)
        c = make_commander(blocker=blocker)
        c._cmd_unblock([self.IP])
        self.assertIn('[DRY-RUN]', c.replies[0])
        self.assertNotIn('Unblocked', c.replies[0])

    def test_whitelist_flags_a_block_it_could_not_remove(self):
        whitelist = FakeWhitelist()
        c = make_commander(blocker=FakeBlocker(unblock_result=False), whitelist=whitelist)
        c._cmd_whitelist([self.IP])
        self.assertEqual(whitelist.added, [self.IP], "whitelisting itself still happens")
        self.assertIn('Whitelisted', c.replies[0])
        self.assertIn('Could NOT remove', c.replies[0])
        self.assertNotIn('Also unblocked', c.replies[0])

    def test_whitelist_reports_a_real_unblock(self):
        c = make_commander()
        c._cmd_whitelist([self.IP])
        self.assertIn('Also unblocked', c.replies[0])

    def test_whitelist_in_dry_run_says_it_would_unblock(self):
        c = make_commander(blocker=FakeBlocker(dry_run=True))
        c._cmd_whitelist([self.IP])
        self.assertIn('[DRY-RUN] Would also unblock', c.replies[0])
        self.assertNotIn('Also unblocked', c.replies[0])


class HistoryDB(FakeDB):
    def get_ip(self, ip):
        return {'current_tier': 0, 'first_seen': 1700000000, 'last_seen': 1700000100,
                'total_hits': 3, 'block_count': 0, 'geoip_country': '',
                'geoip_city': '', 'last_block_reason': ''}

    def get_block_history(self, ip):
        return [
            {'timestamp': 1700000050, 'tier': 1, 'service': 'web',
             'reason': 'Tripwire: /alfa.php', 'blocker': 'dry-run'},
            {'timestamp': 1700000010, 'tier': 1, 'service': 'web',
             'reason': 'Tripwire: /c99.php', 'blocker': 'firewalld'},
        ]


class TestHistoryLabelsSimulatedBlocks(unittest.TestCase):
    def test_dry_run_rows_are_marked_in_history(self):
        c = make_commander(db=HistoryDB())
        c._cmd_history(['192.0.2.50'])
        lines = [l for l in c.replies[0].splitlines() if 'Tripwire' in l]
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].endswith('[dry-run]'))
        self.assertFalse(lines[1].endswith('[dry-run]'))


class TestMailboxCommandsUnderDryRun(unittest.TestCase):
    USER = 'alice@example.com'

    def test_disable_in_dry_run_never_calls_the_mail_backend(self):
        mail, db = FakeMail(), FakeDB()
        c = make_commander(blocker=FakeBlocker(dry_run=True), mail=mail, db=db)
        c._cmd_disable([self.USER, 'phished'])
        self.assertEqual(mail.disabled, [])
        self.assertEqual(db.mailbox_actions, [], "no audit row for a simulated disable")
        self.assertIn('[DRY-RUN] Would disable', c.replies[0])

    def test_enable_in_dry_run_never_calls_the_mail_backend(self):
        mail, db = FakeMail(), FakeDB()
        c = make_commander(blocker=FakeBlocker(dry_run=True), mail=mail, db=db)
        c._cmd_enable([self.USER])
        self.assertEqual(mail.enabled_calls, [])
        self.assertEqual(db.mailbox_actions, [])
        self.assertIn('[DRY-RUN] Would enable', c.replies[0])

    def test_confirm_in_dry_run_does_not_re_disable(self):
        event = {'username': self.USER, 'confirmed_at': 0,
                 'auto_reversed_at': 1, 'mailbox_disabled': 1}
        mail, db = FakeMail(), FakeDB(event=event)
        c = make_commander(blocker=FakeBlocker(dry_run=True), mail=mail, db=db)
        c._cmd_confirm(['7'])
        self.assertEqual(mail.disabled, [])
        self.assertEqual(db.mailbox_actions, [])
        self.assertIn('[DRY-RUN] Would re-disable', c.replies[0])

    def test_live_disable_and_enable_still_work(self):
        mail, db = FakeMail(), FakeDB()
        c = make_commander(blocker=FakeBlocker(dry_run=False), mail=mail, db=db)
        c._cmd_disable([self.USER])
        c._cmd_enable([self.USER])
        self.assertEqual(mail.disabled, [self.USER])
        self.assertEqual(mail.enabled_calls, [self.USER])
        self.assertEqual(db.mailbox_actions, [(self.USER, 'disable'), (self.USER, 'enable')])

    def test_live_confirm_still_re_disables(self):
        event = {'username': self.USER, 'confirmed_at': 0,
                 'auto_reversed_at': 1, 'mailbox_disabled': 1}
        mail, db = FakeMail(), FakeDB(event=event)
        c = make_commander(blocker=FakeBlocker(dry_run=False), mail=mail, db=db)
        c._cmd_confirm(['7'])
        self.assertEqual(mail.disabled, [self.USER])

    def test_flag_is_read_per_command(self):
        blocker, mail = FakeBlocker(dry_run=True), FakeMail()
        c = make_commander(blocker=blocker, mail=mail)
        c._cmd_disable([self.USER])
        blocker.dry_run = False
        c._cmd_disable([self.USER])
        self.assertEqual(mail.disabled, [self.USER])


if __name__ == '__main__':
    unittest.main()
