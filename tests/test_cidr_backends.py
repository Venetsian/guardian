"""Backend side of the subnet block lifecycle (v1.7.19): unblock_cidr() and
list_cidr_entries().

The backends are built without __init__ (it would need firewalld, a router, nft,
csf or a pfSense API) and their command runners are replaced by recorders, so
what is asserted is the exact command each backend issues and how it reads the
answer. RFC 5737 addresses only.

Stdlib unittest on purpose. Run from the repo root:

    python3 -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backends.base import FirewallBackend  # noqa: E402
from backends.csf import CSFBackend  # noqa: E402
from backends.firewalld import FirewalldBackend, IPSET_CIDR  # noqa: E402
from backends.mikrotik import MikroTikBackend  # noqa: E402
from backends.nftables import NftablesBackend  # noqa: E402
from backends.pfsense import PfSenseBackend  # noqa: E402

SUBNET = '198.51.100.0/24'


class Minimal(FirewallBackend):
    """The smallest concrete backend: only what the ABC demands."""

    def block(self, ip, tier, reason, service='web'):
        return True

    def unblock(self, ip):
        return True

    def test_connection(self):
        return True


class TestBaseDefaults(unittest.TestCase):
    def test_unblock_cidr_defaults_to_failure(self):
        self.assertFalse(Minimal().unblock_cidr(SUBNET))

    def test_listing_defaults_to_unsupported_not_empty(self):
        self.assertIsNone(Minimal().list_cidr_entries())

    def test_self_expiry_flags_are_what_the_reaper_assumes(self):
        # expires_own_entries now also governs block_cidr(): the CIDR reaper
        # skips unblock_cidr() on True backends.
        self.assertFalse(Minimal.expires_own_entries)
        self.assertFalse(FirewalldBackend.expires_own_entries)
        self.assertFalse(PfSenseBackend.expires_own_entries)
        self.assertTrue(MikroTikBackend.expires_own_entries)
        self.assertTrue(NftablesBackend.expires_own_entries)
        self.assertTrue(CSFBackend.expires_own_entries)

    def test_the_docstring_says_it_covers_block_cidr(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'backends', 'base.py')
        with open(path, encoding='utf-8') as handle:
            source = handle.read()
        end = source.index('expires_own_entries = False')
        self.assertIn('block_cidr', source[end - 1500:end])


class FirewalldRecorder(FirewalldBackend):
    def __init__(self, answers):
        self.calls = []
        self.answers = answers          # callable(args) -> (ok, out, err)

    def _run_cmd(self, args, timeout=15):
        self.calls.append(args)
        return self.answers(args)


class TestFirewalld(unittest.TestCase):
    def test_unblock_cidr_removes_from_runtime_and_permanent(self):
        fw = FirewalldRecorder(lambda args: (True, 'success', ''))

        self.assertTrue(fw.unblock_cidr(SUBNET))

        self.assertEqual(fw.calls, [
            ['--ipset={}'.format(IPSET_CIDR), '--remove-entry={}'.format(SUBNET)],
            ['--permanent', '--ipset={}'.format(IPSET_CIDR), '--remove-entry={}'.format(SUBNET)],
        ])

    def test_unblock_cidr_is_idempotent(self):
        fw = FirewalldRecorder(lambda args: (False, '', 'Error: NOT_ENABLED: 198.51.100.0/24'))
        self.assertTrue(fw.unblock_cidr(SUBNET))

    def test_unblock_cidr_fails_when_the_runtime_removal_fails(self):
        fw = FirewalldRecorder(lambda args: (False, '', 'Error: INVALID_IPSET: wp_guardian_cidr'))
        self.assertFalse(fw.unblock_cidr(SUBNET))
        self.assertEqual(len(fw.calls), 1, "the permanent leg is not attempted")

    def test_list_cidr_entries_reads_the_permanent_config(self):
        fw = FirewalldRecorder(lambda args: (True, '198.51.100.0/24\n203.0.113.0/24\n', ''))

        entries = fw.list_cidr_entries()

        self.assertEqual(entries, {'198.51.100.0/24', '203.0.113.0/24'})
        self.assertEqual(fw.calls, [['--permanent', '--ipset={}'.format(IPSET_CIDR),
                                     '--get-entries']])

    def test_an_empty_set_is_an_empty_answer(self):
        fw = FirewalldRecorder(lambda args: (True, '', ''))
        self.assertEqual(fw.list_cidr_entries(), set())

    def test_a_failed_listing_raises_it_is_never_an_empty_set(self):
        fw = FirewalldRecorder(lambda args: (False, '', 'timeout'))
        with self.assertRaises(RuntimeError):
            fw.list_cidr_entries()


class MikroTikRecorder(MikroTikBackend):
    def __init__(self, answer):
        self.list_cidr = 'wp-block-cidr'
        self.commands = []
        self.answer = answer

    def _ssh_command(self, command, timeout=10):
        self.commands.append(command)
        return self.answer


class TestMikroTik(unittest.TestCase):
    def test_the_command_removes_only_this_subnet_from_the_cidr_list(self):
        fw = MikroTikRecorder('')
        self.assertTrue(fw.unblock_cidr(SUBNET))
        self.assertEqual(fw.commands, [
            '/ip firewall address-list remove '
            '[find where list="wp-block-cidr" address="198.51.100.0/24"]'])

    def test_nothing_to_remove_is_still_success(self):
        # RouterOS exits 0 with no output when [find] matches nothing.
        self.assertTrue(MikroTikRecorder('').unblock_cidr(SUBNET))

    def test_an_ssh_failure_is_a_failure(self):
        self.assertFalse(MikroTikRecorder(None).unblock_cidr(SUBNET))


class NftRecorder(NftablesBackend):
    def __init__(self, answer):
        self.calls = []
        self.answer = answer

    def _run_nft(self, args, timeout=10):
        self.calls.append(list(args))
        return self.answer


class TestNftables(unittest.TestCase):
    def test_deletes_the_element_from_the_cidr_set(self):
        fw = NftRecorder((True, '', ''))
        self.assertTrue(fw.unblock_cidr(SUBNET))
        self.assertEqual(fw.calls, [['delete', 'element', 'inet', 'wp_guardian',
                                     'blocked_nets', '{ 198.51.100.0/24 }']])

    def test_no_such_element_is_success(self):
        for message in ('Error: Could not process rule: No such file or directory',
                        'Error: element not found'):
            self.assertTrue(NftRecorder((False, '', message)).unblock_cidr(SUBNET), message)

    def test_any_other_error_is_a_failure(self):
        self.assertFalse(NftRecorder((False, '', 'Operation not permitted')).unblock_cidr(SUBNET))


class CsfRecorder(CSFBackend):
    def __init__(self, answers):
        self.calls = []
        self.answers = answers          # {first arg: (ok, out, err)}

    def _run_csf(self, args, timeout=15):
        self.calls.append(args)
        return self.answers.get(args[0], (False, '', 'unexpected'))


class TestCsf(unittest.TestCase):
    def test_removes_the_permanent_and_the_temporary_deny(self):
        fw = CsfRecorder({'-dr': (True, '', ''), '-tr': (True, '', '')})
        self.assertTrue(fw.unblock_cidr(SUBNET))
        self.assertEqual(fw.calls, [['-dr', SUBNET], ['-tr', SUBNET]])

    def test_a_temp_ban_that_already_expired_is_success_once_csf_confirms(self):
        fw = CsfRecorder({'-dr': (False, '', 'not found'), '-tr': (False, '', 'not found'),
                          '-g': (True, 'No matches found for 198.51.100.0/24', '')})
        self.assertTrue(fw.unblock_cidr(SUBNET))
        self.assertEqual([c[0] for c in fw.calls], ['-dr', '-tr', '-g'])

    def test_a_removal_that_failed_while_the_deny_is_still_there_is_a_failure(self):
        fw = CsfRecorder({'-dr': (False, '', 'x'), '-tr': (False, '', 'x'),
                          '-g': (True, 'Chain DENYIN  DROP  198.51.100.0/24', '')})
        self.assertFalse(fw.unblock_cidr(SUBNET))

    def test_a_csf_that_cannot_run_is_a_failure(self):
        fw = CsfRecorder({})
        self.assertFalse(fw.unblock_cidr(SUBNET))

    def test_ip_unblock_is_unchanged(self):
        fw = CsfRecorder({'-dr': (True, '', ''), '-tr': (False, '', '')})
        self.assertTrue(fw.unblock('198.51.100.9'))
        self.assertEqual(fw.calls, [['-dr', '198.51.100.9'], ['-tr', '198.51.100.9']])


class PfRecorder(PfSenseBackend):
    def __init__(self, removal_ok, tracked=()):
        self.platform = 'pfsense'
        self.alias_cidr = 'wp_guardian_cidr'
        self._blocked_cidrs = set(tracked)
        self.removed = []
        self.removal_ok = removal_ok

    def _remove_from_alias(self, alias, address):
        self.removed.append((alias, address))
        return self.removal_ok


class TestPfSense(unittest.TestCase):
    def test_removes_from_the_cidr_alias_and_forgets_it(self):
        fw = PfRecorder(True, tracked=[SUBNET])
        self.assertTrue(fw.unblock_cidr(SUBNET))
        self.assertEqual(fw.removed, [('wp_guardian_cidr', SUBNET)])
        self.assertFalse(fw.is_cidr_blocked(SUBNET))

    def test_an_entry_the_alias_never_had_is_already_gone(self):
        # The reaper retries until success: an API error for an absent entry
        # must not wedge it forever.
        fw = PfRecorder(False, tracked=[])
        self.assertTrue(fw.unblock_cidr(SUBNET))

    def test_a_tracked_entry_the_api_refuses_to_remove_is_a_failure(self):
        fw = PfRecorder(False, tracked=[SUBNET])
        self.assertFalse(fw.unblock_cidr(SUBNET))
        self.assertTrue(fw.is_cidr_blocked(SUBNET), "still tracked: retried next sweep")


if __name__ == '__main__':
    unittest.main()
