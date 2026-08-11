"""Tests for mail-schema auto-detection (v1.7.12+).

The query forms below are real: the `virtual_aliases` set was read off
mail.maiahost.com on 2026-08-11, the others are the documented layouts for
their stacks. Detection has to work across all of them or the feature is
just our own setup with extra steps.

Stdlib unittest — the daemon runs on Python 3.6 and the repo has no test
dependencies. Run from the repo root:

    python3 -m unittest discover -s tests -v
"""

import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import mail_schema  # noqa: E402


class TestSelectColumnReduction(unittest.TestCase):
    def test_plain_column(self):
        self.assertEqual(mail_schema._first_select_column('destination'), 'destination')

    def test_backticked(self):
        self.assertEqual(mail_schema._first_select_column('`goto`'), 'goto')

    def test_aliased_and_multi(self):
        self.assertEqual(
            mail_schema._first_select_column('email as user, password'), 'email')

    def test_table_qualified(self):
        self.assertEqual(mail_schema._first_select_column('a.destination'), 'destination')

    def test_literal_is_rejected(self):
        # Postfix's mailbox map is an existence probe: SELECT 1 FROM ...
        # \w matches digits, so this needs an explicit guard.
        self.assertEqual(mail_schema._first_select_column('1'), '')

    def test_star_is_rejected(self):
        self.assertEqual(mail_schema._first_select_column('*'), '')

    def test_expression_is_rejected(self):
        self.assertEqual(
            mail_schema._first_select_column("CONCAT('*:bytes=', quota)"), '')


class TestSqlParsing(unittest.TestCase):
    def test_postfix_dovecot_mysql_alias(self):
        # Verified on mail.maiahost.com 2026-08-11.
        parsed, problem = mail_schema._parse_sql(
            "SELECT destination FROM virtual_aliases WHERE source='%s' AND enabled=1")
        self.assertEqual(problem, '')
        self.assertEqual(parsed['table'], 'virtual_aliases')
        self.assertEqual(parsed['select_column'], 'destination')
        self.assertEqual(parsed['where_column'], 'source')
        self.assertEqual(parsed['enabled_column'], 'enabled')

    def test_postfixadmin_alias(self):
        parsed, problem = mail_schema._parse_sql(
            "SELECT goto FROM alias WHERE address='%s' AND active='1'")
        self.assertEqual(problem, '')
        self.assertEqual(parsed['table'], 'alias')
        self.assertEqual(parsed['select_column'], 'goto')
        self.assertEqual(parsed['where_column'], 'address')
        self.assertEqual(parsed['enabled_column'], 'active')

    def test_dovecot_password_query(self):
        parsed, problem = mail_schema._parse_sql(
            "SELECT email as user, password FROM virtual_users "
            "WHERE email='%u' AND enabled=1")
        self.assertEqual(problem, '')
        self.assertEqual(parsed['table'], 'virtual_users')
        self.assertEqual(parsed['where_column'], 'email')
        self.assertEqual(parsed['enabled_column'], 'enabled')

    def test_backticked_identifiers(self):
        parsed, problem = mail_schema._parse_sql(
            "SELECT `goto` FROM `alias` WHERE `address`='%s'")
        self.assertEqual(problem, '')
        self.assertEqual(parsed['table'], 'alias')
        self.assertEqual(parsed['where_column'], 'address')

    def test_no_enabled_column_is_not_an_error(self):
        parsed, problem = mail_schema._parse_sql(
            "SELECT destination FROM virtual_aliases WHERE source='%s'")
        self.assertEqual(problem, '')
        self.assertEqual(parsed['enabled_column'], '')

    def test_join_is_refused_rather_than_guessed(self):
        # iRedMail composes forwarding lookups across tables. Guessing here
        # would produce a confident wrong answer, which is worse than none.
        parsed, problem = mail_schema._parse_sql(
            "SELECT f.forwarding FROM forwardings f "
            "JOIN mailbox m ON m.username=f.address WHERE f.address='%s'")
        self.assertIsNone(parsed)
        self.assertIn('join', problem.lower())

    def test_existence_probe_is_refused(self):
        parsed, problem = mail_schema._parse_sql(
            "SELECT 1 FROM virtual_users WHERE email='%s' AND enabled=1")
        self.assertIsNone(parsed)
        self.assertIn('expression', problem.lower())

    def test_garbage_is_refused(self):
        parsed, problem = mail_schema._parse_sql("not sql at all")
        self.assertIsNone(parsed)


class TestCfParsing(unittest.TestCase):
    def _write(self, body):
        fd, path = tempfile.mkstemp(suffix='.cf')
        with os.fdopen(fd, 'w') as fh:
            fh.write(body)
        self.addCleanup(os.unlink, path)
        return path

    def test_password_is_never_read(self):
        # The single most important property of this parser: map files hold
        # the mail server's DB credential and it must not end up in a report,
        # a log line, or the installer's terminal output.
        path = self._write(
            "user = mailuser\n"
            "password = SuperSecret123\n"
            "hosts = 127.0.0.1\n"
            "dbname = mailserver\n"
            "query = SELECT destination FROM virtual_aliases WHERE source='%s'\n"
        )
        cf = mail_schema.parse_cf_file(path)
        self.assertNotIn('password', cf)
        self.assertEqual(cf['dbname'], 'mailserver')
        self.assertNotIn('SuperSecret123', repr(cf))

    def test_unknown_keys_are_ignored(self):
        path = self._write("some_future_key = leaky\nquery = SELECT a FROM b WHERE c='%s'\n")
        cf = mail_schema.parse_cf_file(path)
        self.assertNotIn('some_future_key', cf)

    def test_comments_and_blanks_skipped(self):
        path = self._write("# comment\n\ndbname = mailserver\n")
        cf = mail_schema.parse_cf_file(path)
        self.assertEqual(cf, {'dbname': 'mailserver'})

    def test_missing_file_returns_empty(self):
        self.assertEqual(mail_schema.parse_cf_file('/nonexistent/x.cf'), {})

    def test_legacy_three_key_form_preferred_over_sql(self):
        # Several distro packages still ship table/select_field/where_field.
        # It is unambiguous, so it should win over parsing a query.
        path = self._write(
            "dbname = postfixadmin\n"
            "table = alias\n"
            "select_field = goto\n"
            "where_field = address\n"
        )
        cf = mail_schema.parse_cf_file(path)
        schema, problem = mail_schema._schema_from_cf(cf, path)
        self.assertEqual(problem, '')
        self.assertEqual(schema['table'], 'alias')
        self.assertEqual(schema['select_column'], 'goto')
        self.assertEqual(schema['where_column'], 'address')


class TestMapFileSelection(unittest.TestCase):
    def test_single_mysql_map(self):
        paths, problem = mail_schema._map_files('mysql:/etc/postfix/mysql-virtual-aliases.cf')
        self.assertEqual(problem, '')
        self.assertEqual(paths, ['/etc/postfix/mysql-virtual-aliases.cf'])

    def test_non_mysql_map_is_reported_not_parsed(self):
        paths, problem = mail_schema._map_files('hash:/etc/postfix/virtual')
        self.assertEqual(paths, [])
        self.assertIn('hash', problem)

    def test_ldap_map_is_reported(self):
        paths, problem = mail_schema._map_files('ldap:/etc/postfix/ldap-aliases.cf')
        self.assertEqual(paths, [])
        self.assertIn('ldap', problem)

    def test_chained_maps_are_detected(self):
        paths, _ = mail_schema._map_files(
            'mysql:/etc/postfix/a.cf, mysql:/etc/postfix/b.cf')
        self.assertEqual(len(paths), 2)

    def test_empty_is_reported(self):
        paths, problem = mail_schema._map_files('')
        self.assertEqual(paths, [])
        self.assertIn('not configured', problem)


class TestFullDetection(unittest.TestCase):
    """End-to-end detect(), replaying mail.maiahost.com exactly as it was read
    on 2026-08-11. Covers the merge logic: which source wins for the mailbox
    table, where the database name comes from, and the %d/%n translation."""

    ALIAS_CF = (
        "user = mailuser\n"
        "password = REDACTED-BUT-PRESENT\n"
        "hosts = 127.0.0.1\n"
        "dbname = mailserver\n"
        "query = SELECT destination FROM virtual_aliases "
        "WHERE source='%s' AND enabled=1\n"
    )
    MAILBOX_CF = (
        "user = mailuser\n"
        "password = REDACTED-BUT-PRESENT\n"
        "hosts = 127.0.0.1\n"
        "dbname = mailserver\n"
        "query = SELECT 1 FROM virtual_users WHERE email='%s' AND enabled=1\n"
    )
    DOVECOT_SQL = (
        "driver = mysql\n"
        "connect = host=127.0.0.1 dbname=mailserver user=mailuser password=REDACTED\n"
        "password_query = SELECT email as user, password FROM virtual_users "
        "WHERE email='%u' AND enabled=1\n"
        "user_query = SELECT email as user, '/var/vmail/%d/%n' as home, "
        "5000 as uid, 5000 as gid FROM virtual_users WHERE email='%u'\n"
    )
    DOVEADM = "mail_location = maildir:/var/vmail/%d/%n/\nmail_home = \n"

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

        def w(name, body):
            path = os.path.join(self.dir, name)
            with open(path, 'w') as fh:
                fh.write(body)
            return path

        self.alias_cf = w('mysql-virtual-aliases.cf', self.ALIAS_CF)
        self.mailbox_cf = w('mysql-virtual-mailboxes.cf', self.MAILBOX_CF)
        self.dovecot_sql = w('dovecot-sql.conf.ext', self.DOVECOT_SQL)

        def fake_run(cmd):
            if cmd[0] == 'postconf':
                return "mysql:{a}\nmysql:{m}\n".format(a=self.alias_cf, m=self.mailbox_cf)
            if cmd[0] == 'doveadm':
                return self.DOVEADM
            return ''

        self._real_run = mail_schema._run
        self._real_paths = mail_schema.DOVECOT_SQL_PATHS
        mail_schema._run = fake_run
        mail_schema.DOVECOT_SQL_PATHS = (self.dovecot_sql,)
        self.addCleanup(self._restore)

    def _restore(self):
        mail_schema._run = self._real_run
        mail_schema.DOVECOT_SQL_PATHS = self._real_paths

    def test_detects_the_full_live_schema(self):
        report = mail_schema.detect()
        mb = report['mail_backend']
        self.assertTrue(report['detected'])
        self.assertEqual(mb['database'], 'mailserver')
        self.assertEqual(mb['host'], '127.0.0.1')
        self.assertEqual(mb['table'], 'virtual_users')
        self.assertEqual(mb['email_column'], 'email')
        self.assertEqual(mb['enabled_column'], 'enabled')
        self.assertEqual(mb['alias_table'], 'virtual_aliases')
        self.assertEqual(mb['alias_source_column'], 'source')
        self.assertEqual(mb['alias_destination_column'], 'destination')

    def test_maildir_template_is_translated_out_of_dovecot_syntax(self):
        # A literal % in wp-guardian.conf makes ConfigParser raise at load
        # time and the daemon never starts.
        mb = mail_schema.detect()['mail_backend']
        self.assertEqual(mb['maildir_template'], '/var/vmail/{domain}/{user}')
        self.assertNotIn('%', mb['maildir_template'])

    def test_no_detected_value_contains_a_password(self):
        report = mail_schema.detect()
        self.assertNotIn('REDACTED', repr(report))

    def test_dovecot_wins_the_mailbox_table_over_postfix(self):
        # Postfix's mailbox map is `SELECT 1 FROM ...` — an existence probe
        # that yields no usable column. Dovecot's passdb names the enabled
        # column, which is the one Guardian actually writes.
        report = mail_schema.detect()
        self.assertIn('dovecot-sql.conf.ext', report['evidence']['email_column'])
        self.assertEqual(report['problems'].get('postfix:mailbox', '')[:10], 'SELECT lis')

    def test_grant_matches_the_detected_schema(self):
        report = mail_schema.detect()
        stmt = mail_schema.grant_statement(report)
        self.assertIn('mailserver.virtual_aliases', stmt)
        self.assertIn('(source, destination)', stmt)


class TestGrantStatement(unittest.TestCase):
    def test_includes_created_column_when_known(self):
        report = {'mail_backend': {
            'database': 'mailserver', 'alias_table': 'virtual_aliases',
            'alias_source_column': 'source',
            'alias_destination_column': 'destination',
            'alias_created_column': 'created_at',
        }}
        stmt = mail_schema.grant_statement(report)
        self.assertIn('GRANT SELECT (source, destination, created_at)', stmt)
        self.assertIn('mailserver.virtual_aliases', stmt)
        self.assertIn("'wp_guardian'@'localhost'", stmt)

    def test_omits_created_column_when_absent(self):
        report = {'mail_backend': {
            'database': 'postfixadmin', 'alias_table': 'alias',
            'alias_source_column': 'address',
            'alias_destination_column': 'goto',
        }}
        stmt = mail_schema.grant_statement(report)
        self.assertIn('GRANT SELECT (address, goto)', stmt)

    def test_never_grants_write(self):
        report = {'mail_backend': {
            'database': 'x', 'alias_table': 'y',
            'alias_source_column': 'a', 'alias_destination_column': 'b'}}
        stmt = mail_schema.grant_statement(report).upper()
        for verb in ('UPDATE', 'DELETE', 'INSERT', 'ALL PRIVILEGES'):
            self.assertNotIn(verb, stmt)

    def test_empty_without_alias_table(self):
        self.assertEqual(mail_schema.grant_statement({'mail_backend': {}}), '')


if __name__ == '__main__':
    unittest.main()
