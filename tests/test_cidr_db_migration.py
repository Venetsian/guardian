"""Migration 013 and the cidr_blocks data access layer (v1.7.19).

Subnet blocks used to be an in-memory set plus a line in blocked.log. They are
now rows: one per block, with the status saying how it ended ('expired' by its
duration, 'removed' by an operator).

Stdlib unittest on purpose (the daemon runs on Python 3.6). Run from the repo
root:

    python3 -m unittest discover -s tests -v
"""

import os
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fakes_cidr import NET_A, NET_B, NET_C, DBFixture, add_row, rows, statuses  # noqa: E402
from modules import migrator  # noqa: E402

MIGRATIONS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'migrations')

COLUMNS = ['id', 'subnet', 'blocked_at', 'expires_at', 'duration', 'source',
           'status', 'ended_at', 'reason', 'service', 'backend']


def table_columns(conn, table):
    return [r[1] for r in conn.execute("PRAGMA table_info({})".format(table)).fetchall()]


def index_names(conn):
    return set(r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index'").fetchall())


class TestMigration013(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='wpg-test-')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_creates_the_table_on_an_existing_v12_database(self):
        # A genuine pre-upgrade database: stamped 12, no cidr_blocks table.
        conn = sqlite3.connect(os.path.join(self.tmp, 'old.db'))
        migrator._ensure_schema_table(conn)
        migrator._record_version(conn, 12, 'pre-013 database')
        self.assertEqual(table_columns(conn, 'cidr_blocks'), [])

        applied = migrator.run_migrations(conn, MIGRATIONS_DIR)

        self.assertEqual(applied, 1)
        self.assertEqual(table_columns(conn, 'cidr_blocks'), COLUMNS)
        self.assertEqual(migrator.get_schema_version(conn), 13)
        conn.close()

    def test_creates_both_indexes(self):
        conn = sqlite3.connect(os.path.join(self.tmp, 'old.db'))
        migrator._ensure_schema_table(conn)
        migrator._record_version(conn, 12, 'pre-013 database')
        migrator.run_migrations(conn, MIGRATIONS_DIR)
        self.assertTrue({'idx_cidr_blocks_subnet',
                         'idx_cidr_blocks_status_expires'} <= index_names(conn))
        conn.close()

    def test_is_idempotent_when_the_table_already_exists(self):
        # GuardianDB._create_tables() creates the table before migrations run,
        # so every real upgrade replays 013 over an existing table.
        fx = DBFixture()
        try:
            add_row(fx.db, NET_A)
            fx.db.conn.execute("DELETE FROM schema_version")
            fx.db.conn.commit()
            migrator._record_version(fx.db.conn, 12, 'pre-013 database')

            self.assertEqual(migrator.run_migrations(fx.db.conn, MIGRATIONS_DIR), 1)

            self.assertEqual(len(rows(fx.db)), 1, "existing rows survive")
        finally:
            fx.close()

    def test_fresh_install_has_the_table_at_the_current_version(self):
        fx = DBFixture()
        try:
            self.assertEqual(table_columns(fx.db.conn, 'cidr_blocks'), COLUMNS)
            self.assertEqual(fx.db.get_schema_version(), migrator.CURRENT_SCHEMA_VERSION)
            self.assertEqual(migrator.CURRENT_SCHEMA_VERSION, 13)
            self.assertTrue({'idx_cidr_blocks_subnet',
                             'idx_cidr_blocks_status_expires'} <= index_names(fx.db.conn))
        finally:
            fx.close()

    def test_column_defaults_match_the_spec(self):
        fx = DBFixture()
        try:
            fx.db.conn.execute(
                "INSERT INTO cidr_blocks (subnet, blocked_at, duration, source) "
                "VALUES (?, 1, '30d', 'auto')", (NET_A,))
            row = rows(fx.db)[0]
            self.assertEqual(row['status'], 'active')
            self.assertEqual(row['expires_at'], 0)
            self.assertEqual(row['ended_at'], 0)
            self.assertEqual((row['reason'], row['service'], row['backend']), ('', '', ''))
        finally:
            fx.close()


class TestCidrBlockQueries(unittest.TestCase):
    def setUp(self):
        self.fx = DBFixture()
        self.db = self.fx.db

    def tearDown(self):
        self.fx.close()

    def test_insert_returns_the_row_and_stores_every_field(self):
        now = int(time.time())
        block_id = self.db.insert_cidr_block(
            NET_A, now + 100, '30d', 'auto', reason='r', service='web',
            backend='firewalld', blocked_at=now)
        row = self.db.get_cidr_block_by_id(block_id)
        self.assertEqual(
            (row['subnet'], row['blocked_at'], row['expires_at'], row['duration'],
             row['source'], row['status'], row['reason'], row['service'], row['backend']),
            (NET_A, now, now + 100, '30d', 'auto', 'active', 'r', 'web', 'firewalld'))

    def test_only_one_active_row_per_subnet(self):
        first = add_row(self.db, NET_A)
        second = add_row(self.db, NET_A, source='manual')

        self.assertEqual(statuses(self.db, NET_A), ['removed', 'active'])
        self.assertEqual(self.db.get_cidr_block(NET_A)['id'], second)
        self.assertNotEqual(first, second)

    def test_replacing_an_overdue_row_records_it_as_expired_not_removed(self):
        add_row(self.db, NET_A, expires_in_days=-2)
        add_row(self.db, NET_A)
        self.assertEqual(statuses(self.db, NET_A), ['expired', 'active'])

    def test_other_subnets_are_not_touched_by_an_insert(self):
        add_row(self.db, NET_A)
        add_row(self.db, NET_B)
        self.assertEqual(statuses(self.db, NET_A), ['active'])

    def test_live_lookup_ignores_overdue_and_ended_rows(self):
        add_row(self.db, NET_A, expires_in_days=-1)
        add_row(self.db, NET_B, status='expired', ended_days_ago=1)
        self.assertIsNone(self.db.get_live_cidr_block(NET_A))
        self.assertIsNone(self.db.get_live_cidr_block(NET_B))
        self.assertIsNotNone(self.db.get_cidr_block(NET_A), "still the active row")

    def test_permanent_rows_are_live(self):
        add_row(self.db, NET_A, permanent=True)
        self.assertIsNotNone(self.db.get_live_cidr_block(NET_A))

    def test_overdue_rows_come_longest_overdue_first_and_respect_the_limit(self):
        now = int(time.time())
        add_row(self.db, NET_A, expires_in_days=-1)
        add_row(self.db, NET_B, expires_in_days=-5)
        add_row(self.db, NET_C, expires_in_days=10)
        add_row(self.db, '192.0.2.0/25', permanent=True)

        overdue = self.db.get_overdue_cidr_blocks(now, 10)
        self.assertEqual([r['subnet'] for r in overdue], [NET_B, NET_A])
        self.assertEqual(len(self.db.get_overdue_cidr_blocks(now, 1)), 1)
        self.assertEqual(self.db.count_overdue_cidr_blocks(now), 2)

    def test_end_cidr_block_only_closes_an_active_row(self):
        block_id = add_row(self.db, NET_A)
        self.assertEqual(self.db.end_cidr_block(block_id, 'expired'), 1)
        row = self.db.get_cidr_block_by_id(block_id)
        self.assertEqual(row['status'], 'expired')
        self.assertGreater(row['ended_at'], 0)
        self.assertEqual(self.db.end_cidr_block(block_id, 'removed'), 0,
                         "a second close (lost race) changes nothing")
        self.assertEqual(self.db.get_cidr_block_by_id(block_id)['status'], 'expired')

    def test_latest_expired_row_is_the_repeat_offender_record(self):
        add_row(self.db, NET_A, status='expired', age_days=90, ended_days_ago=60)
        newer = add_row(self.db, NET_A, status='expired', age_days=40, ended_days_ago=10)
        add_row(self.db, NET_A, status='removed', ended_days_ago=1)

        self.assertEqual(self.db.get_expired_cidr(NET_A)['id'], newer)
        self.assertIsNone(self.db.get_expired_cidr(NET_B))

    def test_clear_memory_turns_expired_rows_into_removed(self):
        add_row(self.db, NET_A, status='expired', ended_days_ago=5)
        add_row(self.db, NET_B, status='expired', ended_days_ago=5)

        self.assertEqual(self.db.clear_cidr_memory(NET_A), 1)

        self.assertIsNone(self.db.get_expired_cidr(NET_A))
        self.assertIsNotNone(self.db.get_expired_cidr(NET_B))

    def test_table_empty(self):
        self.assertTrue(self.db.cidr_table_empty())
        add_row(self.db, NET_A, status='removed', ended_days_ago=1)
        self.assertFalse(self.db.cidr_table_empty(), "a closed row still counts")

    def test_counts(self):
        add_row(self.db, NET_A)                                   # active
        add_row(self.db, NET_B, expires_in_days=-3)               # active, overdue
        add_row(self.db, '192.0.2.0/25', permanent=True)          # active, permanent
        add_row(self.db, NET_C, status='expired', ended_days_ago=2)    # on watch
        add_row(self.db, '192.0.2.128/25', status='removed', ended_days_ago=2)

        counts = self.db.cidr_counts()

        self.assertEqual(counts, {'active': 3, 'permanent': 1, 'overdue': 1, 'watch': 1})

    def test_watch_counts_distinct_subnets_without_an_active_row(self):
        add_row(self.db, NET_A, status='expired', age_days=90, ended_days_ago=60)
        add_row(self.db, NET_A, status='expired', age_days=40, ended_days_ago=10)
        add_row(self.db, NET_B, status='expired', ended_days_ago=5)
        add_row(self.db, NET_B)                                   # re-blocked: off the watch

        self.assertEqual(self.db.cidr_counts()['watch'], 1)

    def test_list_orders_soonest_expiring_first_and_permanent_last(self):
        add_row(self.db, NET_A, expires_in_days=20)
        add_row(self.db, NET_B, expires_in_days=2)
        add_row(self.db, NET_C, permanent=True)
        add_row(self.db, '192.0.2.0/25', expires_in_days=-1)

        everything = [r['subnet'] for r in self.db.list_active_cidr_blocks()]
        upcoming = [r['subnet'] for r in
                    self.db.list_active_cidr_blocks(limit=10, include_overdue=False)]

        self.assertEqual(everything, ['192.0.2.0/25', NET_B, NET_A, NET_C])
        self.assertEqual(upcoming, [NET_B, NET_A, NET_C])
        self.assertEqual(len(self.db.list_active_cidr_blocks(limit=2)), 2)


class TestCoveringLookup(unittest.TestCase):
    def setUp(self):
        self.fx = DBFixture()
        self.db = self.fx.db

    def tearDown(self):
        self.fx.close()

    def test_exact_slash_24(self):
        add_row(self.db, NET_A)
        self.assertEqual(self.db.get_active_cidr_covering('198.51.100.77')['subnet'], NET_A)
        self.assertIsNone(self.db.get_active_cidr_covering('203.0.113.77'))

    def test_a_wider_manual_block_covers_the_ip(self):
        add_row(self.db, '198.51.100.0/22', source='manual', permanent=True)
        self.assertEqual(self.db.get_active_cidr_covering('198.51.100.9')['subnet'],
                         '198.51.100.0/22')
        self.assertIsNone(self.db.get_active_cidr_covering('203.0.113.9'))

    def test_a_narrower_manual_block_covers_only_its_own_addresses(self):
        add_row(self.db, '203.0.113.128/25', source='manual', permanent=True)
        self.assertIsNotNone(self.db.get_active_cidr_covering('203.0.113.200'))
        self.assertIsNone(self.db.get_active_cidr_covering('203.0.113.5'))

    def test_overdue_rows_count_only_when_asked(self):
        add_row(self.db, NET_A, expires_in_days=-2)
        add_row(self.db, '198.51.100.0/22', expires_in_days=-2, source='manual')
        self.assertIsNone(self.db.get_active_cidr_covering('198.51.100.9'))
        self.assertIsNotNone(
            self.db.get_active_cidr_covering('198.51.100.9', include_overdue=True))

    def test_ended_rows_never_cover(self):
        add_row(self.db, NET_A, status='expired', ended_days_ago=1)
        add_row(self.db, '198.51.100.0/22', status='removed', ended_days_ago=1)
        self.assertIsNone(self.db.get_active_cidr_covering('198.51.100.9', include_overdue=True))

    def test_ipv6_and_garbage_are_not_covered(self):
        add_row(self.db, NET_A)
        self.assertIsNone(self.db.get_active_cidr_covering('2001:db8::1'))
        self.assertIsNone(self.db.get_active_cidr_covering('not-an-ip'))


if __name__ == '__main__':
    unittest.main()
