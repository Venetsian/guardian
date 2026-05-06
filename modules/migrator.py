"""
WP-Guardian Database Migrator
Applies numbered SQL migrations to bring the database schema up to date.
"""

import os
import re
import time
import logging

logger = logging.getLogger('wp-guardian.migrator')

# Current schema version — increment this when adding new migrations
CURRENT_SCHEMA_VERSION = 8


def get_schema_version(conn):
    """Get the current schema version from the database. Returns 0 if not tracked yet."""
    try:
        cursor = conn.execute("SELECT MAX(version) FROM schema_version")
        row = cursor.fetchone()
        if row and row[0] is not None:
            return row[0]
    except Exception:
        # Table doesn't exist yet — that's fine, means version 0
        pass
    return 0


def _ensure_schema_table(conn):
    """Create the schema_version table if it doesn't exist."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version     INTEGER NOT NULL,
            applied_at  TEXT NOT NULL,
            description TEXT DEFAULT ''
        )
    """)
    conn.commit()


def _record_version(conn, version, description=''):
    """Record that a migration was applied."""
    conn.execute(
        "INSERT INTO schema_version (version, applied_at, description) VALUES (?, ?, ?)",
        (version, time.strftime('%Y-%m-%d %H:%M:%S'), description)
    )
    conn.commit()


def _discover_migrations(migrations_dir):
    """
    Find all migration files in the directory.
    Returns a sorted list of (version_number, filepath, description) tuples.
    """
    migrations = []
    pattern = re.compile(r'^(\d{3})_(.+)\.sql$')

    if not os.path.isdir(migrations_dir):
        return migrations

    for filename in sorted(os.listdir(migrations_dir)):
        match = pattern.match(filename)
        if match:
            version = int(match.group(1))
            description = match.group(2).replace('_', ' ')
            filepath = os.path.join(migrations_dir, filename)
            migrations.append((version, filepath, description))

    return migrations


def _run_migration(conn, version, filepath, description):
    """
    Execute a single migration file.
    Each statement is executed individually. Errors on 'duplicate column'
    or 'already exists' are treated as success (idempotent).
    """
    logger.info(f"Applying migration {version:03d}: {description}")

    with open(filepath, 'r') as f:
        sql_content = f.read()

    # Split into individual statements (skip empty ones and comments-only)
    statements = []
    for stmt in sql_content.split(';'):
        # Remove comments and whitespace
        cleaned = re.sub(r'--[^\n]*', '', stmt).strip()
        if cleaned:
            statements.append(cleaned)

    for stmt in statements:
        try:
            conn.execute(stmt)
        except Exception as e:
            error_msg = str(e).lower()
            # These errors are OK — they mean the change was already applied
            if 'duplicate column' in error_msg:
                logger.debug(f"Column already exists, skipping: {stmt[:60]}")
            elif 'already exists' in error_msg:
                logger.debug(f"Object already exists, skipping: {stmt[:60]}")
            elif 'no such column' in error_msg and 'drop' in stmt.lower():
                logger.debug(f"Column doesn't exist for drop, skipping: {stmt[:60]}")
            else:
                raise

    conn.commit()
    _record_version(conn, version, description)
    logger.info(f"Migration {version:03d} applied successfully")


def run_migrations(conn, migrations_dir):
    """
    Run all pending migrations.

    Args:
        conn: SQLite connection
        migrations_dir: Path to the migrations/ directory

    Returns:
        Number of migrations applied.
    """
    _ensure_schema_table(conn)

    current = get_schema_version(conn)
    migrations = _discover_migrations(migrations_dir)

    if not migrations:
        logger.debug("No migration files found")
        # If no migrations exist but we're on a fresh install, mark as version 1
        if current == 0:
            _record_version(conn, CURRENT_SCHEMA_VERSION, 'initial schema (fresh install)')
        return 0

    pending = [(v, fp, desc) for v, fp, desc in migrations if v > current]

    if not pending:
        logger.debug(f"Database schema is up to date (version {current})")
        return 0

    logger.info(f"Database schema version {current} -> {pending[-1][0]} "
                f"({len(pending)} migration(s) to apply)")

    applied = 0
    for version, filepath, description in pending:
        try:
            _run_migration(conn, version, filepath, description)
            applied += 1
        except Exception as e:
            logger.error(f"Migration {version:03d} FAILED: {e}")
            logger.error(f"Database may be in an inconsistent state. "
                        f"Restore from backup if needed.")
            raise

    return applied


def initialize_fresh_db(conn, migrations_dir):
    """
    Called on fresh installs (after _create_tables).
    Marks the database as being at the current schema version
    without running any migrations (since tables were just created).
    """
    _ensure_schema_table(conn)
    current = get_schema_version(conn)

    if current == 0:
        _record_version(conn, CURRENT_SCHEMA_VERSION, 'initial schema (fresh install)')
        logger.info(f"Fresh database initialized at schema version {CURRENT_SCHEMA_VERSION}")
