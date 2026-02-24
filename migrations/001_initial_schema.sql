-- Migration 001: Initial schema
-- This represents the baseline schema. It is NOT run on fresh installs
-- (the database module creates tables directly). It exists only for
-- documentation and as a reference point for future migrations.
--
-- DB Schema Version: 1

-- Schema version tracking table (added by migration runner)
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER NOT NULL,
    applied_at  TEXT NOT NULL,
    description TEXT DEFAULT ''
);

-- All initial tables are created by modules/database.py _create_tables()
-- This migration is a no-op marker for the baseline.
