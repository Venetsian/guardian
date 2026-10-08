-- Migration 013: subnet (CIDR) block records (v1.7.19)
--
-- Until now a CIDR block had no record anywhere. The blocker kept the subnets
-- it had blocked in a Python set that died with the process, and the only
-- trace on disk was a line in blocked.log. firewalld and pfSense cannot expire
-- an entry on their own, and nothing ever removed one, so a "30d" subnet block
-- stayed in the set for good. Production hosts hold 70, 726 and 29 /24s, most
-- of them long past their logged duration.
--
-- One row per block. status says how it ended:
--   active   enforced now (or overdue and waiting for the hourly reaper)
--   expired  ended because its duration ran out. The range is a known repeat
--            offender, so the next blocked IP in it re-blocks the whole range
--   removed  an operator lifted it (/unblock, or found hand-removed at import).
--            Treated as a cleared false positive and never re-blocked on sight
--
-- expires_at = 0 means permanent. source is auto (threshold), reoffend (repeat
-- offender), manual (/block, --block), import (first run after the upgrade,
-- rebuilt from blocked.log) or adopted (found in the firewall with no record).
--
-- Only one active row per subnet is allowed. SQLite 3.7 (EL7) has no partial
-- indexes, so GuardianDB.insert_cidr_block enforces that in code.
--
-- The table is also created by GuardianDB._create_tables(), so a database that
-- already has it simply skips both statements.

CREATE TABLE IF NOT EXISTS cidr_blocks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    subnet      TEXT NOT NULL,
    blocked_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL DEFAULT 0,
    duration    TEXT NOT NULL,
    source      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active',
    ended_at    INTEGER DEFAULT 0,
    reason      TEXT DEFAULT '',
    service     TEXT DEFAULT '',
    backend     TEXT DEFAULT ''
);

-- Serves the per-subnet lookups made on every aggregation check.
CREATE INDEX IF NOT EXISTS idx_cidr_blocks_subnet
    ON cidr_blocks(subnet);

-- Serves the reaper (overdue active rows) and the status counts.
CREATE INDEX IF NOT EXISTS idx_cidr_blocks_status_expires
    ON cidr_blocks(status, expires_at);
