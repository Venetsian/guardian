-- Migration 003: Track detected compromises
-- DB Schema Version: 3

CREATE TABLE IF NOT EXISTS compromise_events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at         INTEGER NOT NULL,
    username            TEXT NOT NULL,
    service             TEXT NOT NULL,
    trigger_rule        TEXT NOT NULL,
    trigger_count       INTEGER NOT NULL,
    window_seconds      INTEGER NOT NULL,
    distinct_ips        INTEGER NOT NULL,
    distinct_countries  INTEGER NOT NULL,
    distinct_asns       INTEGER NOT NULL,
    sample_ips          TEXT DEFAULT '',
    sample_countries    TEXT DEFAULT '',
    action_taken        TEXT NOT NULL,
    mailbox_disabled    INTEGER DEFAULT 0,
    ips_blocked_count   INTEGER DEFAULT 0,
    notes               TEXT DEFAULT '',
    resolved_at         INTEGER DEFAULT 0,
    resolved_by         TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_compromise_username ON compromise_events(username);
CREATE INDEX IF NOT EXISTS idx_compromise_detected ON compromise_events(detected_at);
CREATE INDEX IF NOT EXISTS idx_compromise_open ON compromise_events(resolved_at);
