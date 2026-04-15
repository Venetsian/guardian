-- Migration 005: Buffer for digest-mode Telegram alerts
-- DB Schema Version: 5

CREATE TABLE IF NOT EXISTS alert_digest_buffer (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    queued_at       INTEGER NOT NULL,
    event_type      TEXT NOT NULL,
    severity        TEXT NOT NULL,
    summary         TEXT NOT NULL,
    payload_json    TEXT DEFAULT '',
    flushed         INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_digest_unflushed ON alert_digest_buffer(flushed, queued_at);
