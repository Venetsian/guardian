-- Migration 004: Audit log for mailbox enable/disable actions
-- DB Schema Version: 4

CREATE TABLE IF NOT EXISTS mailbox_actions (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    performed_at            INTEGER NOT NULL,
    username                TEXT NOT NULL,
    action                  TEXT NOT NULL,
    actor                   TEXT NOT NULL,
    reason                  TEXT DEFAULT '',
    related_compromise_id   INTEGER DEFAULT 0,
    success                 INTEGER NOT NULL,
    error_message           TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_mailbox_actions_username ON mailbox_actions(username);
CREATE INDEX IF NOT EXISTS idx_mailbox_actions_performed ON mailbox_actions(performed_at);
