-- Migration 006: Add original_password_hash column to mailbox_actions
-- Supports the password_reset disable strategy (CyberPanel recipe).
-- Stores the original password hash so enable_mailbox can restore it.

ALTER TABLE mailbox_actions ADD COLUMN original_password_hash TEXT DEFAULT NULL;
