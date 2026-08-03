-- Migration 009: Operator-cleared blocks no longer arm the next escalation
--
-- determine_tier() escalates by looking at the most recent block_log row for
-- an IP. unblock() reset ip_history.current_tier but left block_log intact,
-- so an operator clearing a false positive handed the NEXT block a higher
-- tier: unblock -> client retries -> re-block at tier 2 -> unblock -> tier 3.
-- Every rescue attempt bought a harsher ban.
--
-- cleared_at records when an operator explicitly unblocked the IP.
-- get_recent_block() ignores cleared rows, so a manual unblock resets the
-- escalation ladder instead of climbing it. Rows expired by the block reaper
-- are NOT cleared — those SHOULD escalate on return, which is the whole
-- point of the three-tier design.

ALTER TABLE block_log ADD COLUMN cleared_at INTEGER DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_block_cleared ON block_log(ip, cleared_at, timestamp);
