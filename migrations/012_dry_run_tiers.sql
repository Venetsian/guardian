-- Migration 012: undo enforcement state created by dry-run blocks
--
-- Until now a dry-run block went through record_block(), which sets
-- ip_history.current_tier exactly like a real block. Block() skips any IP with
-- current_tier > 0 ("already blocked"), so after a dry run (the --dry-run flag,
-- or a daemon that fell back to dry-run when its firewall backend failed to
-- initialise) every IP that had merely been SIMULATED stayed unblockable for
-- real -- tier 3 meant forever. The tier also counted as escalation evidence
-- and toward the /24 CIDR aggregation threshold.
--
-- record_simulated_block() no longer touches ip_history, so no new poison is
-- created. This clears what is already there: any IP that still reads as
-- blocked, whose most recent block_log row is a dry-run row. An IP whose
-- latest row is a real firewall block is left alone.
--
-- block_log rows are kept (they are the review trail) and get_recent_block()
-- now ignores them. block_count is not rewound. It only feeds /history.
--
-- Idempotent: a second run finds no tier above 0 with a dry-run latest row.

UPDATE ip_history
SET current_tier = 0
WHERE current_tier > 0
  AND (SELECT blocker FROM block_log
       WHERE block_log.ip = ip_history.ip
       ORDER BY timestamp DESC, id DESC
       LIMIT 1) = 'dry-run';
