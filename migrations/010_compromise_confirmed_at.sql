-- Migration 010: provisional mailbox disables, and the flag that makes one permanent
--
-- A compromise disable used to be permanent until a human noticed. On
-- 2026-08-09 a travelling client's mailbox (bob@example.net) was
-- auto-disabled at 23:44 on five distinct ASNs — his own phone and two rural
-- ILECs — and stayed off for 16h04m because the operator was asleep. The
-- client-visible outage was ten minutes only because the device happened not
-- to poll overnight. That gap was luck, not design.
--
-- Auto re-enable (see [compromise_detection] auto_reenable_hours) treats a
-- disable as PROVISIONAL: absent operator confirmation it is reversed after
-- N hours, bounding the blast radius of any detection error — including
-- classes of error nobody has predicted yet. The attacker IPs stay
-- firewall-blocked on their own tier schedule, so reversing the mailbox does
-- not hand access back to the sources that triggered the event.
--
-- confirmed_at pins a disable against that reversal. An operator who has
-- looked at the evidence and concluded the compromise is real runs
-- /confirm <id>, and the reaper never touches the mailbox again.
--
-- Distinct from resolved_at on purpose: "resolved" means the incident is
-- closed and needs no further attention, "confirmed" means the compromise
-- was genuine and enforcement must stand. An event can be confirmed and
-- still open (attacker active, being worked), or resolved without ever being
-- confirmed (false positive, dismissed).

-- auto_reversed_at records that the reaper already restored this mailbox. It
-- keeps mailbox_disabled intact as the forensic record of what the event did
-- at the time, while stopping the event reappearing as a reaper candidate on
-- every subsequent hourly sweep forever.

ALTER TABLE compromise_events ADD COLUMN confirmed_at INTEGER DEFAULT 0;
ALTER TABLE compromise_events ADD COLUMN confirmed_by TEXT DEFAULT '';
ALTER TABLE compromise_events ADD COLUMN auto_reversed_at INTEGER DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_compromise_pending_reverse
    ON compromise_events(mailbox_disabled, confirmed_at, auto_reversed_at, detected_at);
