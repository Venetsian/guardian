-- Migration 011: outbound send records (v1.7.15)
--
-- The payload-phase half of abuse corroboration. The reconnaissance-phase
-- checks that shipped in v1.7.12 look for artefacts an attacker leaves while
-- reading mail and planting persistence. This table records what the account
-- actually SENT, so a takeover that has started monetising can be proved
-- rather than inferred from geography.
--
-- One row per authenticated outbound message. The row is written only when a
-- Postfix queue ID has been seen on BOTH of these lines:
--
--   smtpd  <QID>: client=host[1.2.3.4], sasl_method=PLAIN, sasl_username=u@d
--   qmgr   <QID>: from=<u@d>, size=80933, nrcpt=1 (queue active)
--
-- The correlation is mandatory, not an optimisation. qmgr logs inbound and
-- outbound mail identically -- on the reference host most sampled qmgr lines
-- were inbound (bounces, spam) -- so counting qmgr alone would measure how
-- much mail the server RECEIVES for an account and call it sending. Only a
-- queue ID first seen on an authenticated smtpd line is ours going out.
--
-- nrcpt is stored per message rather than summed, because the two corroboration
-- checks read it differently. Volume compares the account against its own
-- history and is inert until enough history accrues. Fan-out reads the largest
-- single message, needs no baseline, and is therefore the only outbound signal
-- available on the day the feature is installed.
--
-- Retention is [database] outbound_retention_days (default 30) rather than the
-- 90 days auth_sessions keeps. This table grows per MESSAGE, not per login, and
-- its only consumer is a baseline whose window is 30 days -- anything older is
-- dead weight.

CREATE TABLE IF NOT EXISTS outbound_activity (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL,
    ip          TEXT DEFAULT '',
    timestamp   INTEGER NOT NULL,
    queue_id    TEXT DEFAULT '',
    nrcpt       INTEGER DEFAULT 1,
    size_bytes  INTEGER DEFAULT 0
);

-- Serves the per-account volume and fan-out queries.
CREATE INDEX IF NOT EXISTS idx_outbound_user_time
    ON outbound_activity(username, timestamp);

-- Serves the retention sweep and the global "how long have we been observing
-- outbound at all" query that gates the volume baseline.
CREATE INDEX IF NOT EXISTS idx_outbound_time
    ON outbound_activity(timestamp);
