-- Migration 008: Posture audit + host-health module foundation
-- Adds three tables that back the new posture-audit and host-health
-- modules described in task #122:
--
--   host_profile     applicability flags for a managed host
--                    (is_cloudlinux, web_server, etc.)
--   posture_state    current value of every (host, module, check_id),
--                    upserted on every run
--   posture_events   append-only transitions log with 30-day TTL
--                    enforced by the orchestrators daily cleanup
--
-- The `host` column is included on every table even though each guardian
-- instance currently audits only its own box. This leaves room for a
-- future fleet-rollup pass without another schema migration.

CREATE TABLE IF NOT EXISTS host_profile (
    host                       TEXT PRIMARY KEY,
    is_linux                   INTEGER NOT NULL DEFAULT 1,
    is_cloudlinux              INTEGER NOT NULL DEFAULT 0,
    is_multi_tenant            INTEGER NOT NULL DEFAULT 0,
    is_single_site             INTEGER NOT NULL DEFAULT 0,
    web_server                 TEXT NOT NULL DEFAULT 'none',
    db_server                  TEXT NOT NULL DEFAULT 'none',
    mta                        TEXT NOT NULL DEFAULT 'none',
    has_modsec                 INTEGER NOT NULL DEFAULT 0,
    behind_perimeter_firewall  INTEGER NOT NULL DEFAULT 0,
    distro_id                  TEXT DEFAULT '',
    distro_version             TEXT DEFAULT '',
    extras_json                TEXT DEFAULT '',
    detected_at                INTEGER NOT NULL,
    detection_method           TEXT NOT NULL DEFAULT 'auto'
);

CREATE TABLE IF NOT EXISTS posture_state (
    host           TEXT NOT NULL,
    module         TEXT NOT NULL,
    check_id       TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'unknown',
    severity       TEXT NOT NULL DEFAULT 'low',
    current_value  TEXT DEFAULT '',
    detail         TEXT DEFAULT '',
    last_run_at    INTEGER NOT NULL,
    last_change_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host, module, check_id)
);

CREATE INDEX IF NOT EXISTS idx_posture_state_module ON posture_state(module);
CREATE INDEX IF NOT EXISTS idx_posture_state_status ON posture_state(status);

CREATE TABLE IF NOT EXISTS posture_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host         TEXT NOT NULL,
    module       TEXT NOT NULL,
    check_id     TEXT NOT NULL,
    occurred_at  INTEGER NOT NULL,
    from_status  TEXT DEFAULT '',
    to_status    TEXT NOT NULL,
    from_value   TEXT DEFAULT '',
    to_value     TEXT DEFAULT '',
    severity     TEXT NOT NULL DEFAULT 'low',
    detail       TEXT DEFAULT '',
    alerted      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_posture_events_check ON posture_events(check_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_posture_events_occurred ON posture_events(occurred_at);
CREATE INDEX IF NOT EXISTS idx_posture_events_severity ON posture_events(severity, occurred_at);
