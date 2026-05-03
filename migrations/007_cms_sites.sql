-- Migration 007: CMS site registry (v1.5)
-- Records the auto-detected (or operator-overridden) CMS for each site.
-- Used by the v1.5 web detector to dispatch CMS-specific rules and to
-- register admin paths with the POST-flood detector.

CREATE TABLE IF NOT EXISTS cms_sites (
    site         TEXT PRIMARY KEY,
    cms          TEXT NOT NULL DEFAULT 'unknown',
    docroot      TEXT DEFAULT '',
    admin_paths  TEXT DEFAULT '',     -- JSON list of admin paths, lowercase
    detected_at  INTEGER NOT NULL,
    overridden   INTEGER DEFAULT 0    -- 1 if set via vhosts.conf
);

CREATE INDEX IF NOT EXISTS idx_cms_sites_cms ON cms_sites(cms);
