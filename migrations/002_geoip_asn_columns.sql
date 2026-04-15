-- Migration 002: Add ASN columns to auth_sessions and ip_history
-- DB Schema Version: 2

ALTER TABLE auth_sessions ADD COLUMN geoip_asn INTEGER DEFAULT 0;
ALTER TABLE auth_sessions ADD COLUMN geoip_asn_org TEXT DEFAULT '';

ALTER TABLE ip_history ADD COLUMN geoip_asn INTEGER DEFAULT 0;
ALTER TABLE ip_history ADD COLUMN geoip_asn_org TEXT DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_auth_username_ts ON auth_sessions(username, timestamp);
CREATE INDEX IF NOT EXISTS idx_auth_country_ts ON auth_sessions(geoip_country, timestamp);
