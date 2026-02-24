"""
WP-Guardian Database Module
SQLite schema setup and data access layer.
"""

import sqlite3
import time
import os
import logging

logger = logging.getLogger('wp-guardian.db')


class GuardianDB:
    def __init__(self, db_path, base_dir=None):
        self.db_path = db_path
        self._base_dir = base_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        is_fresh = not os.path.exists(db_path) or os.path.getsize(db_path) == 0

        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")  # Better concurrent read performance
        self.conn.execute("PRAGMA busy_timeout=5000")
        self._create_tables()

        # Run database migrations
        self._run_migrations(is_fresh)

    def _create_tables(self):
        cursor = self.conn.cursor()

        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS ip_history (
                ip              TEXT PRIMARY KEY,
                first_seen      INTEGER NOT NULL,
                last_seen       INTEGER NOT NULL,
                total_hits      INTEGER DEFAULT 0,
                current_tier    INTEGER DEFAULT 0,
                tier_changed_at INTEGER DEFAULT 0,
                block_count     INTEGER DEFAULT 0,
                last_block_reason  TEXT DEFAULT '',
                last_block_service TEXT DEFAULT '',
                geoip_country   TEXT DEFAULT '',
                geoip_city      TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS auth_sessions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT NOT NULL,
                timestamp   INTEGER NOT NULL,
                service     TEXT NOT NULL,
                username    TEXT NOT NULL,
                site        TEXT DEFAULT '',
                geoip_country TEXT DEFAULT '',
                geoip_city  TEXT DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_auth_ip ON auth_sessions(ip);
            CREATE INDEX IF NOT EXISTS idx_auth_service_user ON auth_sessions(service, username);
            CREATE INDEX IF NOT EXISTS idx_auth_timestamp ON auth_sessions(timestamp);

            CREATE TABLE IF NOT EXISTS account_baselines (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT NOT NULL,
                service     TEXT NOT NULL,
                country     TEXT NOT NULL,
                city        TEXT DEFAULT '',
                first_seen  INTEGER NOT NULL,
                last_seen   INTEGER NOT NULL,
                hit_count   INTEGER DEFAULT 1,
                UNIQUE(username, service, country, city)
            );

            CREATE TABLE IF NOT EXISTS tripwires (
                path        TEXT PRIMARY KEY,
                category    TEXT DEFAULT 'unknown',
                hit_count   INTEGER DEFAULT 0,
                first_seen  INTEGER NOT NULL,
                last_updated INTEGER NOT NULL,
                active      INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS whitelist (
                ip          TEXT PRIMARY KEY,
                type        TEXT NOT NULL,
                added_at    INTEGER NOT NULL,
                expires_at  INTEGER DEFAULT NULL,
                reason      TEXT DEFAULT '',
                added_by    TEXT DEFAULT 'system'
            );

            CREATE TABLE IF NOT EXISTS block_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT NOT NULL,
                timestamp   INTEGER NOT NULL,
                tier        INTEGER NOT NULL,
                reason      TEXT NOT NULL,
                service     TEXT NOT NULL,
                blocker     TEXT NOT NULL,
                duration    TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_block_ip ON block_log(ip);
            CREATE INDEX IF NOT EXISTS idx_block_timestamp ON block_log(timestamp);

            CREATE TABLE IF NOT EXISTS login_isolation (
                ip              TEXT PRIMARY KEY,
                first_seen      INTEGER NOT NULL,
                last_seen       INTEGER NOT NULL,
                login_hits      INTEGER DEFAULT 0,
                has_css         INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_login_iso_last ON login_isolation(last_seen);
        """)

        self.conn.commit()
        logger.info(f"Database initialized: {self.db_path}")

    def _run_migrations(self, is_fresh):
        """Run database migrations on startup."""
        try:
            from modules.migrator import run_migrations, initialize_fresh_db, get_schema_version

            migrations_dir = os.path.join(self._base_dir, 'migrations')

            if is_fresh:
                initialize_fresh_db(self.conn, migrations_dir)
            else:
                applied = run_migrations(self.conn, migrations_dir)
                if applied > 0:
                    logger.info(f"Applied {applied} database migration(s)")

            version = get_schema_version(self.conn)
            logger.debug(f"Database schema version: {version}")
        except ImportError:
            logger.debug("Migration module not available, skipping")
        except Exception as e:
            logger.warning(f"Migration check failed (non-fatal): {e}")

    def get_schema_version(self):
        """Get current database schema version."""
        try:
            from modules.migrator import get_schema_version
            return get_schema_version(self.conn)
        except Exception:
            return 0

    # ------------------------------------------------------------------
    # IP History
    # ------------------------------------------------------------------
    def get_ip(self, ip):
        """Get full history for an IP."""
        cursor = self.conn.execute("SELECT * FROM ip_history WHERE ip = ?", (ip,))
        return cursor.fetchone()

    def track_ip(self, ip, service='web', country='', city=''):
        """Record a hit for an IP. Creates entry if new."""
        now = int(time.time())
        existing = self.get_ip(ip)

        if existing:
            self.conn.execute("""
                UPDATE ip_history
                SET last_seen = ?, total_hits = total_hits + 1,
                    geoip_country = COALESCE(NULLIF(?, ''), geoip_country),
                    geoip_city = COALESCE(NULLIF(?, ''), geoip_city)
                WHERE ip = ?
            """, (now, country, city, ip))
        else:
            self.conn.execute("""
                INSERT INTO ip_history (ip, first_seen, last_seen, total_hits, geoip_country, geoip_city)
                VALUES (?, ?, ?, 1, ?, ?)
            """, (ip, now, now, country, city))

        self.conn.commit()

    def record_block(self, ip, tier, reason, service, blocker, duration):
        """Record a block action and update IP history."""
        now = int(time.time())

        # Update ip_history
        self.conn.execute("""
            UPDATE ip_history
            SET current_tier = ?, tier_changed_at = ?,
                block_count = block_count + 1,
                last_block_reason = ?, last_block_service = ?
            WHERE ip = ?
        """, (tier, now, reason, service, ip))

        # Add to block_log
        self.conn.execute("""
            INSERT INTO block_log (ip, timestamp, tier, reason, service, blocker, duration)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (ip, now, tier, reason, service, blocker, duration))

        self.conn.commit()

    def count_blocked_in_subnet(self, subnet_prefix):
        """Count unique IPs with current_tier > 0 that start with the given prefix.
        subnet_prefix should be like '192.0.2.' for a /24 check."""
        cursor = self.conn.execute(
            "SELECT COUNT(*) FROM ip_history WHERE ip LIKE ? AND current_tier > 0",
            (subnet_prefix + '%',)
        )
        return cursor.fetchone()[0]

    def get_blocked_ips_in_subnet(self, subnet_prefix):
        """Get all blocked IPs in a subnet (for logging/alerting)."""
        cursor = self.conn.execute(
            "SELECT ip FROM ip_history WHERE ip LIKE ? AND current_tier > 0",
            (subnet_prefix + '%',)
        )
        return [row['ip'] for row in cursor.fetchall()]

    def get_block_history(self, ip):
        """Get all block records for an IP."""
        cursor = self.conn.execute(
            "SELECT * FROM block_log WHERE ip = ? ORDER BY timestamp DESC", (ip,)
        )
        return cursor.fetchall()

    def get_recent_block(self, ip, lookback_seconds):
        """Check if IP was blocked within the lookback period."""
        cutoff = int(time.time()) - lookback_seconds
        cursor = self.conn.execute(
            "SELECT * FROM block_log WHERE ip = ? AND timestamp > ? ORDER BY timestamp DESC LIMIT 1",
            (ip, cutoff)
        )
        return cursor.fetchone()

    def determine_tier(self, ip, tier2_lookback_seconds):
        """Determine what tier to assign based on block history."""
        ip_data = self.get_ip(ip)

        if not ip_data:
            return 1

        current_tier = ip_data['current_tier']

        # Already permanent
        if current_tier >= 3:
            return 3

        # Check if there's a recent block (within lookback window)
        recent = self.get_recent_block(ip, tier2_lookback_seconds)

        if recent:
            previous_tier = recent['tier']
            if previous_tier >= 2:
                return 3  # Was tier 2, now tier 3 (permanent)
            elif previous_tier >= 1:
                return 2  # Was tier 1, now tier 2 (30 days)

        return 1  # First offense or long time since last block

    # ------------------------------------------------------------------
    # Authenticated Sessions
    # ------------------------------------------------------------------
    def record_auth(self, ip, service, username, site='', country='', city=''):
        """Record a successful authentication."""
        now = int(time.time())
        self.conn.execute("""
            INSERT INTO auth_sessions (ip, timestamp, service, username, site, geoip_country, geoip_city)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (ip, now, service, username, site, country, city))
        self.conn.commit()

    def is_ip_authenticated(self, ip, trust_duration_seconds):
        """Check if IP has a recent successful WordPress login."""
        cutoff = int(time.time()) - trust_duration_seconds
        cursor = self.conn.execute(
            "SELECT 1 FROM auth_sessions WHERE ip = ? AND service = 'wordpress' AND timestamp > ? LIMIT 1",
            (ip, cutoff)
        )
        return cursor.fetchone() is not None

    def get_account_locations(self, username, service):
        """Get all known locations for an account."""
        cursor = self.conn.execute(
            "SELECT DISTINCT geoip_country, geoip_city FROM auth_sessions WHERE username = ? AND service = ?",
            (username, service)
        )
        return cursor.fetchall()

    # ------------------------------------------------------------------
    # Account Baselines
    # ------------------------------------------------------------------
    def update_baseline(self, username, service, country, city=''):
        """Update or create a baseline entry for an account's login location."""
        now = int(time.time())
        existing = self.conn.execute(
            "SELECT id FROM account_baselines WHERE username = ? AND service = ? AND country = ? AND city = ?",
            (username, service, country, city)
        ).fetchone()

        if existing:
            self.conn.execute("""
                UPDATE account_baselines
                SET last_seen = ?, hit_count = hit_count + 1
                WHERE id = ?
            """, (now, existing['id']))
        else:
            self.conn.execute("""
                INSERT INTO account_baselines (username, service, country, city, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (username, service, country, city, now, now))

        self.conn.commit()

    def is_known_location(self, username, service, country):
        """Check if a country is in the account's baseline."""
        cursor = self.conn.execute(
            "SELECT 1 FROM account_baselines WHERE username = ? AND service = ? AND country = ? LIMIT 1",
            (username, service, country)
        )
        return cursor.fetchone() is not None

    def get_last_auth(self, username, service):
        """Get the most recent auth record for an account."""
        cursor = self.conn.execute(
            "SELECT * FROM auth_sessions WHERE username = ? AND service = ? ORDER BY timestamp DESC LIMIT 1",
            (username, service)
        )
        return cursor.fetchone()

    # ------------------------------------------------------------------
    # Tripwires
    # ------------------------------------------------------------------
    def load_tripwires(self):
        """Load all active tripwire paths."""
        cursor = self.conn.execute("SELECT path, category FROM tripwires WHERE active = 1")
        return {row['path']: row['category'] for row in cursor.fetchall()}

    def add_tripwire(self, path, category='unknown'):
        """Add a new tripwire path."""
        now = int(time.time())
        self.conn.execute("""
            INSERT OR REPLACE INTO tripwires (path, category, hit_count, first_seen, last_updated, active)
            VALUES (?, ?, COALESCE((SELECT hit_count FROM tripwires WHERE path = ?), 0), 
                    COALESCE((SELECT first_seen FROM tripwires WHERE path = ?), ?), ?, 1)
        """, (path, category, path, path, now, now))
        self.conn.commit()

    def record_tripwire_hit(self, path):
        """Increment hit count for a tripwire."""
        now = int(time.time())
        self.conn.execute(
            "UPDATE tripwires SET hit_count = hit_count + 1, last_updated = ? WHERE path = ?",
            (now, path)
        )
        self.conn.commit()

    def import_tripwires(self, filepath, category='log-analysis'):
        """Import tripwire paths from a file (one per line). Replaces existing entries."""
        count = 0
        with open(filepath, 'r') as f:
            for line in f:
                path = line.strip()
                if path and not path.startswith('#'):
                    self.add_tripwire(path, category)
                    count += 1
        logger.info(f"Imported {count} tripwires from {filepath}")
        return count

    def import_tripwires_incremental(self, filepath, category='auto-analysis'):
        """
        Import ONLY NEW tripwire paths from a file.
        Existing tripwires are kept untouched. Never removes old entries.
        Returns the number of NEW tripwires added.
        """
        existing = self.get_all_tripwire_paths()
        added = 0

        with open(filepath, 'r') as f:
            for line in f:
                path = line.strip().lower()
                if path and not path.startswith('#'):
                    if path not in existing:
                        self.add_tripwire(path, category)
                        existing.add(path)
                        added += 1

        logger.info(f"Incremental import: {added} new tripwires added from {filepath}")
        return added

    def get_all_tripwire_paths(self):
        """Get all tripwire paths as a set (for incremental import comparison)."""
        cursor = self.conn.execute("SELECT path FROM tripwires")
        return set(row['path'] for row in cursor.fetchall())

    # ------------------------------------------------------------------
    # Whitelist
    # ------------------------------------------------------------------
    def is_whitelisted(self, ip):
        """Check if an IP is in the whitelist (and not expired)."""
        now = int(time.time())
        cursor = self.conn.execute(
            "SELECT 1 FROM whitelist WHERE ip = ? AND (expires_at IS NULL OR expires_at > ?)",
            (ip, now)
        )
        return cursor.fetchone() is not None

    def add_whitelist(self, ip, wl_type='permanent', duration_seconds=None, reason='', added_by='admin'):
        """Add an IP to the whitelist."""
        now = int(time.time())
        expires = now + duration_seconds if duration_seconds else None

        self.conn.execute("""
            INSERT OR REPLACE INTO whitelist (ip, type, added_at, expires_at, reason, added_by)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ip, wl_type, now, expires, reason, added_by))
        self.conn.commit()
        logger.info(f"Whitelisted {ip} ({wl_type}) reason: {reason}")

    def remove_whitelist(self, ip):
        """Remove an IP from the whitelist."""
        self.conn.execute("DELETE FROM whitelist WHERE ip = ?", (ip,))
        self.conn.commit()

    def get_whitelist(self):
        """Get all active whitelist entries."""
        now = int(time.time())
        cursor = self.conn.execute(
            "SELECT * FROM whitelist WHERE expires_at IS NULL OR expires_at > ?", (now,)
        )
        return cursor.fetchall()

    # ------------------------------------------------------------------
    # Login Isolation Tracking
    # ------------------------------------------------------------------
    def login_isolation_record_hit(self, ip):
        """Record a wp-login.php hit. Returns (login_hits, has_css)."""
        now = int(time.time())
        existing = self.conn.execute(
            "SELECT login_hits, has_css FROM login_isolation WHERE ip = ?", (ip,)
        ).fetchone()

        if existing:
            new_count = existing['login_hits'] + 1
            self.conn.execute(
                "UPDATE login_isolation SET login_hits = ?, last_seen = ? WHERE ip = ?",
                (new_count, now, ip)
            )
            self.conn.commit()
            return (new_count, existing['has_css'])
        else:
            self.conn.execute(
                "INSERT INTO login_isolation (ip, first_seen, last_seen, login_hits, has_css) "
                "VALUES (?, ?, ?, 1, 0)",
                (ip, now, now)
            )
            self.conn.commit()
            return (1, 0)

    def login_isolation_record_css(self, ip):
        """Record that this IP has loaded a CSS file (real browser signal)."""
        now = int(time.time())
        existing = self.conn.execute(
            "SELECT 1 FROM login_isolation WHERE ip = ?", (ip,)
        ).fetchone()

        if existing:
            self.conn.execute(
                "UPDATE login_isolation SET has_css = 1, last_seen = ? WHERE ip = ?",
                (now, ip)
            )
        else:
            self.conn.execute(
                "INSERT INTO login_isolation (ip, first_seen, last_seen, login_hits, has_css) "
                "VALUES (?, ?, ?, 0, 1)",
                (ip, now, now)
            )
        self.conn.commit()

    def login_isolation_has_css(self, ip):
        """Check if IP has loaded any CSS (is a real browser)."""
        row = self.conn.execute(
            "SELECT has_css FROM login_isolation WHERE ip = ?", (ip,)
        ).fetchone()
        return row is not None and row['has_css'] == 1

    def login_isolation_cleanup(self, max_age_seconds):
        """Remove login isolation entries older than max_age."""
        cutoff = int(time.time()) - max_age_seconds
        result = self.conn.execute(
            "DELETE FROM login_isolation WHERE last_seen < ?", (cutoff,)
        )
        self.conn.commit()
        return result.rowcount

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def cleanup_expired(self, auth_retention_days=90, history_retention_days=180):
        """Remove old data beyond retention periods."""
        now = int(time.time())
        auth_cutoff = now - (auth_retention_days * 86400)
        history_cutoff = now - (history_retention_days * 86400)

        # Clean old auth sessions
        r1 = self.conn.execute("DELETE FROM auth_sessions WHERE timestamp < ?", (auth_cutoff,))

        # Clean old block logs
        r2 = self.conn.execute("DELETE FROM block_log WHERE timestamp < ?", (history_cutoff,))

        # Clean expired whitelist entries
        r3 = self.conn.execute("DELETE FROM whitelist WHERE expires_at IS NOT NULL AND expires_at < ?", (now,))

        # Clean old baselines
        baseline_cutoff = now - (auth_retention_days * 86400)
        r4 = self.conn.execute("DELETE FROM account_baselines WHERE last_seen < ?", (baseline_cutoff,))

        self.conn.commit()

        total = r1.rowcount + r2.rowcount + r3.rowcount + r4.rowcount
        if total > 0:
            logger.info(f"Cleanup: removed {r1.rowcount} auth sessions, {r2.rowcount} block logs, "
                       f"{r3.rowcount} expired whitelist, {r4.rowcount} old baselines")

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------
    def get_stats(self):
        """Get current statistics."""
        now = int(time.time())
        today_start = now - (now % 86400)

        stats = {}
        stats['total_ips_tracked'] = self.conn.execute("SELECT COUNT(*) FROM ip_history").fetchone()[0]
        stats['total_blocks_today'] = self.conn.execute(
            "SELECT COUNT(*) FROM block_log WHERE timestamp > ?", (today_start,)
        ).fetchone()[0]
        stats['active_tier1'] = self.conn.execute(
            "SELECT COUNT(*) FROM ip_history WHERE current_tier = 1"
        ).fetchone()[0]
        stats['active_tier2'] = self.conn.execute(
            "SELECT COUNT(*) FROM ip_history WHERE current_tier = 2"
        ).fetchone()[0]
        stats['active_tier3'] = self.conn.execute(
            "SELECT COUNT(*) FROM ip_history WHERE current_tier = 3"
        ).fetchone()[0]
        stats['whitelist_count'] = self.conn.execute(
            "SELECT COUNT(*) FROM whitelist WHERE expires_at IS NULL OR expires_at > ?", (now,)
        ).fetchone()[0]
        stats['tripwire_count'] = self.conn.execute(
            "SELECT COUNT(*) FROM tripwires WHERE active = 1"
        ).fetchone()[0]
        stats['auth_sessions_today'] = self.conn.execute(
            "SELECT COUNT(*) FROM auth_sessions WHERE timestamp > ?", (today_start,)
        ).fetchone()[0]

        return stats

    def close(self):
        """Close the database connection."""
        self.conn.close()
