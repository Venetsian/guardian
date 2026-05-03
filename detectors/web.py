"""Web access log detector.

Parses web access logs (currently OpenLiteSpeed format with outer quotes)
and runs the WordPress-focused detection pipeline.

v1.5: extracted from wp-guardian.py with no behavior change. v1.6+ will
split this into universal/wordpress/joomla/drupal modules driven by the
CMSRegistry.
"""

import re
import logging

from .base import HitTracker
from .log_formats import parse_line


class WebDetector:
    """Parses web access logs and detects attacks."""

    def __init__(self, config, blocker, db, tripwires, whitelist=None,
                 post_flood_detector=None, cms_registry=None):
        self.blocker = blocker
        self.db = db
        self.tripwires = tripwires
        self.whitelist = whitelist
        self.post_flood_detector = post_flood_detector
        self.cms_registry = cms_registry
        self.time_window = config.getint('thresholds', 'time_window', fallback=300)

        # Thresholds
        self.wp_login_threshold = config.getint('thresholds', 'wp_login_threshold', fallback=10)
        self.xmlrpc_threshold = config.getint('thresholds', 'xmlrpc_threshold', fallback=5)
        self.author_enum_threshold = config.getint('thresholds', 'author_enum_threshold', fallback=8)
        self.php_404_threshold = config.getint('thresholds', 'php_404_threshold', fallback=20)
        self.general_404_threshold = config.getint('thresholds', 'general_404_threshold', fallback=50)

        # Auth tracking
        self.trust_duration = config.getint('auth_tracking', 'wp_trust_duration', fallback=24) * 3600

        # Hit trackers (separate per rule type)
        self.hits_login = HitTracker(self.time_window)
        self.hits_xmlrpc = HitTracker(self.time_window)
        self.hits_author = HitTracker(self.time_window)
        self.hits_php404 = HitTracker(self.time_window)
        self.hits_404 = HitTracker(self.time_window)

        # Structural tripwires (always active, no file needed)
        self.structural_patterns = [
            re.compile(r'/wp-content/uploads/.*\.php', re.IGNORECASE),
        ]

        # Pattern tripwires — INSTANT block (known malicious, no legitimate use ever)
        self.instant_patterns = [
            (re.compile(r'/(alfa|c99|r57|wso|b374k|eval-stdin)\.php', re.IGNORECASE), 'Known webshell'),
        ]

        # Short PHP filenames that are legitimate (not suspicious)
        self.legit_short_php = {
            '/api.php', '/ajax.php', '/public.php',
            '/cron.php', '/rss.php', '/feed.php',
        }

        # Paths that should NEVER be tripwires (legitimate WordPress/app paths)
        self.safe_path_patterns = [
            re.compile(r'^/wp-admin/'),           # All WordPress admin pages
            re.compile(r'^/wp-includes/'),         # WordPress core includes
            re.compile(r'^.*/wp-admin/'),          # Subdir WP admin (e.g., /blog/wp-admin/)
        ]

        # Pattern tripwires — THRESHOLD based (suspicious but could be a mistake)
        self.suspicious_patterns = [
            re.compile(r'^/[a-z0-9]{1,4}\.php$'),
            re.compile(r'^/[a-z]{6,}\.php$'),
            re.compile(r'/wp-content/themes/[^/]+/(db|admin|shell|config|cmd)\.php', re.IGNORECASE),
            re.compile(r'^/(wp-good|wp-plain|xmrlpc)\.php$'),
        ]

        self.hits_suspicious = HitTracker(self.time_window)
        self.suspicious_threshold = 3

        # Login isolation detection
        self.login_isolation_threshold = config.getint('thresholds', 'login_isolation_threshold', fallback=3)
        self.login_isolation_window = config.getint('thresholds', 'login_isolation_window', fallback=120)

    def process_line(self, line, site=''):
        """Process a single access log line."""
        parsed = parse_line(line)
        if not parsed:
            return

        ip = parsed['ip']
        method = parsed['method']
        path = parsed['path']
        status = parsed['status']
        clean_path = parsed['clean_path']

        # Feed POST-flood detector first — it has its own watchlist and runs
        # regardless of CMS, including before the WP-specific pipeline below.
        if self.post_flood_detector is not None:
            try:
                self.post_flood_detector.evaluate(parsed, site=site)
            except Exception as e:
                logging.getLogger('wp-guardian.web').error(
                    "post_flood evaluate error for %s: %s", ip, e
                )

        # ----- WHITELIST EARLY BYPASS -----
        # Skip all detection for whitelisted IPs, but still record successful WP logins
        if self.whitelist and self.whitelist.is_whitelisted(ip):
            if method == 'POST' and 'wp-login.php' in clean_path and status == '302':
                wp_user = 'wp@{s}'.format(s=site) if site else 'wp@unknown'
                self.db.record_auth(ip, 'wordpress', wp_user, site=site, country='', city='')
            return

        # ----- LOGIN ISOLATION: track CSS loads (real browser signal) -----
        if clean_path.endswith('.css'):
            self.db.login_isolation_record_css(ip)

        # ----- AUTHENTICATION TRACKING -----
        if method == 'POST' and 'wp-login.php' in clean_path and status == '302':
            wp_user = 'wp@{s}'.format(s=site) if site else 'wp@unknown'
            self.db.record_auth(ip, 'wordpress', wp_user, site=site, country='', city='')
            return

        # ----- TRIPWIRE RULES (instant block for non-authenticated) -----

        # Skip safe paths (wp-admin, wp-includes — always legitimate)
        for pattern in self.safe_path_patterns:
            if pattern.search(clean_path):
                return

        # Check structural tripwires first (e.g., PHP in uploads)
        for pattern in self.structural_patterns:
            if pattern.search(clean_path):
                if self.db.is_ip_authenticated(ip, self.trust_duration):
                    logging.getLogger('wp-guardian.web').warning(
                        f"Authenticated IP {ip} hit structural tripwire: {clean_path}"
                    )
                    return
                self.blocker.block(ip, f"PHP in uploads: {clean_path}", service='web', site=site, rule='structural')
                return

        # Check instant-block patterns (known webshells)
        if clean_path.endswith('.php'):
            for pattern, description in self.instant_patterns:
                if pattern.search(clean_path):
                    if self.db.is_ip_authenticated(ip, self.trust_duration):
                        logging.getLogger('wp-guardian.web').warning(
                            f"Authenticated IP {ip} hit instant pattern: {description} ({clean_path})"
                        )
                        return
                    self.blocker.block(ip, f"{description}: {clean_path}", service='web', site=site, rule='instant')
                    return

        # Check suspicious patterns (threshold-based)
        if clean_path.endswith('.php') and status in ('404', '401', '403'):
            if clean_path not in self.legit_short_php:
                for pattern in self.suspicious_patterns:
                    if pattern.search(clean_path):
                        count = self.hits_suspicious.add(ip)
                        if count >= self.suspicious_threshold:
                            self.blocker.block(ip, f"Suspicious PHP scanning ({count} pattern hits in {self.time_window}s)", service='web', site=site, rule='suspicious')
                        return

        # Check file-based tripwires (PHP only)
        if clean_path.endswith('.php') and clean_path in self.tripwires:
            if self.db.is_ip_authenticated(ip, self.trust_duration):
                logging.getLogger('wp-guardian.web').warning(
                    f"Authenticated IP {ip} hit tripwire: {clean_path}"
                )
                return
            self.db.record_tripwire_hit(clean_path)
            self.blocker.block(ip, f"Tripwire: {clean_path}", service='web', site=site, rule='tripwire')
            return

        # ----- LOGIN ISOLATION DETECTION -----
        if 'wp-login.php' in clean_path:
            if not self.db.is_ip_authenticated(ip, self.trust_duration):
                login_hits, has_css = self.db.login_isolation_record_hit(ip)
                if login_hits >= self.login_isolation_threshold and not has_css:
                    self.blocker.block(
                        ip,
                        f"Login isolation: {login_hits} wp-login.php hits, zero CSS loads",
                        service='web',
                        site=site,
                        rule='login_isolation'
                    )
                    return

        # ----- THRESHOLD RULES -----

        # wp-login.php brute force
        if 'wp-login.php' in clean_path and method == 'POST' and status != '302':
            count = self.hits_login.add(ip)
            if count >= self.wp_login_threshold:
                self.blocker.block(ip, f"wp-login brute force ({count} in {self.time_window}s)", service='web', site=site, rule='wp_login')
            return

        # xmlrpc.php
        if 'xmlrpc.php' in clean_path:
            count = self.hits_xmlrpc.add(ip)
            if count >= self.xmlrpc_threshold:
                self.blocker.block(ip, f"xmlrpc abuse ({count} in {self.time_window}s)", service='web', site=site, rule='xmlrpc')
            return

        # Author enumeration
        if re.search(r'\?author=\d', path):
            count = self.hits_author.add(ip)
            if count >= self.author_enum_threshold:
                self.blocker.block(ip, f"Author enumeration ({count} in {self.time_window}s)", service='web', site=site, rule='author_enum')
            return

        # PHP file 404s
        if status in ('404', '401') and clean_path.endswith('.php'):
            count = self.hits_php404.add(ip)
            if count >= self.php_404_threshold:
                self.blocker.block(ip, f"PHP scanning ({count} 404s in {self.time_window}s)", service='web', site=site, rule='php_scan')
            return

        # General 404 storm
        if status in ('404', '403'):
            count = self.hits_404.add(ip)
            if count >= self.general_404_threshold:
                self.blocker.block(ip, f"404 storm ({count} in {self.time_window}s)", service='web', site=site, rule='general_404')
            return
