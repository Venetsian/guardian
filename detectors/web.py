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
from modules.config import parse_csv_set
from modules.spa_assets import is_framework_payload


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

        # A 404 storm is a *ratio*, not a count. A browser rendering a site
        # pulls real content alongside its misses; a scanner enumerating one
        # pulls almost nothing that exists. Counting alone is what turned a
        # developer's post-deploy prefetch burst into a 30-day tier-2 block.
        # Require misses to dominate the client's traffic this heavily before
        # calling it a storm.
        self.general_404_min_fail_ratio = config.getfloat(
            'thresholds', 'general_404_min_fail_ratio', fallback=0.9)
        # Framework navigation payloads get their own, far looser budget
        # rather than a blanket exemption — see the branch that uses it.
        self.framework_404_threshold = config.getint(
            'thresholds', 'framework_404_threshold', fallback=400)
        # Ceiling on the guard above: past this many misses in the window,
        # block whatever the ratio says. Stops a high-volume dirbuster from
        # buying immunity by padding its run with pages that exist.
        self.general_404_hard_limit = config.getint(
            'thresholds', 'general_404_hard_limit', fallback=500)

        # Auth tracking
        self.trust_duration = config.getint('auth_tracking', 'wp_trust_duration', fallback=24) * 3600

        # Hit trackers (separate per rule type)
        self.hits_login = HitTracker(self.time_window)
        self.hits_xmlrpc = HitTracker(self.time_window)
        self.hits_author = HitTracker(self.time_window)
        self.hits_php404 = HitTracker(self.time_window)
        self.hits_404 = HitTracker(self.time_window)
        # Successful (2xx/3xx) responses per IP — the denominator of the
        # miss-ratio guard above.
        self.hits_success = HitTracker(self.time_window)
        # Misses on framework navigation payloads, kept apart from hits_404
        # so the two can carry different thresholds.
        self.hits_fw404 = HitTracker(self.time_window)

        # Structural tripwires (always active, no file needed)
        self.structural_patterns = [
            re.compile(r'/wp-content/uploads/.*\.php', re.IGNORECASE),
        ]

        # Pattern tripwires — INSTANT block (known malicious, no legitimate use ever)
        self.instant_patterns = [
            (re.compile(r'/(alfa|c99|r57|wso|b374k|eval-stdin)\.php', re.IGNORECASE), 'Known webshell'),
        ]

        # PHP endpoints that are legitimate application entry points, not scans.
        # The suspicious_patterns below deliberately over-match ordinary
        # endpoint names (any lowercase 6+ letter .php), so this allowlist is
        # what keeps a customer-facing endpoint from becoming a landmine.
        # /index.php is listed explicitly — it was previously safe only by the
        # accident of being 5 characters, missing both length regexes.
        self.legit_short_php = {
            '/api.php', '/ajax.php', '/public.php',
            '/cron.php', '/rss.php', '/feed.php',
            '/client.php', '/index.php',
        }
        # Per-install additions — [whitelist] legit_php_paths. An operator
        # cannot be expected to patch the set above for their own app's
        # /billing.php or /account.php.
        self.legit_short_php |= parse_csv_set(
            config.get('whitelist', 'legit_php_paths', fallback='')
        )

        # Extra build-tool path prefixes for this install, on top of the
        # frameworks modules/spa_assets.py already recognises.
        self.framework_payload_paths = tuple(parse_csv_set(
            config.get('whitelist', 'framework_payload_paths', fallback='')
        ))

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
        self.suspicious_threshold = config.getint('thresholds', 'suspicious_threshold', fallback=3)

        # Which response statuses count as scanning evidence for the rule above.
        # Default is every status the rule has always counted — deny-heavy
        # installs answer scans with 403 (or 401), not 404, and on the Apache
        # host in this fleet 403 outnumbers 404 on these paths by ~100:1.
        # Hosts that instead serve a customer-facing PHP endpoint returning
        # application-level 403s should narrow this to '404'.
        self.suspicious_statuses = parse_csv_set(
            config.get('thresholds', 'suspicious_statuses', fallback='404, 401, 403')
        )

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

        # ----- REAL-CONTENT TRACKING (denominator for the 404-storm ratio) -----
        # Recorded here, ahead of every rule that can return, so a served
        # request counts no matter which branch below handles it.
        if status[:1] in ('2', '3'):
            self.hits_success.add(ip)

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
        if clean_path.endswith('.php') and status in self.suspicious_statuses:
            if clean_path not in self.legit_short_php:
                for pattern in self.suspicious_patterns:
                    if pattern.search(clean_path):
                        # Trust a recently-authenticated IP, same as every
                        # other tripwire branch above. These patterns match
                        # ordinary endpoint names, so a logged-in user hitting
                        # a permission-denied response three times must not be
                        # mistaken for a scanner.
                        if self.db.is_ip_authenticated(ip, self.trust_duration):
                            logging.getLogger('wp-guardian.web').warning(
                                f"Authenticated IP {ip} hit suspicious pattern: {clean_path}"
                            )
                            return
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
            # A framework's own navigation payloads are not path enumeration.
            # After a deploy an SPA re-requests every route it had prefetched
            # and misses on all of them at once — measurements in
            # modules/spa_assets.py. Counted in their own bucket at a far
            # looser threshold rather than exempted outright, so `?_rsc=` is
            # not a token that switches the rule off. Never matches a .php
            # path, so none of the PHP rules above can be reached this way.
            if is_framework_payload(path, clean_path, self.framework_payload_paths):
                count = self.hits_fw404.add(ip)
                threshold = self.framework_404_threshold
                label = 'Framework payload 404 storm'
            else:
                count = self.hits_404.add(ip)
                threshold = self.general_404_threshold
                label = '404 storm'

            # A threshold of 0 means "disabled" everywhere else in this
            # config section; without the guard it would mean "block on the
            # first miss" here.
            if threshold and count >= threshold:
                if not self._is_scanning_ratio(ip, count):
                    return
                self.blocker.block(ip, f"{label} ({count} in {self.time_window}s)", service='web', site=site, rule='general_404')
            return

    def _is_scanning_ratio(self, ip, bucket_count):
        """True when misses dominate this IP's traffic enough to be a scan.

        `bucket_count` is the count of whichever bucket just crossed its
        threshold. The hard limit is checked against that bucket alone, not
        against the two summed: a long rebuild session can pile up several
        hundred payload misses beside a normal handful of plain ones, and
        summing them would put a developer back over the ceiling that exists
        to catch enumeration.

        The ratio itself does use both buckets — a client is one client
        whichever shape its failures take.
        """
        if bucket_count >= self.general_404_hard_limit:
            return True

        misses = self.hits_404.get_count(ip) + self.hits_fw404.get_count(ip)

        successes = self.hits_success.get_count(ip)
        total = misses + successes
        if total <= 0:
            return True

        ratio = float(misses) / total
        if ratio >= self.general_404_min_fail_ratio:
            return True

        logging.getLogger('wp-guardian.web').info(
            "%s reached %d misses in %ds but was served %d real responses "
            "(miss ratio %.2f < %.2f) — browsing a broken build, not scanning",
            ip, misses, self.time_window, successes, ratio,
            self.general_404_min_fail_ratio
        )
        return False
