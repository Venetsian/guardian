"""Web access log detector.

Parses web access logs (currently OpenLiteSpeed format with outer quotes)
and runs the WordPress-focused detection pipeline.

v1.5: extracted from wp-guardian.py with no behavior change. v1.6+ will
split this into universal/wordpress/joomla/drupal modules driven by the
CMSRegistry.
"""

import re
import time
import logging
from urllib.parse import parse_qs

from .base import HitTracker
from .log_formats import parse_line
from modules.config import parse_csv_set
from modules.spa_assets import is_framework_payload


# Extensions that only a rendering browser fetches. Login isolation originally
# keyed on `.css` alone, which produced confirmed false positives on real
# customers: the login stylesheet carries a `?ver=` cache buster and a far-future
# max-age, so a returning admin re-opens wp-login.php with every stylesheet
# already in cache and issues zero `.css` requests. A CDN in front of the site
# (or a 503 that stops WordPress rendering at all) removes the signal the same
# way. Measured on wp.maiahost.com: of 60 datacenter IPs blocked by this rule,
# 59 fetched not one of these — widening the signal costs ~1.7% of the rule's
# reach and rescues every browser that merely had a warm cache.
_BROWSER_ASSET_EXT = (
    '.css', '.js', '.mjs',
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.avif', '.ico', '.bmp',
    '.woff', '.woff2', '.ttf', '.otf', '.eot',
)


def is_browser_asset(clean_path):
    """True when the path is a static asset only a rendering client requests.

    `clean_path` is already lowercased with the query string stripped by
    parse_line(), so a plain suffix test is enough.
    """
    return clean_path.endswith(_BROWSER_ASSET_EXT)


# A 302 from `POST wp-login.php` is what a successful login looks like in the
# access log, but it is not proof of one. Stock WordPress answers
# `action=postpass` (with any same-site Referer) with a 302 whatever the
# password, and because WordPress reads `action` from $_REQUEST the same can be
# sent in the POST *body*, where the log never shows it. So the redirect only
# nominates a login; trust is granted when the same client then gets a 200 from
# an admin page an anonymous client cannot load (WebDetector._track_wp_login).
LOGIN_CONFIRM_WINDOW = 120
# Cap on unconfirmed candidates held in memory; scanners POST wp-login.php
# from many addresses and most of those logins never confirm.
MAX_PENDING_LOGINS = 5000
# What WebDetector._track_wp_login reports for a login candidate.
_LOGIN_FIRST = 'first'
_LOGIN_REPEAT = 'repeat'

# `action` values WordPress core routes to something other than the login
# handler. Anything else — including unknown values — falls through to the
# login handler in core, so those stay candidates.
_NON_LOGIN_ACTIONS = frozenset((
    'postpass', 'logout', 'lostpassword', 'retrievepassword', 'resetpass',
    'rp', 'register', 'confirm_admin_email', 'confirmaction', 'checkemail',
    'entered_recovery_mode',
))

# Admin screens that answer 200 only to a logged-in session (anonymous clients
# are redirected to wp-login.php). Deliberately NOT listed, because they answer
# 200 to anyone: admin-ajax.php, admin-post.php, load-styles.php,
# load-scripts.php, install.php, upgrade.php, setup-config.php, maint/*, and
# the static assets under /wp-admin/. `search`, not `match`, so /blog/wp-admin/
# installs count.
_ADMIN_SESSION_PAGE = re.compile(
    r'/wp-admin/?$'
    r'|/wp-admin/(?:index|admin|edit|post|post-new|upload|plugins|themes|users'
    r'|profile|edit-comments|update-core|tools|options-general|nav-menus'
    r'|widgets|customize|site-editor|edit-tags|plugin-install|theme-install'
    r'|user-edit|about)\.php$'
)


# Endpoints under /wp-admin/ that serve anonymous front-end traffic.
_PUBLIC_ADMIN_ENDPOINTS = ('/wp-admin/admin-ajax.php', '/wp-admin/admin-post.php')


def is_login_candidate(method, path, clean_path, status):
    """True when a request looks like a successful WordPress login.

    A candidate is a POST answered 302 on wp-login.php itself (subdirectory
    installs included, look-alikes such as /anything-wp-login.php excluded)
    whose query-string `action` is not one of WordPress's non-login actions.
    It is only a candidate: see LOGIN_CONFIRM_WINDOW.
    """
    if method != 'POST' or status != '302':
        return False
    if not clean_path.endswith('/wp-login.php'):
        return False
    query = path.partition('?')[2]
    if query:
        # Any occurrence counts: PHP keeps only the last duplicate, so which
        # one WordPress acts on is not worth guessing at.
        for value in parse_qs(query).get('action', ()):
            if value.lower() in _NON_LOGIN_ACTIONS:
                return False
    return True


def is_admin_session_page(clean_path):
    """True for an admin page that only a logged-in session gets a 200 from."""
    return _ADMIN_SESSION_PAGE.search(clean_path) is not None


# Rejected, with the measurement, so nobody re-proposes it: treating
# `GET wp-login.php -> 302` as proof of an already-logged-in visitor. It reads
# well — WordPress does bounce a valid auth cookie to the dashboard — but on
# 55k replayed lines it removed 1% of false positives while losing 13% of bot
# detection. Plenty of sites redirect wp-login.php for *everyone* (hidden-login
# plugins, http->https, canonical host), so bots collect that 302 too.


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
        # (ip, site) -> time of a login candidate still awaiting confirmation.
        self._pending_logins = {}

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
            self._track_wp_login(ip, site, method, path, clean_path, status)
            return

        # ----- LOGIN ISOLATION: track browser assets (real browser signal) -----
        # Any static asset, not just `.css` — see is_browser_asset().
        if is_browser_asset(clean_path):
            self.db.login_isolation_record_css(ip)

        # ----- REAL-CONTENT TRACKING (denominator for the 404-storm ratio) -----
        # Recorded here, ahead of every rule that can return, so a served
        # request counts no matter which branch below handles it.
        if status[:1] in ('2', '3'):
            self.hits_success.add(ip)

        # ----- AUTHENTICATION TRACKING -----
        # Must run before the safe-path skip below: the confirming request is
        # itself a /wp-admin/ page.
        login_state = self._track_wp_login(ip, site, method, path, clean_path, status)
        if login_state == _LOGIN_FIRST:
            return
        # A repeat candidate falls through: the earlier one never confirmed, so
        # it was a failed attempt and this line counts like any other wp-login
        # POST (login isolation below, brute force further down).
        repeat_login = login_state == _LOGIN_REPEAT

        # ----- KNOWN WEBSHELLS (instant block, everyone) -----
        # Ahead of the safe-path skip: /wp-admin/ and /wp-includes/ are the
        # usual places to plant a shell, so exempting them hid the probes. No
        # legitimate client ever asks for these names, so unlike the tripwire
        # rules below a logged-in session does not buy an exemption.
        if clean_path.endswith('.php'):
            for pattern, description in self.instant_patterns:
                if pattern.search(clean_path):
                    if self.db.is_ip_authenticated(ip, self.trust_duration):
                        logging.getLogger('wp-guardian.web').warning(
                            f"Authenticated IP {ip} hit instant pattern: {description} ({clean_path}) — blocking anyway"
                        )
                    self.blocker.block(ip, f"{description}: {clean_path}", service='web', site=site, rule='instant')
                    return

        # ----- TRIPWIRE RULES (instant block for non-authenticated) -----

        # Skip safe paths (wp-admin, wp-includes — legitimate to browse), but
        # still count PHP misses there: scanners probe these directories too.
        # 404/401 only — 403 is what sites with an .htaccess IP restriction on
        # wp-admin answer the operator's own secondary address with. The
        # public AJAX endpoints are left out: front-end plugins poll them for
        # anonymous visitors and some answer those with 401.
        for pattern in self.safe_path_patterns:
            if pattern.search(clean_path):
                if (clean_path.endswith('.php') and status in ('404', '401')
                        and not clean_path.endswith(_PUBLIC_ADMIN_ENDPOINTS)
                        and not self.db.is_ip_authenticated(ip, self.trust_duration)):
                    count = self.hits_php404.add(ip)
                    if count >= self.php_404_threshold:
                        self.blocker.block(ip, f"PHP scanning ({count} 404s in {self.time_window}s)", service='web', site=site, rule='php_scan')
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
        # Two other candidate fixes were measured and rejected here: skipping
        # 5xx responses (kept 55% of bot detection, removed 1% more FPs) and a
        # sliding hit window (bots pace wp-login hits slowly, so any window
        # short enough to help a human gutted the rule — 120s kept 34%). The
        # durable browser memory below does the job without either.
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

        # wp-login.php brute force. A 302 is normally a login, so it is not a
        # failure — unless it repeats an earlier 302 that never confirmed.
        if 'wp-login.php' in clean_path and method == 'POST' and (status != '302' or repeat_login):
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

    def _track_wp_login(self, ip, site, method, path, clean_path, status):
        """Two-step WordPress login tracking.

        A candidate (see is_login_candidate) is only remembered. The IP becomes
        authenticated when a later 200 from an admin session page arrives for
        the same (ip, site) inside LOGIN_CONFIRM_WINDOW, which also clears the
        pending entry.

        Returns _LOGIN_FIRST for a candidate with nothing pending: the caller
        skips the rest of the pipeline, so one stray redirect (a real user's
        mistyped password, say) is never counted. Returns _LOGIN_REPEAT for a
        candidate while an earlier one is still pending, however old: that
        earlier login evidently failed, so the caller keeps processing the
        line as a failed attempt. Every other line returns None.
        """
        key = (ip, site)
        started = self._pending_logins.get(key)
        if started is not None and status == '200' and is_admin_session_page(clean_path):
            del self._pending_logins[key]
            if time.time() - started <= LOGIN_CONFIRM_WINDOW:
                wp_user = 'wp@{s}'.format(s=site) if site else 'wp@unknown'
                self.db.record_auth(ip, 'wordpress', wp_user, site=site, country='', city='')
            return None

        if is_login_candidate(method, path, clean_path, status):
            self._remember_login_candidate(key)
            return _LOGIN_FIRST if started is None else _LOGIN_REPEAT
        return None

    def _remember_login_candidate(self, key):
        """Store a candidate, keeping the pending map bounded."""
        pending = self._pending_logins
        now = time.time()
        pending[key] = now
        if len(pending) > MAX_PENDING_LOGINS:
            cutoff = now - LOGIN_CONFIRM_WINDOW
            for stale in [k for k, ts in pending.items() if ts < cutoff]:
                del pending[stale]
            if len(pending) > MAX_PENDING_LOGINS:
                oldest = sorted(pending, key=pending.get)[:len(pending) // 2]
                for k in oldest:
                    del pending[k]

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
