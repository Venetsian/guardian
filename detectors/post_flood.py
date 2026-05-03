"""POST-flood detector (v1.5).

A two-stage gate that catches generic POST flooding to admin/auth endpoints
without false-positiving on legitimate high-traffic forms.

Stage 1 — rate gate
    threshold POSTs to a watched URL from one IP within the configured window.

Stage 2 — behavioral confirmation (configurable; on by default)
    At least one of:
      A) Zero CSS loads from this IP (real browsers always fetch CSS for
         the page that hosts the form).
      C) >= behavioral_referer_pct of recent POSTs have a missing or
         off-host Referer header.
      D) >= behavioral_content_length_pct of recent POSTs share the same
         Content-Length value (bots reuse the same payload; humans don't).

Note on the v1.5 plan's signal B ("zero successful auth in 24h"): in
practice this is redundant with the trusted-IP exemption that runs before
the gate (any IP that authenticated in the trust window short-circuits
the whole detector with a heads-up alert), so it's omitted here. A/C/D
are the discriminating signals.

The detector consults the CMSRegistry to know which paths to watch per
site, plus a universal fallback list (/login, /signin, /phpmyadmin/, etc.)
that's always on. WordPress's wp-login.php is intentionally NOT watched
here because the dedicated wp_login rule already covers it.

Block decisions are tier-1 only at first. After observing 2+ weeks of clean
data we can re-enable normal escalation.
"""

import time
import logging
from collections import defaultdict


_log = logging.getLogger('wp-guardian.post-flood')


# Universal admin/auth paths watched on every vhost regardless of CMS.
# Operator can add more via [post_flood] universal_paths in config.
DEFAULT_UNIVERSAL_PATHS = [
    '/phpmyadmin/',
    '/cpanel',
    '/login',
    '/signin',
    '/admin/login',
    '/admin/index.php',
]


class PostFloodTracker:
    """Per (ip, url) sliding window of POST observations.

    Each observation is (timestamp, referer, content_length). We keep the
    raw observations rather than just a counter so the behavioral signals
    can inspect the recent samples.
    """

    def __init__(self, window_seconds):
        self.window = window_seconds
        self._obs = defaultdict(list)

    def record(self, ip, url, referer, content_length):
        now = time.time()
        key = (ip, url)
        self._obs[key].append((now, referer, content_length))
        cutoff = now - self.window
        self._obs[key] = [o for o in self._obs[key] if o[0] > cutoff]
        return self._obs[key]

    def cleanup(self):
        now = time.time()
        cutoff = now - self.window
        stale = [k for k, obs in self._obs.items() if not obs or obs[-1][0] < cutoff]
        for k in stale:
            del self._obs[k]


class PostFloodDetector:
    """Watchlist-only POST flood detector with a two-stage gate."""

    def __init__(self, config, blocker, db, whitelist=None, cms_registry=None):
        self.blocker = blocker
        self.db = db
        self.whitelist = whitelist
        self.cms_registry = cms_registry

        self.enabled = config.getboolean('post_flood', 'enabled', fallback=False)
        self.threshold = config.getint('post_flood', 'threshold', fallback=30)
        self.window = config.getint('post_flood', 'window', fallback=300)
        self.behavioral_required = config.getboolean(
            'post_flood', 'behavioral_required', fallback=True
        )
        self.referer_pct = config.getint('post_flood', 'behavioral_referer_pct', fallback=80)
        self.content_length_pct = config.getint(
            'post_flood', 'behavioral_content_length_pct', fallback=80
        )
        self.trust_duration = config.getint(
            'auth_tracking', 'wp_trust_duration', fallback=24
        ) * 3600

        # Universal paths — always watched. Operator can extend via config.
        extra_raw = config.get('post_flood', 'universal_paths', fallback='')
        extra = [p.strip().lower() for p in extra_raw.split(',') if p.strip()]
        self._universal_paths = [p.lower() for p in DEFAULT_UNIVERSAL_PATHS] + extra

        self._tracker = PostFloodTracker(self.window)

        # Dedupe: once we block (ip, url), suppress further blocks for the
        # remainder of the window so we don't alert on every subsequent POST.
        self._recent_blocks = {}

    # ----- Public API -----

    def evaluate(self, parsed, site=''):
        """Called by the web pipeline for every parsed access-log line.

        parsed: dict produced by detectors.log_formats.parse_line()
        site:   site name (from tail --verbose header)
        """
        if not self.enabled:
            return

        method = parsed.get('method', '')
        if method != 'POST':
            return

        ip = parsed.get('ip', '')
        clean_path = parsed.get('clean_path', '')
        if not ip or not clean_path:
            return

        if self.whitelist and self.whitelist.is_whitelisted(ip):
            return

        if not self._is_watched(site, clean_path):
            return

        # Stage 1: rate gate
        observations = self._tracker.record(
            ip, clean_path,
            parsed.get('referer', '') or '',
            parsed.get('size', '') or '',
        )
        if len(observations) < self.threshold:
            return

        # Trusted-IP exemption — covers the v1.5-plan signal B by short-circuiting.
        if self.db.is_ip_authenticated(ip, self.trust_duration):
            _log.warning(
                "Trusted IP %s hit POST-flood gate on %s (%d POSTs in %ds) — not blocking",
                ip, clean_path, len(observations), self.window,
            )
            try:
                self.blocker.alert_trusted_skip(ip, 'post_flood', len(observations), self.window, '')
            except Exception:
                pass
            return

        # Stage 2: behavioral confirmation
        if self.behavioral_required:
            signals = self._behavioral_signals(ip, observations, site)
            if not signals:
                _log.debug(
                    "POST-flood rate exceeded for %s on %s (%d/%d) but no behavioral signal — not blocking",
                    ip, clean_path, len(observations), self.window,
                )
                return
            reason_signals = ','.join(signals)
        else:
            reason_signals = 'rate-only'

        # Dedupe — one block per (ip, url) per window
        key = (ip, clean_path)
        last = self._recent_blocks.get(key, 0)
        if time.time() - last < self.window:
            return
        self._recent_blocks[key] = time.time()

        self.blocker.block(
            ip,
            "POST flood ({n} POSTs to {p} in {w}s; signals={s})".format(
                n=len(observations), p=clean_path, w=self.window, s=reason_signals,
            ),
            service='web',
            site=site,
            rule='post_flood',
        )

    # ----- Internals -----

    def _is_watched(self, site, clean_path):
        """Return True if this path is on the watch list for this site."""
        if self.cms_registry:
            entry = self.cms_registry.get(site)
            cms = entry.get('cms', 'unknown')
            for ap in entry.get('admin_paths', []):
                if not ap:
                    continue
                if clean_path == ap or clean_path.startswith(ap + '/') or \
                   (ap.endswith('/') and clean_path.startswith(ap)):
                    # WordPress wp-login is already covered by the dedicated rule.
                    if cms == 'wordpress' and 'wp-login.php' in clean_path:
                        return False
                    return True

        for up in self._universal_paths:
            if clean_path == up or clean_path.startswith(up + '/') or \
               (up.endswith('/') and clean_path.startswith(up)):
                return True
        return False

    def _behavioral_signals(self, ip, observations, site):
        """Return a list of triggered signal names. Empty list = no signal fired."""
        signals = []

        # Signal A: no CSS loads in last hour. login_isolation tracks this
        # cheaply — has_css stays 1 until the row ages out (default 48h).
        try:
            if not self.db.login_isolation_has_css(ip):
                signals.append('no_css')
        except Exception as e:
            _log.debug("login_isolation_has_css failed for %s: %s", ip, e)

        # Signal C: off-host referer ratio.
        if observations:
            host = (site or '').lower()
            offhost = 0
            for _, ref, _ in observations:
                ref_l = (ref or '').lower()
                if not ref_l or ref_l == '-':
                    offhost += 1
                elif host and host not in ref_l:
                    offhost += 1
            pct = (offhost * 100) // len(observations)
            if pct >= self.referer_pct:
                signals.append('offhost_referer={pct}%'.format(pct=pct))

        # Signal D: identical content_length ratio.
        if observations:
            counts = defaultdict(int)
            for _, _, cl in observations:
                if cl:  # skip blanks — '-' or '' don't count toward uniformity
                    counts[cl] += 1
            if counts:
                most_common = max(counts.values())
                pct = (most_common * 100) // len(observations)
                if pct >= self.content_length_pct:
                    signals.append('uniform_size={pct}%'.format(pct=pct))

        return signals

    def cleanup(self):
        """Periodic cleanup hook — call from the main loop."""
        self._tracker.cleanup()
        # Prune recent_blocks too
        cutoff = time.time() - self.window
        stale = [k for k, t in self._recent_blocks.items() if t < cutoff]
        for k in stale:
            del self._recent_blocks[k]
