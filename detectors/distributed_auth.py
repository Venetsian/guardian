"""Distributed-auth compromise detector (v1.4+).

Watches successful authentications across services and flags accounts
showing distributed-source patterns indicative of credential compromise.

Not a process_line detector — fed by a callback from MailDetector,
SSHDetector, and the backfill tool after every successful auth.

v1.5: extracted from wp-guardian.py with no behavior change.
"""

import re
import time
import logging

from modules.config import parse_asn_list


class DistributedAuthDetector:
    """Watches successful authentications across services and flags accounts
    showing distributed-source patterns indicative of credential compromise.

    Not a process_line detector — it's fed by a callback from MailDetector,
    SSHDetector, and the backfill tool after every successful auth.
    """

    def __init__(self, config, db, compromise_action):
        self.enabled = config.getboolean(
            'compromise_detection', 'enabled', fallback=False
        )
        self.db = db
        self.compromise_action = compromise_action
        self.window_seconds = config.getint(
            'compromise_detection', 'window_seconds', fallback=3600
        )
        self.threshold_countries = config.getint(
            'compromise_detection', 'threshold_distinct_countries', fallback=3
        )
        self.threshold_asns = config.getint(
            'compromise_detection', 'threshold_distinct_asns', fallback=5
        )
        self.threshold_ips = config.getint(
            'compromise_detection', 'threshold_distinct_ips', fallback=20
        )
        self.suppression_seconds = config.getint(
            'compromise_detection', 'suppression_seconds', fallback=1800
        )

        # Trusted ASNs — excluded from country / ASN counts but NOT IP count.
        # Cloud mail providers (Microsoft 365, Google Workspace, iCloud) relay
        # the same user through DCs in many countries; without this filter
        # legitimate users repeatedly trip threshold_distinct_countries.
        # Parsed via the shared helper so the enforcement side (Blocker,
        # CompromiseAction) reads exactly the same list — the split between
        # "not evidence" and "still blockable" was the Outlook bug.
        self.trusted_asns = parse_asn_list(
            config.get('compromise_detection', 'trusted_asns',
                       fallback='8075, 15169, 714')
        )

        # Exclude regex list (one pattern per line in config)
        excl_raw = config.get('compromise_detection', 'exclude_usernames', fallback='')
        self._exclude_regexes = []
        for line in excl_raw.splitlines():
            pattern = line.strip()
            if pattern and not pattern.startswith('#'):
                try:
                    self._exclude_regexes.append(re.compile(pattern, re.IGNORECASE))
                except re.error as e:
                    logging.getLogger('wp-guardian.compromise-detector').warning(
                        "Invalid exclude_usernames regex '{p}': {e}".format(p=pattern, e=e)
                    )

        self._suppressed = {}  # username -> epoch expiry
        self._logger = logging.getLogger('wp-guardian.compromise-detector')

    def on_successful_auth(self, username, ip, service, geo):
        """Called after every successful auth. Must be fast."""
        if not self.enabled:
            return
        if not username:
            return
        if self._is_excluded(username):
            return
        if self._is_suppressed(username):
            return

        # Need at least some geo data for the country/asn rules to be meaningful;
        # the IP rule still works without.
        try:
            counts = self.db.distinct_auth_counts(
                username, self.window_seconds,
                trusted_asns=self.trusted_asns,
            )
        except Exception as e:
            self._logger.error("distinct_auth_counts failed: {e}".format(e=e))
            return

        triggered = None
        if counts['countries'] >= self.threshold_countries:
            triggered = 'countries'
        elif counts['asns'] >= self.threshold_asns:
            triggered = 'asns'
        elif counts['ips'] >= self.threshold_ips:
            triggered = 'ips'

        if not triggered:
            return

        self._mark_suppressed(username)
        self._logger.warning(
            "Compromise trigger: user={u} rule={r} counts={c}".format(
                u=username, r=triggered, c=counts
            )
        )
        try:
            self.compromise_action.handle(
                username=username,
                service=service or 'unknown',
                trigger_rule=triggered,
                counts=counts,
                window_seconds=self.window_seconds,
            )
        except Exception as e:
            self._logger.error("CompromiseAction.handle failed: {e}".format(e=e))

    def _is_excluded(self, username):
        for rx in self._exclude_regexes:
            if rx.search(username):
                return True
        return False

    def _is_suppressed(self, username):
        expires = self._suppressed.get(username)
        if not expires:
            return False
        if time.time() > expires:
            del self._suppressed[username]
            return False
        return True

    def _mark_suppressed(self, username):
        self._suppressed[username] = time.time() + self.suppression_seconds
