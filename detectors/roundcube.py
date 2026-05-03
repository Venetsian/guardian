"""Roundcube webmail error log detector.

Parses /var/www/roundcube/logs/errors.log for failed webmail logins.

v1.5: extracted from wp-guardian.py with no behavior change.
"""

import re
import logging

from .base import HitTracker


class RoundcubeDetector:
    """Parses Roundcube errors.log for failed webmail logins.

    Log line example:
        [14-Apr-2026 15:11:15 +0000]: <abc> IMAP Error: Login failed for
        user@example.com against localhost from 198.51.100.21. ...
    """

    _FAIL_RE = re.compile(
        r'IMAP Error:\s*Login failed for (?P<user>\S+) against \S+ from (?P<ip>\d+\.\d+\.\d+\.\d+)'
    )

    def __init__(self, config, blocker, db, whitelist=None):
        self.blocker = blocker
        self.db = db
        self.whitelist = whitelist
        self.time_window = config.getint('thresholds', 'time_window', fallback=300)
        self.threshold = config.getint('thresholds', 'roundcube_fail_threshold', fallback=10)
        self.trust_duration = config.getint('auth_tracking', 'mail_trust_duration', fallback=24) * 3600
        self.hits = HitTracker(self.time_window)

    def process_line(self, line):
        m = self._FAIL_RE.search(line)
        if not m:
            return
        ip = m.group('ip')
        username = m.group('user')

        if self.whitelist and self.whitelist.is_whitelisted(ip):
            return

        count = self.hits.add(ip)
        if count >= self.threshold:
            if self.db.is_ip_authenticated(ip, self.trust_duration):
                logging.getLogger('wp-guardian.roundcube').warning(
                    "Authenticated IP {ip} hit Roundcube fail threshold ({c} in {w}s, last user={u}) — not blocking".format(
                        ip=ip, c=count, w=self.time_window, u=username
                    )
                )
                self.blocker.alert_trusted_skip(ip, 'roundcube', count, self.time_window, username)
                return
            self.blocker.block(
                ip,
                "Roundcube auth brute force ({c} fails in {w}s, last user={u})".format(
                    c=count, w=self.time_window, u=username
                ),
                service='roundcube',
                username=username,
                rule='roundcube',
            )
