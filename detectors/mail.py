"""Mail log detector — Postfix SMTP + Dovecot IMAP/POP3.

v1.5: extracted from wp-guardian.py with no behavior change.
"""

import re
import logging

from .base import HitTracker, is_guardian_disabled_client


class MailDetector:
    """Parses /var/log/maillog for SMTP and IMAP/POP3 attacks."""

    def __init__(self, config, blocker, db, whitelist=None,
                 geoip=None, distributed_auth_detector=None,
                 corroborator=None):
        self.blocker = blocker
        self.db = db
        self.whitelist = whitelist
        self.geoip = geoip
        self.distributed_auth_detector = distributed_auth_detector
        self.corroborator = corroborator
        self.time_window = config.getint('thresholds', 'time_window', fallback=300)

        self.smtp_threshold = config.getint('thresholds', 'smtp_auth_fail_threshold', fallback=10)
        self.imap_threshold = config.getint('thresholds', 'imap_auth_fail_threshold', fallback=10)
        self.trust_duration = config.getint('auth_tracking', 'mail_trust_duration', fallback=24) * 3600

        self.hits_smtp = HitTracker(self.time_window)
        self.hits_imap = HitTracker(self.time_window)

    def _record_failure(self, username):
        """Feed the per-username failure counter used as compromise
        corroboration.

        Called after the whitelist bypass, so whitelisted sources never
        contribute. That is deliberate: this counter can promote enforcement
        up to disabling a mailbox, and an operator's own whitelisted box
        looping on a stale password would otherwise manufacture the evidence
        for someone else's punishment. It still counts across every
        non-whitelisted IP, which is what makes it see a stuffing burst that
        the per-IP tracker cannot.
        """
        if self.corroborator and username:
            self.corroborator.record_auth_failure(username)

    def _geo(self, ip):
        if self.geoip and getattr(self.geoip, 'enabled', False):
            try:
                return self.geoip.lookup(ip)
            except Exception as e:
                logging.getLogger('wp-guardian.mail').debug(
                    "GeoIP lookup error for {ip}: {e}".format(ip=ip, e=e)
                )
        return None

    def _on_auth(self, ip, service, username):
        """Common post-auth hook: geo-enrich, record, notify compromise detector."""
        geo = self._geo(ip)
        self.db.record_auth(ip, service, username, geo=geo)
        if self.distributed_auth_detector:
            try:
                self.distributed_auth_detector.on_successful_auth(
                    username, ip, service, geo or {}
                )
            except Exception as e:
                logging.getLogger('wp-guardian.mail').error(
                    "DistributedAuthDetector error: {e}".format(e=e)
                )

    def process_line(self, line):
        """Process a single maillog line."""

        # SMTP failed auth
        if 'authentication failed' in line.lower():
            ip_match = re.search(r'unknown\[(\d+\.\d+\.\d+\.\d+)\]', line)
            if not ip_match:
                ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', line)
            if ip_match:
                ip = ip_match.group(1)
                if self.whitelist and self.whitelist.is_whitelisted(ip):
                    return
                # Username is best-effort on Postfix fail lines; most configs
                # don't log it on failure. Left blank when unavailable.
                user_match = re.search(r'sasl_username=(\S+)', line)
                username = user_match.group(1) if user_match else ''
                self._record_failure(username)
                count = self.hits_smtp.add(ip)
                if count >= self.smtp_threshold:
                    if self.db.is_ip_authenticated(ip, self.trust_duration):
                        logging.getLogger('wp-guardian.mail').warning(
                            f"Authenticated IP {ip} hit SMTP fail threshold ({count} in {self.time_window}s) — not blocking (likely misconfigured mail client)"
                        )
                        self.blocker.alert_trusted_skip(ip, 'smtp', count, self.time_window, username)
                        return
                    # Postfix rarely logs sasl_username on failure, so this only
                    # catches the cases where it does. Dovecot below is reliable.
                    if is_guardian_disabled_client(self.db, ip, username, 'smtp',
                                                   'wp-guardian.mail'):
                        self.blocker.alert_guardian_disabled_skip(
                            ip, 'smtp', username, count, self.time_window)
                        return
                    self.blocker.block(ip, f"SMTP auth brute force ({count} in {self.time_window}s)",
                                      service='smtp', username=username, rule='smtp_fail')
            return

        # SMTP successful auth — record for geo tracking.
        # Gated on `sasl_method=` which Postfix only logs on real successes
        # (the auth failed case above has already returned, but this is
        # defence-in-depth so the two paths agree with the backfill tool).
        if 'sasl_method=' in line:
            ip_match = re.search(r'client=[^,\s]*\[(\d+\.\d+\.\d+\.\d+)\]', line)
            user_match = re.search(r'sasl_username=(\S+)', line)
            if ip_match and user_match:
                ip = ip_match.group(1)
                username = user_match.group(1)
                self._on_auth(ip, 'smtp', username)
            return

        # Dovecot failed auth (IMAP/POP3)
        if 'auth failed' in line:
            ip_match = re.search(r'rip=(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                if self.whitelist and self.whitelist.is_whitelisted(ip):
                    return
                # Dovecot reliably logs user=<...> on failed auth lines.
                user_match = re.search(r'user=<([^>]+)>', line)
                username = user_match.group(1) if user_match else ''
                self._record_failure(username)
                count = self.hits_imap.add(ip)
                if count >= self.imap_threshold:
                    service = 'imap' if 'imap-login' in line else 'pop3'
                    if self.db.is_ip_authenticated(ip, self.trust_duration):
                        logging.getLogger('wp-guardian.mail').warning(
                            f"Authenticated IP {ip} hit {service.upper()} fail threshold ({count} in {self.time_window}s) — not blocking (likely misconfigured mail client)"
                        )
                        self.blocker.alert_trusted_skip(ip, service, count, self.time_window, username)
                        return
                    if is_guardian_disabled_client(self.db, ip, username, service,
                                                   'wp-guardian.mail'):
                        self.blocker.alert_guardian_disabled_skip(
                            ip, service, username, count, self.time_window)
                        return
                    rule = 'imap_fail' if service == 'imap' else 'pop3_fail'
                    self.blocker.block(ip, f"{service.upper()} auth brute force ({count} in {self.time_window}s)",
                                      service=service, username=username, rule=rule)
            return

        # Dovecot successful auth — record for geo tracking
        if 'Login: user=' in line:
            ip_match = re.search(r'rip=(\d+\.\d+\.\d+\.\d+)', line)
            user_match = re.search(r'user=<([^>]+)>', line)
            if ip_match and user_match:
                ip = ip_match.group(1)
                username = user_match.group(1)
                service = 'imap' if 'imap-login' in line else 'pop3'
                self._on_auth(ip, service, username)
            return
