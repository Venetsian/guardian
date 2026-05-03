"""SSH log detector — /var/log/secure (sshd auth events).

v1.5: extracted from wp-guardian.py with no behavior change.
Port-agnostic: parses log content, doesn't care about the listening port.
A v1.6+ tune-up will add a dedicated rule for root-login attempts.
"""

import re
import logging

from .base import HitTracker


class SSHDetector:
    """Parses /var/log/secure for SSH attacks."""

    def __init__(self, config, blocker, db, whitelist=None,
                 geoip=None, distributed_auth_detector=None):
        self.blocker = blocker
        self.db = db
        self.whitelist = whitelist
        self.geoip = geoip
        self.distributed_auth_detector = distributed_auth_detector
        self.time_window = config.getint('thresholds', 'time_window', fallback=300)

        self.ssh_threshold = config.getint('thresholds', 'ssh_fail_threshold', fallback=3)
        self.instant_block_invalid = config.getboolean(
            'thresholds', 'ssh_invalid_user_instant_block', fallback=True
        )
        # Root login attempts are higher signal than ordinary failed passwords.
        # Default: half the regular threshold, floor at 1 (= instant block).
        default_root = max(1, self.ssh_threshold // 2)
        self.ssh_root_threshold = config.getint(
            'thresholds', 'ssh_root_fail_threshold', fallback=default_root
        )

        self.hits_ssh = HitTracker(self.time_window)
        self.hits_root = HitTracker(self.time_window)

    def _geo(self, ip):
        if self.geoip and getattr(self.geoip, 'enabled', False):
            try:
                return self.geoip.lookup(ip)
            except Exception:
                return None
        return None

    def process_line(self, line):
        """Process a single secure log line."""

        # Invalid user — instant block
        if 'Invalid user' in line or 'invalid user' in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if ip_match and self.instant_block_invalid:
                ip = ip_match.group(1)
                if self.whitelist and self.whitelist.is_whitelisted(ip):
                    return
                user_match = re.search(r'[Ii]nvalid user (\S+)', line)
                username = user_match.group(1) if user_match else 'unknown'
                self.blocker.block(ip, f"SSH invalid user: {username}", service='ssh',
                                   username=username, rule='ssh_invalid')
            return

        # Failed password — root attempts get their own (lower) threshold.
        # The listening sshd port (22, 69, etc.) is not in the log message —
        # only the client's source port — so this is port-agnostic by design.
        if 'Failed password' in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                if self.whitelist and self.whitelist.is_whitelisted(ip):
                    return
                # 'Failed password for root from ...' is the root attempt signal.
                # Match with a real word boundary so 'rootless' wouldn't trip it.
                if re.search(r'Failed password for (?:invalid user )?root from', line):
                    rcount = self.hits_root.add(ip)
                    if rcount >= self.ssh_root_threshold:
                        self.blocker.block(
                            ip,
                            f"SSH root brute force ({rcount} in {self.time_window}s)",
                            service='ssh',
                            username='root',
                            rule='ssh_root',
                        )
                    return
                count = self.hits_ssh.add(ip)
                if count >= self.ssh_threshold:
                    self.blocker.block(ip, f"SSH brute force ({count} in {self.time_window}s)",
                                       service='ssh', rule='ssh_fail')
            return

        # Successful login — record for geo tracking
        if 'Accepted password' in line or 'Accepted publickey' in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            user_match = re.search(r'for (\S+) from', line)
            if ip_match and user_match:
                ip = ip_match.group(1)
                username = user_match.group(1)
                geo = self._geo(ip)
                self.db.record_auth(ip, 'ssh', username, geo=geo)
                if self.distributed_auth_detector:
                    try:
                        self.distributed_auth_detector.on_successful_auth(
                            username, ip, 'ssh', geo or {}
                        )
                    except Exception as e:
                        logging.getLogger('wp-guardian.ssh').error(
                            "DistributedAuthDetector error: {e}".format(e=e)
                        )
            return
