"""
WP-Guardian firewalld Backend
Blocking via firewalld (firewall-cmd) — the default firewall on modern
RHEL/AlmaLinux/CentOS/Fedora systems and CyberPanel 2.4+.

Uses rich rules for IP-level blocking with per-tier timeouts via
runtime rules (permanent rules would survive reboots but can't have
timeouts). Instead, we use --permanent rich rules and reload, relying on
the database for TTL tracking and periodic cleanup.

Strategy:
  - Tier 1 & 2: Added to an ipset for fast matching + a rich rule to drop
  - Tier 3:     Same ipset approach, permanent entries
  - Cleanup:    Daemon periodically removes expired blocks (based on DB tier expiry)

Alternatively (and simpler): use rich rules directly. firewalld handles
thousands of rules efficiently via nftables backend.
"""

import subprocess
import logging
import time
import os

from backends.base import FirewallBackend
from modules.config import parse_duration

logger = logging.getLogger('wp-guardian.firewalld')


class FirewalldBackend(FirewallBackend):
    """Firewall backend using firewalld (firewall-cmd)."""

    supports_cidr = True
    supports_friendly_list = False  # No built-in friendly list; use whitelist.conf

    def __init__(self, config):
        # Parse tier durations
        self.tier1_duration_str = config.get('escalation', 'tier1_duration', fallback='24h')
        self.tier2_duration_str = config.get('escalation', 'tier2_duration', fallback='30d')
        self.tier1_seconds = parse_duration(self.tier1_duration_str)
        self.tier2_seconds = parse_duration(self.tier2_duration_str)

        # CIDR duration
        self.cidr_duration_str = config.get('cidr', 'duration', fallback='30d')
        self.cidr_seconds = parse_duration(self.cidr_duration_str)

        # Zone to add rules to (default: public)
        self.zone = config.get('firewalld', 'zone', fallback='public')

        if not self.test_connection():
            raise RuntimeError(
                "firewalld is not installed or not running. "
                "Install/start firewalld or choose a different firewall backend.\n"
                "  Install: yum install firewalld && systemctl enable --now firewalld\n"
                "  Or:      apt install firewalld && systemctl enable --now firewalld"
            )

    def _run_cmd(self, args, timeout=15):
        """Run a firewall-cmd command. Returns (success, stdout, stderr)."""
        cmd = ['firewall-cmd'] + args

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=timeout
            )
            return (result.returncode == 0, result.stdout.strip(), result.stderr.strip())
        except subprocess.TimeoutExpired:
            logger.error(f"firewall-cmd timeout ({timeout}s): {' '.join(args)}")
            return (False, '', 'timeout')
        except FileNotFoundError:
            logger.error("firewall-cmd not found — is firewalld installed?")
            return (False, '', 'not found')
        except Exception as e:
            logger.error(f"firewall-cmd exception: {e}")
            return (False, '', str(e))

    def test_connection(self):
        """Verify firewalld is running."""
        success, stdout, stderr = self._run_cmd(['--state'], timeout=5)
        if success and 'running' in stdout:
            logger.info("firewalld is running")
            return True
        # Also check via systemctl
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', 'firewalld'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=5
            )
            if result.stdout.strip() == 'active':
                logger.info("firewalld is active (via systemctl)")
                return True
        except Exception:
            pass
        logger.error(f"firewalld check failed: {stderr}")
        return False

    def _rich_rule(self, ip, action='drop'):
        """Build a rich rule string for an IP or CIDR."""
        family = 'ipv4'
        return (f'rule family="{family}" source address="{ip}" {action}')

    def block(self, ip, tier, reason, service='web'):
        """Block an IP via firewalld rich rule."""
        rule = self._rich_rule(ip)

        # Add as permanent rule (survives firewall-cmd --reload)
        success, stdout, stderr = self._run_cmd([
            '--permanent', '--zone={}'.format(self.zone),
            '--add-rich-rule={}'.format(rule)
        ])

        if not success:
            combined = (stdout + stderr).lower()
            if 'already' in combined:
                logger.debug(f"firewalld: {ip} already blocked")
                return True
            logger.error(f"firewalld block failed for {ip}: {stderr}")
            return False

        # Apply immediately (reload)
        self._run_cmd(['--reload'])

        logger.info(f"firewalld BLOCKED {ip} tier={tier} reason={reason}")
        return True

    def unblock(self, ip):
        """Remove an IP from firewalld rich rules."""
        rule = self._rich_rule(ip)

        success, stdout, stderr = self._run_cmd([
            '--permanent', '--zone={}'.format(self.zone),
            '--remove-rich-rule={}'.format(rule)
        ])

        if success:
            self._run_cmd(['--reload'])
            logger.info(f"firewalld UNBLOCKED {ip}")
            return True

        combined = (stdout + stderr).lower()
        if 'not enabled' in combined or 'not found' in combined:
            logger.debug(f"firewalld: {ip} was not blocked")
            return True

        logger.error(f"firewalld unblock failed for {ip}: {stderr}")
        return False

    def is_blocked(self, ip):
        """Check if IP has a drop rich rule."""
        rule = self._rich_rule(ip)
        success, stdout, stderr = self._run_cmd([
            '--permanent', '--zone={}'.format(self.zone),
            '--query-rich-rule={}'.format(rule)
        ])
        return success

    def block_cidr(self, subnet, reason, service='web', duration='30d'):
        """Block a CIDR subnet via firewalld rich rule."""
        rule = self._rich_rule(subnet)

        success, stdout, stderr = self._run_cmd([
            '--permanent', '--zone={}'.format(self.zone),
            '--add-rich-rule={}'.format(rule)
        ])

        if not success:
            combined = (stdout + stderr).lower()
            if 'already' in combined:
                logger.debug(f"firewalld: {subnet} already blocked")
                return True
            logger.error(f"firewalld CIDR block failed for {subnet}: {stderr}")
            return False

        self._run_cmd(['--reload'])
        logger.info(f"firewalld CIDR BLOCKED {subnet} reason={reason}")
        return True

    def is_cidr_blocked(self, subnet):
        """Check if a CIDR subnet has a drop rich rule."""
        rule = self._rich_rule(subnet)
        success, stdout, stderr = self._run_cmd([
            '--permanent', '--zone={}'.format(self.zone),
            '--query-rich-rule={}'.format(rule)
        ])
        return success

    def get_block_counts(self):
        """Count current rich rules (all counted together since firewalld has no tiers)."""
        counts = {'total': 0}

        success, stdout, stderr = self._run_cmd([
            '--permanent', '--zone={}'.format(self.zone),
            '--list-rich-rules'
        ])

        if success and stdout:
            for line in stdout.split('\n'):
                line = line.strip()
                if line and 'drop' in line:
                    counts['total'] += 1

        return counts

    def ensure_firewall_rules(self):
        """firewalld manages rules via zones — nothing extra to set up."""
        logger.info(f"firewalld backend using zone: {self.zone}")
