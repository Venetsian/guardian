"""
WP-Guardian CSF Backend
Blocking via ConfigServer Firewall (csf).
Supports tier-based temporary and permanent blocks.
"""

import subprocess
import logging
import time
import os
import re

from backends.base import FirewallBackend
from modules.config import parse_duration

logger = logging.getLogger('wp-guardian.csf')


class CSFBackend(FirewallBackend):
    """Firewall backend using ConfigServer Firewall (csf)."""

    supports_cidr = True
    supports_friendly_list = True

    def __init__(self, config):
        # Parse tier durations for temp blocks
        self.tier1_duration_str = config.get('escalation', 'tier1_duration', fallback='24h')
        self.tier2_duration_str = config.get('escalation', 'tier2_duration', fallback='30d')
        self.tier1_seconds = parse_duration(self.tier1_duration_str)
        self.tier2_seconds = parse_duration(self.tier2_duration_str)

        # CIDR duration
        self.cidr_duration_str = config.get('cidr', 'duration', fallback='30d')
        self.cidr_seconds = parse_duration(self.cidr_duration_str)

        # CSF config paths
        self._csf_deny = '/etc/csf/csf.deny'
        self._csf_allow = '/etc/csf/csf.allow'
        self._csf_ignore = '/etc/csf/csf.ignore'

        # Load friendly (allowed) IPs from csf.allow
        self._friendly_ips = set()

        if not self.test_connection():
            raise RuntimeError(
                "CSF (ConfigServer Firewall) is not installed or not working. "
                "Install CSF or choose a different firewall backend."
            )

        self._load_friendly_list()

    def _run_csf(self, args, timeout=15):
        """Run a csf command and return (success, stdout, stderr)."""
        cmd = ['csf'] + args

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
            logger.error(f"CSF command timeout ({timeout}s): csf {' '.join(args)}")
            return (False, '', 'timeout')
        except FileNotFoundError:
            logger.error("CSF command not found — is csf installed?")
            return (False, '', 'not found')
        except Exception as e:
            logger.error(f"CSF command exception: {e}")
            return (False, '', str(e))

    def test_connection(self):
        """Verify CSF is installed and accessible."""
        success, stdout, stderr = self._run_csf(['-v'], timeout=5)
        if success:
            logger.info(f"CSF available: {stdout}")
            return True
        else:
            logger.error(f"CSF check failed: {stderr}")
            return False

    def _load_friendly_list(self):
        """Load allowed IPs from csf.allow and csf.ignore."""
        self._friendly_ips = set()

        for filepath in [self._csf_allow, self._csf_ignore]:
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                # CSF allows comments after the IP with #
                                ip_part = line.split('#')[0].strip()
                                if ip_part:
                                    self._friendly_ips.add(ip_part)
                except Exception as e:
                    logger.warning(f"Could not read {filepath}: {e}")

        logger.info(f"Loaded CSF friendly list: {len(self._friendly_ips)} entries "
                    f"from csf.allow and csf.ignore")

    def is_friendly(self, ip):
        """Check if IP is in CSF's allow/ignore lists."""
        return self._check_friendly(ip, self._friendly_ips)

    def is_friendly_subnet(self, subnet):
        """Check if any friendly IP falls within the given subnet."""
        return self._check_friendly_subnet(subnet, self._friendly_ips)

    def block(self, ip, tier, reason, service='web'):
        """Block an IP via CSF with tier-based durations."""
        # Safety check
        if self.is_friendly(ip):
            logger.warning(f"Refusing to block friendly IP: {ip}")
            return False

        timestamp = time.strftime('%Y-%m-%d %H:%M')
        comment = f"WPG-{service}: {reason} [{timestamp}]"

        if tier == 1:
            # Temporary block — use csf -td (temp deny)
            success, stdout, stderr = self._run_csf(
                ['-td', ip, str(self.tier1_seconds), comment]
            )
        elif tier == 2:
            # Longer temp block
            success, stdout, stderr = self._run_csf(
                ['-td', ip, str(self.tier2_seconds), comment]
            )
        else:
            # Permanent block — use csf -d
            success, stdout, stderr = self._run_csf(
                ['-d', ip, comment]
            )

        if success:
            logger.info(f"CSF BLOCKED {ip} tier={tier} reason={reason}")
            return True

        # CSF returns non-zero if IP is already blocked — that's fine
        combined = (stdout + stderr).lower()
        if 'already exists' in combined or 'already blocked' in combined:
            logger.debug(f"CSF: {ip} already blocked")
            return True

        logger.error(f"CSF block failed for {ip}: {stderr}")
        return False

    def unblock(self, ip):
        """Remove an IP from CSF deny lists."""
        unblocked = False

        # Remove permanent deny
        success, stdout, stderr = self._run_csf(['-dr', ip])
        if success:
            unblocked = True

        # Remove temp deny
        success, stdout, stderr = self._run_csf(['-tr', ip])
        if success:
            unblocked = True

        if unblocked:
            logger.info(f"CSF UNBLOCKED {ip}")
        return unblocked

    def is_blocked(self, ip):
        """Check if IP is in CSF deny list."""
        success, stdout, stderr = self._run_csf(['-g', ip])
        if success and stdout:
            # csf -g outputs matching lines; check for deny entries
            for line in stdout.split('\n'):
                if 'deny' in line.lower() or 'Block' in line:
                    return True
        return False

    def block_cidr(self, subnet, reason, service='web', duration='30d'):
        """Block a CIDR subnet via CSF."""
        if self.is_friendly_subnet(subnet):
            logger.warning(f"Refusing to CIDR block {subnet} — contains friendly IPs")
            return False

        timestamp = time.strftime('%Y-%m-%d %H:%M')
        comment = f"WPG-CIDR-{service}: {reason} [{timestamp}]"

        if duration == 'permanent':
            success, stdout, stderr = self._run_csf(['-d', subnet, comment])
        else:
            duration_seconds = parse_duration(duration)
            success, stdout, stderr = self._run_csf(
                ['-td', subnet, str(duration_seconds), comment]
            )

        if success:
            logger.info(f"CSF CIDR BLOCKED {subnet} reason={reason}")
            return True

        combined = (stdout + stderr).lower()
        if 'already exists' in combined:
            logger.debug(f"CSF: {subnet} already blocked")
            return True

        logger.error(f"CSF CIDR block failed for {subnet}: {stderr}")
        return False

    def is_cidr_blocked(self, subnet):
        """Check if a CIDR subnet is in CSF deny list."""
        success, stdout, stderr = self._run_csf(['-g', subnet])
        if success and stdout:
            for line in stdout.split('\n'):
                if 'deny' in line.lower() or 'Block' in line:
                    return True
        return False

    def get_block_counts(self):
        """Get block counts from CSF deny files."""
        counts = {'tier1': 0, 'tier2': 0, 'tier3': 0, 'cidr': 0}

        # Count permanent denies
        if os.path.exists(self._csf_deny):
            try:
                with open(self._csf_deny, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            ip_part = line.split('#')[0].strip()
                            if '/' in ip_part:
                                counts['cidr'] += 1
                            else:
                                counts['tier3'] += 1
            except Exception as e:
                logger.warning(f"Could not read csf.deny: {e}")

        # Count temp denies from csf -t output
        success, stdout, stderr = self._run_csf(['-t'])
        if success and stdout:
            for line in stdout.split('\n'):
                if 'DENY' in line or 'deny' in line:
                    # Try to categorize by WPG comment
                    if '/' in line.split('#')[0].split()[0] if line.split() else '':
                        counts['cidr'] += 1
                    else:
                        counts['tier1'] += 1  # Count all temps as tier1 for simplicity

        return counts

    def ensure_firewall_rules(self):
        """CSF manages its own iptables rules — nothing to set up."""
        logger.info("CSF manages firewall rules automatically")
