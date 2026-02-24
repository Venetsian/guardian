"""
WP-Guardian MikroTik Backend
Manages IP blocking via SSH to MikroTik RouterOS.
"""

import subprocess
import logging
import time
import re

from backends.base import FirewallBackend

logger = logging.getLogger('wp-guardian.mikrotik')


class MikroTikBackend(FirewallBackend):
    """Firewall backend for MikroTik routers via SSH."""

    supports_cidr = True
    supports_friendly_list = True

    def __init__(self, config):
        self.host = config.get('mikrotik', 'host', fallback='192.168.2.1')
        self.port = config.getint('mikrotik', 'port', fallback=22)
        self.user = config.get('mikrotik', 'user', fallback='guardian')
        self.key_file = config.get('mikrotik', 'key_file', fallback='/root/.ssh/mikrotik_guardian')

        self.list_tier1 = config.get('mikrotik', 'list_tier1', fallback='wp-block-24h')
        self.list_tier2 = config.get('mikrotik', 'list_tier2', fallback='wp-block-30d')
        self.list_tier3 = config.get('mikrotik', 'list_tier3', fallback='wp-block-permanent')
        self.list_cidr = config.get('mikrotik', 'list_cidr', fallback='wp-block-cidr')
        self.friendly_list = config.get('mikrotik', 'friendly_list', fallback='friendly')

        # Friendly IPs loaded once at startup
        self._friendly_ips = set()

        # Parse tier durations for MikroTik timeout values
        self.tier1_timeout = config.get('escalation', 'tier1_duration', fallback='24h')
        self.tier2_timeout = config.get('escalation', 'tier2_duration', fallback='30d')

        # Test connection and load friendly list
        if not self.test_connection():
            raise RuntimeError(
                f"Cannot connect to MikroTik at {self.user}@{self.host}:{self.port}. "
                f"Check SSH key ({self.key_file}) and network connectivity."
            )

    def _ssh_command(self, command, timeout=10):
        """Execute a command on MikroTik via SSH."""
        cmd = [
            'ssh',
            '-i', self.key_file,
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'ConnectTimeout=5',
            '-o', f'Port={self.port}',
            '-o', 'BatchMode=yes',
            f'{self.user}@{self.host}',
            command
        ]

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=timeout
            )

            if result.returncode != 0:
                stderr = result.stderr.strip()
                if stderr:
                    logger.error(f"MikroTik SSH error: {stderr}")
                return None

            return result.stdout.strip()

        except subprocess.TimeoutExpired:
            logger.error(f"MikroTik SSH timeout ({timeout}s) for command: {command}")
            return None
        except FileNotFoundError:
            logger.error("SSH client not found")
            return None
        except Exception as e:
            logger.error(f"MikroTik SSH exception: {e}")
            return None

    def test_connection(self):
        """Test SSH connectivity to MikroTik."""
        result = self._ssh_command("/system identity print")
        if result:
            logger.info(f"MikroTik connected: {result}")
            self._load_friendly_list()
            return True
        else:
            logger.error("MikroTik connection test FAILED")
            return False

    def _load_friendly_list(self):
        """Load the friendly address list from MikroTik. Called once at startup."""
        result = self._ssh_command(
            f'/ip firewall address-list print where list="{self.friendly_list}" terse'
        )

        if result is None:
            logger.warning("Could not load friendly list from MikroTik")
            return

        self._friendly_ips = set()
        for line in result.split('\n'):
            match = re.search(r'address=([\d./]+)', line)
            if match:
                self._friendly_ips.add(match.group(1))

        logger.info(f"Loaded friendly list: {len(self._friendly_ips)} entries")

    def is_friendly(self, ip):
        """Check if IP is in MikroTik's friendly list."""
        return self._check_friendly(ip, self._friendly_ips)

    def is_friendly_subnet(self, subnet):
        """Check if any friendly IP falls within the given subnet."""
        return self._check_friendly_subnet(subnet, self._friendly_ips)

    def block(self, ip, tier, reason, service='web'):
        """Block an IP on MikroTik."""
        # Safety checks
        if self.is_friendly(ip):
            logger.warning(f"Refusing to block friendly IP: {ip}")
            return False

        if self.is_blocked(ip):
            logger.debug(f"IP already blocked on MikroTik: {ip}")
            return True

        # Determine list and timeout based on tier
        if tier == 1:
            list_name = self.list_tier1
            timeout = f"timeout={self.tier1_timeout}"
        elif tier == 2:
            list_name = self.list_tier2
            timeout = f"timeout={self.tier2_timeout}"
        else:
            list_name = self.list_tier3
            timeout = ""  # No timeout = permanent

        # Build comment
        timestamp = time.strftime('%Y-%m-%d %H:%M')
        comment = f"WPG-{service}: {reason} [{timestamp}]"
        if len(comment) > 256:
            comment = comment[:253] + "..."

        # Execute block
        cmd = (f'/ip firewall address-list add list="{list_name}" '
               f'address="{ip}" {timeout} comment="{comment}"')
        result = self._ssh_command(cmd)

        if result is not None:
            logger.info(f"MikroTik BLOCKED {ip} tier={tier} list={list_name} reason={reason}")
            return True
        else:
            logger.error(f"MikroTik BLOCK FAILED for {ip}")
            return False

    def unblock(self, ip):
        """Remove an IP from all block lists."""
        removed = False
        for list_name in [self.list_tier1, self.list_tier2, self.list_tier3]:
            result = self._ssh_command(
                f'/ip firewall address-list remove [find where list="{list_name}" address="{ip}"]'
            )
            if result is not None:
                removed = True

        if removed:
            logger.info(f"MikroTik UNBLOCKED {ip}")
        return removed

    def is_blocked(self, ip):
        """Check if IP is already in any block list."""
        for list_name in [self.list_tier1, self.list_tier2, self.list_tier3]:
            result = self._ssh_command(
                f'/ip firewall address-list print count-only where list="{list_name}" address="{ip}"'
            )
            if result and result.strip() != '0':
                return True
        return False

    def block_cidr(self, subnet, reason, service='web', duration='30d'):
        """Block a CIDR subnet on MikroTik."""
        if self.is_friendly_subnet(subnet):
            logger.warning(f"Refusing to CIDR block {subnet} — contains friendly IPs")
            return False

        timestamp = time.strftime('%Y-%m-%d %H:%M')
        comment = f"WPG-CIDR-{service}: {reason} [{timestamp}]"
        if len(comment) > 256:
            comment = comment[:253] + "..."

        timeout = f"timeout={duration}" if duration != 'permanent' else ""

        cmd = (f'/ip firewall address-list add list="{self.list_cidr}" '
               f'address="{subnet}" {timeout} comment="{comment}"')
        result = self._ssh_command(cmd)

        if result is not None:
            logger.info(f"MikroTik CIDR BLOCKED {subnet} list={self.list_cidr} reason={reason}")
            return True
        else:
            logger.error(f"MikroTik CIDR BLOCK FAILED for {subnet}")
            return False

    def is_cidr_blocked(self, subnet):
        """Check if a CIDR subnet is already in the CIDR block list."""
        result = self._ssh_command(
            f'/ip firewall address-list print count-only where list="{self.list_cidr}" address="{subnet}"'
        )
        return result is not None and result.strip() != '0'

    def get_block_counts(self):
        """Get number of entries in each block list."""
        counts = {}
        for name, list_name in [('tier1', self.list_tier1),
                                 ('tier2', self.list_tier2),
                                 ('tier3', self.list_tier3),
                                 ('cidr', self.list_cidr)]:
            result = self._ssh_command(
                f'/ip firewall address-list print count-only where list="{list_name}"'
            )
            counts[name] = int(result) if result and result.isdigit() else 0

        return counts

    def ensure_firewall_rules(self):
        """Ensure the drop rules exist for our address lists. Run once on startup."""
        for list_name in [self.list_tier1, self.list_tier2, self.list_tier3, self.list_cidr]:
            # Check if forward rule already exists
            result = self._ssh_command(
                f'/ip firewall filter print count-only where src-address-list="{list_name}" action=drop'
            )

            if result and result.strip() == '0':
                self._ssh_command(
                    f'/ip firewall filter add chain=forward src-address-list="{list_name}" '
                    f'action=drop comment="WP-Guardian auto-block ({list_name})"'
                )
                logger.info(f"Created firewall drop rule for list: {list_name}")

            # Also add input chain rule
            result = self._ssh_command(
                f'/ip firewall filter print count-only where chain=input src-address-list="{list_name}" action=drop'
            )

            if result and result.strip() == '0':
                self._ssh_command(
                    f'/ip firewall filter add chain=input src-address-list="{list_name}" '
                    f'action=drop comment="WP-Guardian auto-block input ({list_name})"'
                )
                logger.info(f"Created firewall input drop rule for list: {list_name}")
