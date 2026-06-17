"""
WP-Guardian nftables Backend
Direct nftables blocking using the 'nft' command.

nftables is the successor to iptables and the default packet filtering
framework on modern Linux kernels (3.13+). This backend is for servers
that use nftables directly without a frontend like firewalld or CSF.

Strategy:
  - Creates a WP-Guardian table and set on startup
  - Blocks IPs by adding them to an nftables set
  - Uses set element timeouts for tier 1 & 2 auto-expiry
  - Tier 3 entries have no timeout (permanent)
  - Separate set for CIDR blocks
"""

import subprocess
import logging
import time

from backends.base import FirewallBackend
from modules.config import parse_duration
from modules.conntrack import ConntrackFlusher

logger = logging.getLogger('wp-guardian.nftables')

# nftables table/chain/set names
NFT_TABLE = 'wp_guardian'
NFT_CHAIN = 'wp_block'
NFT_SET_IPS = 'blocked_ips'
NFT_SET_CIDR = 'blocked_nets'


class NftablesBackend(FirewallBackend):
    """Firewall backend using nftables directly (nft command)."""

    supports_cidr = True
    supports_friendly_list = False  # Use whitelist.conf

    def __init__(self, config):
        # Parse tier durations
        self.tier1_duration_str = config.get('escalation', 'tier1_duration', fallback='24h')
        self.tier2_duration_str = config.get('escalation', 'tier2_duration', fallback='30d')
        self.tier1_seconds = parse_duration(self.tier1_duration_str)
        self.tier2_seconds = parse_duration(self.tier2_duration_str)

        # CIDR duration
        self.cidr_duration_str = config.get('cidr', 'duration', fallback='30d')
        self.cidr_seconds = parse_duration(self.cidr_duration_str)

        # Priority (lower = earlier in chain)
        self.priority = config.getint('nftables', 'priority', fallback=-10)

        # Our drop lives in our own base chain, so a `drop` verdict already
        # beats any other chain's established-accept (drop is terminal across
        # base chains on a hook). Flushing conntrack on block is therefore
        # belt-and-suspenders here — it just tears the live connection down
        # immediately instead of waiting for the next dropped packet. Kept for
        # parity with the firewalld backend and honoring the same config knob.
        self.conntrack = ConntrackFlusher(
            enabled=config.getboolean('firewall', 'flush_conntrack', fallback=True)
        )

        if not self.test_connection():
            raise RuntimeError(
                "nft command not found or not working. "
                "Install nftables: yum install nftables or apt install nftables"
            )

    def _run_nft(self, args, timeout=10):
        """Run an nft command. Returns (success, stdout, stderr)."""
        if isinstance(args, str):
            cmd = ['nft'] + args.split()
        else:
            cmd = ['nft'] + list(args)

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
            logger.error(f"nft timeout ({timeout}s): {' '.join(cmd)}")
            return (False, '', 'timeout')
        except FileNotFoundError:
            logger.error("nft command not found — is nftables installed?")
            return (False, '', 'not found')
        except Exception as e:
            logger.error(f"nft exception: {e}")
            return (False, '', str(e))

    def _run_nft_script(self, script, timeout=10):
        """Run a multi-line nft script via stdin."""
        try:
            result = subprocess.run(
                ['nft', '-f', '-'],
                input=script,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=timeout
            )
            return (result.returncode == 0, result.stdout.strip(), result.stderr.strip())
        except subprocess.TimeoutExpired:
            logger.error(f"nft script timeout ({timeout}s)")
            return (False, '', 'timeout')
        except FileNotFoundError:
            logger.error("nft command not found")
            return (False, '', 'not found')
        except Exception as e:
            logger.error(f"nft script exception: {e}")
            return (False, '', str(e))

    def test_connection(self):
        """Verify nft is installed and accessible."""
        success, stdout, stderr = self._run_nft(['list', 'ruleset'], timeout=5)
        if success:
            logger.info("nftables accessible")
            return True
        # nft list ruleset might fail on empty ruleset with return 0,
        # or might need root. Check if command exists at least.
        success2, stdout2, stderr2 = self._run_nft(['-v'], timeout=5)
        if success2:
            logger.info(f"nftables available: {stdout2}")
            return True
        logger.error(f"nftables check failed: {stderr}")
        return False

    def _nft_timeout(self, seconds):
        """Convert seconds to nftables timeout format (e.g., '24h', '30d')."""
        if seconds >= 86400:
            days = seconds // 86400
            return f"{days}d"
        elif seconds >= 3600:
            hours = seconds // 3600
            return f"{hours}h"
        elif seconds >= 60:
            minutes = seconds // 60
            return f"{minutes}m"
        else:
            return f"{seconds}s"

    def block(self, ip, tier, reason, service='web'):
        """Block an IP by adding to nftables set."""
        if tier == 1:
            timeout = f" timeout {self._nft_timeout(self.tier1_seconds)}"
        elif tier == 2:
            timeout = f" timeout {self._nft_timeout(self.tier2_seconds)}"
        else:
            timeout = ""  # Permanent

        # Add element to the set
        success, stdout, stderr = self._run_nft([
            'add', 'element', 'inet', NFT_TABLE, NFT_SET_IPS,
            '{{ {}{} }}'.format(ip, timeout)
        ])

        if not success:
            combined = (stdout + stderr).lower()
            if 'exists' in combined:
                logger.debug(f"nftables: {ip} already in set")
                return True
            logger.error(f"nftables block failed for {ip}: {stderr}")
            return False

        torn = self.conntrack.flush_source(ip)
        torn_note = f" (tore down {torn} live conns)" if torn else ""
        logger.info(f"nftables BLOCKED {ip} tier={tier} reason={reason}{torn_note}")
        return True

    def unblock(self, ip):
        """Remove IP from the nftables blocked set."""
        success, stdout, stderr = self._run_nft([
            'delete', 'element', 'inet', NFT_TABLE, NFT_SET_IPS,
            '{{ {} }}'.format(ip)
        ])

        if success:
            logger.info(f"nftables UNBLOCKED {ip}")
            return True

        combined = (stdout + stderr).lower()
        if 'no such' in combined or 'not found' in combined:
            logger.debug(f"nftables: {ip} was not in set")
            return True

        logger.error(f"nftables unblock failed for {ip}: {stderr}")
        return False

    def is_blocked(self, ip):
        """Check if IP is in the blocked set."""
        success, stdout, stderr = self._run_nft([
            'get', 'element', 'inet', NFT_TABLE, NFT_SET_IPS,
            '{{ {} }}'.format(ip)
        ])
        return success

    def block_cidr(self, subnet, reason, service='web', duration='30d'):
        """Block a CIDR subnet."""
        if duration == 'permanent':
            timeout = ""
        else:
            dur_seconds = parse_duration(duration)
            timeout = f" timeout {self._nft_timeout(dur_seconds)}"

        success, stdout, stderr = self._run_nft([
            'add', 'element', 'inet', NFT_TABLE, NFT_SET_CIDR,
            '{{ {}{} }}'.format(subnet, timeout)
        ])

        if not success:
            combined = (stdout + stderr).lower()
            if 'exists' in combined:
                logger.debug(f"nftables: {subnet} already in CIDR set")
                return True
            logger.error(f"nftables CIDR block failed for {subnet}: {stderr}")
            return False

        torn = self.conntrack.flush_source(subnet)
        torn_note = f" (tore down {torn} live conns)" if torn else ""
        logger.info(f"nftables CIDR BLOCKED {subnet} reason={reason}{torn_note}")
        return True

    def is_cidr_blocked(self, subnet):
        """Check if CIDR is in the blocked nets set."""
        success, stdout, stderr = self._run_nft([
            'get', 'element', 'inet', NFT_TABLE, NFT_SET_CIDR,
            '{{ {} }}'.format(subnet)
        ])
        return success

    def get_block_counts(self):
        """Count elements in the blocked sets."""
        counts = {'ips': 0, 'cidr': 0}

        # Count IPs
        success, stdout, stderr = self._run_nft([
            'list', 'set', 'inet', NFT_TABLE, NFT_SET_IPS
        ])
        if success and stdout:
            # Count lines that look like IP entries (have dots)
            for line in stdout.split('\n'):
                line = line.strip().rstrip(',')
                if line and '.' in line and not line.startswith(('type', 'flags', 'timeout', 'set', '}')):
                    counts['ips'] += 1

        # Count CIDRs
        success, stdout, stderr = self._run_nft([
            'list', 'set', 'inet', NFT_TABLE, NFT_SET_CIDR
        ])
        if success and stdout:
            for line in stdout.split('\n'):
                line = line.strip().rstrip(',')
                if line and '/' in line and not line.startswith(('type', 'flags', 'timeout', 'set', '}')):
                    counts['cidr'] += 1

        return counts

    def ensure_firewall_rules(self):
        """Create the WP-Guardian nftables table, sets, and chain if they don't exist."""
        # Use a single atomic script to set up everything
        script = """
table inet {table} {{
    set {set_ips} {{
        type ipv4_addr
        flags timeout
    }}

    set {set_cidr} {{
        type ipv4_addr
        flags interval, timeout
    }}

    chain {chain} {{
        type filter hook input priority {priority}; policy accept;
        ip saddr @{set_ips} counter drop comment "WP-Guardian blocked IPs"
        ip saddr @{set_cidr} counter drop comment "WP-Guardian blocked subnets"
    }}
}}
""".format(
            table=NFT_TABLE,
            set_ips=NFT_SET_IPS,
            set_cidr=NFT_SET_CIDR,
            chain=NFT_CHAIN,
            priority=self.priority
        )

        # Check if table already exists
        success, stdout, stderr = self._run_nft([
            'list', 'table', 'inet', NFT_TABLE
        ])

        if success:
            logger.info(f"nftables table '{NFT_TABLE}' already exists")
            return

        # Create the table/sets/chain
        success, stdout, stderr = self._run_nft_script(script)

        if success:
            logger.info(f"Created nftables table '{NFT_TABLE}' with sets and drop chain")
        else:
            logger.error(f"Failed to create nftables table: {stderr}")
            logger.error("You may need to create it manually. See backends/README.md")
