"""
WP-Guardian Firewall Backend — Abstract Base Class
All firewall backends must implement this interface.
"""

from abc import ABC, abstractmethod


class FirewallBackend(ABC):
    """
    Abstract base class for firewall backends.

    Every backend (CSF, MikroTik, nftables, etc.) must implement these methods.
    The Blocker module calls these methods without knowing which backend is active.
    """

    # Override in subclass if the backend supports CIDR /24 aggregation
    supports_cidr = False

    # Override in subclass if the backend maintains a "friendly" / never-block list
    supports_friendly_list = False

    @abstractmethod
    def block(self, ip, tier, reason, service='web'):
        """
        Block an IP address.

        Args:
            ip:      The IP to block (e.g. '192.0.2.123')
            tier:    Escalation tier (1=24h, 2=30d, 3=permanent)
            reason:  Human-readable reason string
            service: Which service detected the threat ('web', 'ssh', 'smtp', etc.)

        Returns:
            True if blocked successfully, False on failure.
            Should return True if the IP is already blocked (idempotent).
        """
        pass

    @abstractmethod
    def unblock(self, ip):
        """
        Remove an IP from all block lists.

        Args:
            ip: The IP to unblock

        Returns:
            True if removed (or was not blocked), False on failure.
        """
        pass

    @abstractmethod
    def test_connection(self):
        """
        Verify the backend is reachable and working.

        Returns:
            True if ready, False if not.
        """
        pass

    def is_blocked(self, ip):
        """
        Check if an IP is currently blocked.

        Optional — backends that cannot check this should return False.
        The Blocker module uses the database as the primary "already blocked" check,
        so this is a secondary optimization to avoid redundant calls.

        Returns:
            True if blocked, False otherwise.
        """
        return False

    def block_cidr(self, subnet, reason, service='web', duration='30d'):
        """
        Block an entire CIDR subnet (e.g. '192.0.2.0/24').

        Only called if supports_cidr = True.

        Args:
            subnet:   CIDR notation (e.g. '192.0.2.0/24')
            reason:   Human-readable reason
            service:  Service that triggered the block
            duration: How long to block ('24h', '30d', 'permanent')

        Returns:
            True if blocked, False on failure.
        """
        return False

    def is_cidr_blocked(self, subnet):
        """
        Check if a CIDR subnet is already blocked.
        Only relevant if supports_cidr = True.

        Returns:
            True if blocked, False otherwise.
        """
        return False

    def is_friendly(self, ip):
        """
        Check if an IP is in the backend's "never block" list.
        Only relevant if supports_friendly_list = True.

        Returns:
            True if friendly, False otherwise.
        """
        return False

    def is_friendly_subnet(self, subnet):
        """
        Check if any friendly IP falls within the given subnet.
        Only relevant if supports_friendly_list = True.

        Returns:
            True if the subnet contains a friendly IP, False otherwise.
        """
        return False

    # ------------------------------------------------------------------
    # Shared CIDR helpers — available to all backends
    # ------------------------------------------------------------------
    @staticmethod
    def _ip_in_cidr(ip, cidr):
        """Check if an IP address falls within a CIDR range."""
        try:
            network, prefix_len = cidr.split('/')
            prefix_len = int(prefix_len)

            ip_parts = [int(p) for p in ip.split('.')]
            net_parts = [int(p) for p in network.split('.')]

            ip_int = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
            net_int = (net_parts[0] << 24) + (net_parts[1] << 16) + (net_parts[2] << 8) + net_parts[3]

            mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF

            return (ip_int & mask) == (net_int & mask)
        except (ValueError, IndexError):
            return False

    def _check_friendly(self, ip, friendly_set):
        """Check if IP matches any entry in a set of IPs/CIDRs."""
        if ip in friendly_set:
            return True
        for entry in friendly_set:
            if '/' in entry:
                if self._ip_in_cidr(ip, entry):
                    return True
        return False

    def _check_friendly_subnet(self, subnet, friendly_set):
        """Check if any entry in friendly_set overlaps with the given subnet."""
        for entry in friendly_set:
            check_ip = entry.split('/')[0] if '/' in entry else entry
            if self._ip_in_cidr(check_ip, subnet):
                return True
            if '/' in entry:
                subnet_base = subnet.split('/')[0]
                if self._ip_in_cidr(subnet_base, entry):
                    return True
        return False

    def refresh_friendly_list(self):
        """
        Reload the backend's friendly/never-block list.
        Called periodically by the main loop to pick up changes.
        No-op by default — override if the backend maintains a friendly list.
        """
        pass

    def ensure_firewall_rules(self):
        """
        Called once on daemon startup.
        Create any necessary firewall rules, chains, or structures.
        No-op by default — override if the backend needs setup.
        """
        pass

    def get_block_counts(self):
        """
        Get current block statistics.

        Returns:
            dict with at least: {'tier1': N, 'tier2': N, 'tier3': N}
            Add 'cidr': N if supports_cidr is True.
            Return empty dict if not supported.
        """
        return {}
