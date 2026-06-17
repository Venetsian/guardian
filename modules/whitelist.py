"""
WP-Guardian Whitelist Module
Combines three whitelist sources:
1. File-based (whitelist.conf)
2. Database (temporary and permanent entries)
3. Firewall backend's friendly list (if supported)
"""

import ipaddress
import logging

logger = logging.getLogger('wp-guardian.whitelist')


class WhitelistManager:
    def __init__(self, db, firewall=None, file_ips=None):
        self.db = db
        self.firewall = firewall
        self.file_ips = file_ips or set()

        # Parse CIDR ranges from file whitelist
        self._file_networks = []
        self._file_exact = set()
        for entry in self.file_ips:
            if '/' in entry:
                try:
                    self._file_networks.append(ipaddress.ip_network(entry, strict=False))
                except ValueError:
                    logger.warning(f"Invalid CIDR in whitelist: {entry}")
            else:
                self._file_exact.add(entry)

        logger.info(f"Whitelist initialized: {len(self._file_exact)} exact IPs, "
                    f"{len(self._file_networks)} CIDR ranges from file")

    def reload_file(self, filepath):
        """Re-read whitelist file and rebuild in-memory sets.
        Uses atomic reference swaps (GIL-safe) so readers never see partial state."""
        from modules.config import load_whitelist_file
        new_ips = load_whitelist_file(filepath)

        new_networks = []
        new_exact = set()
        for entry in new_ips:
            if '/' in entry:
                try:
                    new_networks.append(ipaddress.ip_network(entry, strict=False))
                except ValueError:
                    logger.warning(f"Invalid CIDR in whitelist: {entry}")
            else:
                new_exact.add(entry)

        # Atomic reference swaps
        self._file_networks = new_networks
        self._file_exact = new_exact
        self.file_ips = new_ips

        logger.info(f"Whitelist reloaded: {len(new_exact)} exact IPs, "
                    f"{len(new_networks)} CIDR ranges from file")

    def contains_whitelisted_ip(self, subnet_prefix):
        """Check if any whitelisted IP falls within a /24 subnet prefix.
        subnet_prefix should be like '192.0.2.' (with trailing dot).
        Checks file exact IPs, file CIDRs (overlap), and DB whitelist entries."""
        # Check file exact IPs
        for ip in self._file_exact:
            if ip.startswith(subnet_prefix):
                return True

        # Check file CIDR ranges for overlap with this /24
        subnet_cidr = subnet_prefix + '0/24'
        try:
            subnet_net = ipaddress.ip_network(subnet_cidr, strict=False)
            for network in self._file_networks:
                if network.overlaps(subnet_net):
                    return True
        except ValueError:
            pass

        # Check DB whitelist entries
        try:
            rows = self.db.get_whitelist()
            for row in rows:
                wl_ip = row['ip']
                if '/' in wl_ip:
                    try:
                        if ipaddress.ip_network(wl_ip, strict=False).overlaps(subnet_net):
                            return True
                    except ValueError:
                        pass
                elif wl_ip.startswith(subnet_prefix):
                    return True
        except Exception:
            pass

        return False

    def overlaps_cidr(self, cidr):
        """Check whether any whitelisted IP or range falls within / overlaps an
        arbitrary CIDR (any prefix length). Used before a manual CIDR block so
        we never blackhole a range that contains a whitelisted address.
        Returns True if there is any overlap, False otherwise."""
        try:
            target = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False

        # File exact IPs
        for ip in self._file_exact:
            try:
                if ipaddress.ip_address(ip) in target:
                    return True
            except ValueError:
                pass

        # File CIDR ranges
        for network in self._file_networks:
            if network.overlaps(target):
                return True

        # DB whitelist entries
        try:
            for row in self.db.get_whitelist():
                wl_ip = row['ip']
                if '/' in wl_ip:
                    try:
                        if ipaddress.ip_network(wl_ip, strict=False).overlaps(target):
                            return True
                    except ValueError:
                        pass
                else:
                    try:
                        if ipaddress.ip_address(wl_ip) in target:
                            return True
                    except ValueError:
                        pass
        except Exception:
            pass

        return False

    def is_whitelisted(self, ip):
        """Check if IP is whitelisted from any source."""
        # 1. Check file-based exact match
        if ip in self._file_exact:
            return True

        # 2. Check file-based CIDR ranges
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self._file_networks:
                if ip_obj in network:
                    return True
        except ValueError:
            pass

        # 3. Check database whitelist
        if self.db.is_whitelisted(ip):
            return True

        # 4. Check firewall backend's friendly list (if supported)
        if self.firewall and self.firewall.supports_friendly_list:
            if self.firewall.is_friendly(ip):
                return True

        return False

    def add(self, ip, wl_type='permanent', duration_seconds=None, reason='', added_by='admin'):
        """Add an IP to the database whitelist."""
        self.db.add_whitelist(ip, wl_type, duration_seconds, reason, added_by)

    def remove(self, ip):
        """Remove an IP from the database whitelist."""
        self.db.remove_whitelist(ip)

    def list_all(self):
        """List all whitelist entries from all sources."""
        entries = []

        # File-based
        for ip in self.file_ips:
            entries.append({'ip': ip, 'type': 'file', 'source': 'whitelist.conf'})

        # Database
        for row in self.db.get_whitelist():
            entries.append({
                'ip': row['ip'],
                'type': row['type'],
                'source': 'database',
                'reason': row['reason'],
                'expires_at': row['expires_at']
            })

        return entries
