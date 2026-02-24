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
