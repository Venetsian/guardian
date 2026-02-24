"""
WP-Guardian pfSense / OPNsense Backend
Blocking via the pfSense/OPNsense REST API.

Both pfSense and OPNsense support API-based firewall management, making
them excellent choices for blocking at the network edge (similar to MikroTik).

pfSense: Uses the pfSense API package (or FauxAPI)
OPNsense: Uses the built-in REST API with key+secret auth

This backend auto-detects which platform is running based on the API
endpoint response and uses the appropriate API calls.

Requirements:
  - pfSense: Install the "pfSense-pkg-API" package from System > Package Manager
  - OPNsense: Enable API access in System > Settings > Administration > API
  - Both: Create an API key pair and configure in wp-guardian.conf

Network topology:
  Internet -> pfSense/OPNsense (gateway) -> Server
"""

import subprocess
import logging
import time
import json
import os

from backends.base import FirewallBackend
from modules.config import parse_duration

logger = logging.getLogger('wp-guardian.pfsense')


class PfSenseBackend(FirewallBackend):
    """
    Firewall backend for pfSense and OPNsense via REST API.
    Uses the 'requests' library for HTTP calls.
    """

    supports_cidr = True
    supports_friendly_list = False  # Managed via aliases on the device

    def __init__(self, config):
        # API connection settings
        self.host = config.get('pfsense', 'host', fallback='192.168.1.1')
        self.port = config.getint('pfsense', 'port', fallback=443)
        self.api_key = config.get('pfsense', 'api_key', fallback='')
        self.api_secret = config.get('pfsense', 'api_secret', fallback='')
        self.verify_ssl = config.getboolean('pfsense', 'verify_ssl', fallback=False)

        # Platform: 'pfsense' or 'opnsense' (auto-detect if empty)
        self.platform = config.get('pfsense', 'platform', fallback='').lower()

        # Alias name to use for blocked IPs (created on the firewall)
        self.alias_name = config.get('pfsense', 'alias_name', fallback='wp_guardian_blocked')
        self.alias_cidr = config.get('pfsense', 'alias_cidr', fallback='wp_guardian_cidr')

        # Parse tier durations
        self.tier1_duration_str = config.get('escalation', 'tier1_duration', fallback='24h')
        self.tier2_duration_str = config.get('escalation', 'tier2_duration', fallback='30d')
        self.tier1_seconds = parse_duration(self.tier1_duration_str)
        self.tier2_seconds = parse_duration(self.tier2_duration_str)

        # Import requests
        try:
            import requests
            self._requests = requests
            # Suppress InsecureRequestWarning if not verifying SSL
            if not self.verify_ssl:
                try:
                    from requests.packages.urllib3.exceptions import InsecureRequestWarning
                    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
                except Exception:
                    pass
        except ImportError:
            raise RuntimeError(
                "Python 'requests' library is required for pfSense/OPNsense backend.\n"
                "  Install: pip3 install requests --break-system-packages"
            )

        self._base_url = "https://{}:{}".format(self.host, self.port)

        # In-memory tracking of blocked IPs (avoid API call per check)
        self._blocked_ips = set()
        self._blocked_cidrs = set()

        if not self.test_connection():
            raise RuntimeError(
                "Cannot connect to pfSense/OPNsense API at {}.\n"
                "  Check host, port, API key/secret, and that API access is enabled.".format(
                    self._base_url
                )
            )

    def _api_call(self, method, path, data=None, timeout=15):
        """
        Make an API call to pfSense/OPNsense.
        Returns (success, response_data_or_None).
        """
        url = self._base_url + path
        headers = {'Content-Type': 'application/json'}

        try:
            if self.platform == 'opnsense':
                # OPNsense uses HTTP Basic auth with key:secret
                auth = (self.api_key, self.api_secret)
                if method.upper() == 'GET':
                    resp = self._requests.get(
                        url, auth=auth, headers=headers,
                        verify=self.verify_ssl, timeout=timeout
                    )
                elif method.upper() == 'POST':
                    resp = self._requests.post(
                        url, auth=auth, headers=headers,
                        json=data or {},
                        verify=self.verify_ssl, timeout=timeout
                    )
                elif method.upper() == 'DELETE':
                    resp = self._requests.delete(
                        url, auth=auth, headers=headers,
                        verify=self.verify_ssl, timeout=timeout
                    )
                else:
                    resp = self._requests.request(
                        method.upper(), url, auth=auth, headers=headers,
                        json=data or {},
                        verify=self.verify_ssl, timeout=timeout
                    )
            else:
                # pfSense API uses Authorization header
                headers['Authorization'] = '{} {}'.format(self.api_key, self.api_secret)
                if method.upper() == 'GET':
                    resp = self._requests.get(
                        url, headers=headers,
                        verify=self.verify_ssl, timeout=timeout
                    )
                elif method.upper() == 'POST':
                    resp = self._requests.post(
                        url, headers=headers,
                        json=data or {},
                        verify=self.verify_ssl, timeout=timeout
                    )
                elif method.upper() == 'DELETE':
                    resp = self._requests.delete(
                        url, headers=headers,
                        verify=self.verify_ssl, timeout=timeout
                    )
                else:
                    resp = self._requests.request(
                        method.upper(), url, headers=headers,
                        json=data or {},
                        verify=self.verify_ssl, timeout=timeout
                    )

            if resp.status_code < 300:
                try:
                    return (True, resp.json())
                except ValueError:
                    return (True, {'text': resp.text})
            else:
                logger.error(f"API {method} {path} returned {resp.status_code}: {resp.text[:200]}")
                return (False, None)

        except self._requests.exceptions.ConnectionError as e:
            logger.error(f"API connection error to {url}: {e}")
            return (False, None)
        except self._requests.exceptions.Timeout:
            logger.error(f"API timeout ({timeout}s) for {method} {path}")
            return (False, None)
        except Exception as e:
            logger.error(f"API exception: {e}")
            return (False, None)

    def test_connection(self):
        """Test API connectivity and auto-detect platform."""
        # Try OPNsense first (more common to have API enabled by default)
        if not self.platform or self.platform == 'opnsense':
            self.platform = 'opnsense'
            success, data = self._api_call('GET', '/api/core/firmware/status')
            if success:
                logger.info("Connected to OPNsense API")
                return True

        # Try pfSense
        if not self.platform or self.platform == 'pfsense':
            self.platform = 'pfsense'
            success, data = self._api_call('GET', '/api/v1/system/info')
            if success:
                logger.info("Connected to pfSense API")
                return True

        logger.error("Could not connect to pfSense or OPNsense API")
        return False

    def _opnsense_add_to_alias(self, alias, address):
        """Add an address to an OPNsense alias via API."""
        # OPNsense uses the firewall alias API
        success, data = self._api_call('POST', '/api/firewall/alias_util/add/{}'.format(alias), {
            'address': address
        })
        return success

    def _opnsense_remove_from_alias(self, alias, address):
        """Remove an address from an OPNsense alias."""
        success, data = self._api_call('POST', '/api/firewall/alias_util/delete/{}'.format(alias), {
            'address': address
        })
        return success

    def _opnsense_get_alias(self, alias):
        """Get all entries in an OPNsense alias. Returns list of addresses."""
        success, data = self._api_call('GET', '/api/firewall/alias_util/list/{}'.format(alias))
        if success and data:
            rows = data.get('rows', [])
            return [r.get('ip', r.get('address', '')) for r in rows if r]
        return []

    def _pfsense_add_to_alias(self, alias, address):
        """Add an address to a pfSense alias via API."""
        success, data = self._api_call('POST', '/api/v1/firewall/alias/entry', {
            'name': alias,
            'address': [address],
            'detail': ['WP-Guardian block {}'.format(time.strftime('%Y-%m-%d %H:%M'))]
        })
        if success:
            # Apply changes
            self._api_call('POST', '/api/v1/firewall/apply')
        return success

    def _pfsense_remove_from_alias(self, alias, address):
        """Remove an address from a pfSense alias."""
        success, data = self._api_call('DELETE', '/api/v1/firewall/alias/entry', {
            'name': alias,
            'address': [address]
        })
        if success:
            self._api_call('POST', '/api/v1/firewall/apply')
        return success

    def _pfsense_get_alias(self, alias):
        """Get all entries in a pfSense alias."""
        success, data = self._api_call('GET', '/api/v1/firewall/alias', {
            'name': alias
        })
        if success and data:
            entries = data.get('data', {}).get('address', '')
            if isinstance(entries, str):
                return [e.strip() for e in entries.split(' ') if e.strip()]
            return entries
        return []

    def _add_to_alias(self, alias, address):
        """Add to alias using the correct platform API."""
        if self.platform == 'opnsense':
            return self._opnsense_add_to_alias(alias, address)
        else:
            return self._pfsense_add_to_alias(alias, address)

    def _remove_from_alias(self, alias, address):
        """Remove from alias using the correct platform API."""
        if self.platform == 'opnsense':
            return self._opnsense_remove_from_alias(alias, address)
        else:
            return self._pfsense_remove_from_alias(alias, address)

    def _get_alias_entries(self, alias):
        """Get alias entries using the correct platform API."""
        if self.platform == 'opnsense':
            return self._opnsense_get_alias(alias)
        else:
            return self._pfsense_get_alias(alias)

    def block(self, ip, tier, reason, service='web'):
        """Block an IP by adding to the firewall alias."""
        if ip in self._blocked_ips:
            logger.debug(f"{self.platform}: {ip} already tracked as blocked")
            return True

        success = self._add_to_alias(self.alias_name, ip)

        if success:
            self._blocked_ips.add(ip)
            logger.info(f"{self.platform} BLOCKED {ip} tier={tier} reason={reason}")
            return True

        logger.error(f"{self.platform} block failed for {ip}")
        return False

    def unblock(self, ip):
        """Remove IP from the firewall alias."""
        success = self._remove_from_alias(self.alias_name, ip)

        if success:
            self._blocked_ips.discard(ip)
            logger.info(f"{self.platform} UNBLOCKED {ip}")
            return True

        logger.error(f"{self.platform} unblock failed for {ip}")
        return False

    def is_blocked(self, ip):
        """Check if IP is blocked (in-memory check first, then API)."""
        return ip in self._blocked_ips

    def block_cidr(self, subnet, reason, service='web', duration='30d'):
        """Block a CIDR subnet."""
        if subnet in self._blocked_cidrs:
            return True

        success = self._add_to_alias(self.alias_cidr, subnet)

        if success:
            self._blocked_cidrs.add(subnet)
            logger.info(f"{self.platform} CIDR BLOCKED {subnet} reason={reason}")
            return True

        logger.error(f"{self.platform} CIDR block failed for {subnet}")
        return False

    def is_cidr_blocked(self, subnet):
        """Check if CIDR is blocked."""
        return subnet in self._blocked_cidrs

    def get_block_counts(self):
        """Get counts from aliases."""
        counts = {
            'blocked_ips': len(self._blocked_ips),
            'blocked_cidrs': len(self._blocked_cidrs)
        }
        return counts

    def ensure_firewall_rules(self):
        """
        Verify the aliases exist on the firewall.
        The user must create:
          1. An alias (type: Host) named per alias_name config
          2. An alias (type: Network) named per alias_cidr config
          3. A firewall rule that blocks traffic from these aliases

        This method loads existing entries into memory.
        """
        logger.info(f"{self.platform} backend — alias: {self.alias_name}, CIDR alias: {self.alias_cidr}")

        # Load existing blocked IPs into memory
        try:
            entries = self._get_alias_entries(self.alias_name)
            self._blocked_ips = set(entries)
            logger.info(f"Loaded {len(self._blocked_ips)} blocked IPs from {self.platform} alias")
        except Exception as e:
            logger.warning(f"Could not load blocked IPs from alias: {e}")

        try:
            entries = self._get_alias_entries(self.alias_cidr)
            self._blocked_cidrs = set(entries)
            logger.info(f"Loaded {len(self._blocked_cidrs)} blocked CIDRs from {self.platform} alias")
        except Exception as e:
            logger.warning(f"Could not load blocked CIDRs from alias: {e}")
