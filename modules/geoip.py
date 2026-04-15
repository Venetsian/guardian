"""
WP-Guardian GeoIP Module (v1.4+)

Thin wrapper around the MaxMind GeoLite2-City + GeoLite2-ASN databases.
Provides a single `lookup(ip) -> dict` entry point with LRU caching.

Fails safe: if a database file is missing or unreadable and the config
setting `on_missing_db = warn` (default), the resolver silently disables
itself and all calls return empty dicts. Callers should check `.enabled`
or treat missing keys as empty/zero.
"""

import logging
import threading
from collections import OrderedDict

logger = logging.getLogger('wp-guardian.geoip')


EMPTY_RESULT = {
    'country': '',
    'city': '',
    'asn': 0,
    'asn_org': '',
}


class GeoIPResolver:
    def __init__(self, config):
        self.enabled = False
        self._city_reader = None
        self._asn_reader = None
        self._cache_size = config.getint('geoip', 'cache_size', fallback=10000)
        self._cache = OrderedDict()  # ip -> dict
        self._lock = threading.Lock()

        if not config.getboolean('geoip', 'enabled', fallback=False):
            logger.debug("GeoIP disabled in config")
            return

        try:
            import geoip2.database  # pure-Python, no compiled deps
        except ImportError:
            logger.warning(
                "GeoIP enabled but 'geoip2' library not installed. "
                "Run: pip install geoip2"
            )
            self._handle_missing(config, "geoip2 library not installed")
            return

        city_path = config.get(
            'geoip', 'city_database_path',
            fallback='/opt/wp-guardian/state/geoip/GeoLite2-City.mmdb'
        )
        asn_path = config.get(
            'geoip', 'asn_database_path',
            fallback='/opt/wp-guardian/state/geoip/GeoLite2-ASN.mmdb'
        )

        try:
            self._city_reader = geoip2.database.Reader(city_path)
        except Exception as e:
            logger.error("Failed to open GeoLite2-City database at {p}: {e}".format(p=city_path, e=e))
            self._handle_missing(config, "City DB unreadable: {e}".format(e=e))
            return

        try:
            self._asn_reader = geoip2.database.Reader(asn_path)
        except Exception as e:
            logger.error("Failed to open GeoLite2-ASN database at {p}: {e}".format(p=asn_path, e=e))
            # Close city reader to avoid leaking handle
            try:
                self._city_reader.close()
            except Exception:
                pass
            self._city_reader = None
            self._handle_missing(config, "ASN DB unreadable: {e}".format(e=e))
            return

        self.enabled = True
        logger.info("GeoIP enabled (City={c}, ASN={a}, cache={n})".format(
            c=city_path, a=asn_path, n=self._cache_size
        ))

    def _handle_missing(self, config, reason):
        """Respect on_missing_db config. 'fail' raises; 'warn' disables quietly."""
        policy = config.get('geoip', 'on_missing_db', fallback='warn').lower()
        if policy == 'fail':
            raise RuntimeError("GeoIP required but unavailable: {r}".format(r=reason))
        logger.warning("GeoIP disabled at runtime: {r}".format(r=reason))

    def lookup(self, ip):
        """Return geo dict for an IP. Never raises. Keys always present."""
        if not self.enabled or not ip:
            return dict(EMPTY_RESULT)

        # Cache hit?
        with self._lock:
            cached = self._cache.get(ip)
            if cached is not None:
                # Move to end (LRU)
                self._cache.move_to_end(ip)
                return dict(cached)

        result = dict(EMPTY_RESULT)

        try:
            city_resp = self._city_reader.city(ip)
            if city_resp.country and city_resp.country.iso_code:
                result['country'] = city_resp.country.iso_code
            if city_resp.city and city_resp.city.name:
                result['city'] = city_resp.city.name
        except Exception as e:
            logger.debug("City lookup failed for {ip}: {e}".format(ip=ip, e=e))

        try:
            asn_resp = self._asn_reader.asn(ip)
            if asn_resp.autonomous_system_number:
                result['asn'] = int(asn_resp.autonomous_system_number)
            if asn_resp.autonomous_system_organization:
                result['asn_org'] = asn_resp.autonomous_system_organization
        except Exception as e:
            logger.debug("ASN lookup failed for {ip}: {e}".format(ip=ip, e=e))

        # Cache insertion with LRU eviction
        if self._cache_size > 0:
            with self._lock:
                self._cache[ip] = dict(result)
                self._cache.move_to_end(ip)
                while len(self._cache) > self._cache_size:
                    self._cache.popitem(last=False)

        return result

    def close(self):
        """Close underlying MaxMind readers."""
        if self._city_reader:
            try:
                self._city_reader.close()
            except Exception:
                pass
        if self._asn_reader:
            try:
                self._asn_reader.close()
            except Exception:
                pass
