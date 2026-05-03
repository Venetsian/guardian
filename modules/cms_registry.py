"""CMS Site Registry (v1.5).

Builds and holds the {site -> {cms, docroot, admin_paths}} map used by
the web detection pipeline. The registry is built once at startup and
refreshed periodically (default every 6 hours).

Detection strategy:
  1. Walk the access-log paths in logfiles.txt and derive each site's
     name from the path (e.g. /home/<site>/logs/...).
  2. Probe conventional docroot locations for each site.
  3. Fingerprint the docroot by file presence (wp-config.php =
     WordPress, configuration.php + /administrator = Joomla, etc.).
  4. Record the result in the cms_sites table and the in-memory map.

Per-vhost overrides come from a simple INI file (vhosts.conf) where the
operator can pin a site's CMS or extend its admin-path list. Overrides
always win over auto-detection.

Detection is best-effort. A site that cannot be fingerprinted is recorded
as 'unknown' and gets only the universal web rules — no harm done.
"""

import os
import time
import logging
import threading

try:
    import configparser
except ImportError:
    import ConfigParser as configparser  # type: ignore


logger = logging.getLogger('wp-guardian.cms-registry')


# CMS fingerprints — checked in order; first match wins.
# Each entry: (cms_name, list_of_relative_paths_that_must_exist, list_of_relative_dirs_that_must_exist)
# v1.5 ships WordPress as the only "real" CMS. Joomla/Drupal/etc. are
# detected so the registry knows what they are, but their detection
# modules will land in v1.6+.
CMS_FINGERPRINTS = [
    ('wordpress',  ['wp-config.php'],                     []),
    ('wordpress',  ['wp-includes/version.php'],           []),
    ('joomla',     ['configuration.php'],                 ['administrator']),
    ('drupal',     ['core/lib/Drupal.php'],               []),       # Drupal 8+
    ('drupal',     ['includes/bootstrap.inc'],            ['sites']),  # Drupal 7
    ('magento',    ['app/etc/env.php'],                   []),       # Magento 2
    ('magento',    ['app/etc/local.xml'],                 []),       # Magento 1
    ('prestashop', ['config/settings.inc.php'],           []),
    ('opencart',   ['system/startup.php', 'admin/config.php'], []),
    ('phpmyadmin', ['libraries/config.default.php'],      []),
]


# Default admin paths registered per CMS. Lowercase. Used by POST-flood
# (and any future CMS-specific detector) so we don't have to discover
# them per-site.
#
# For CMSes that ship a detector skeleton in detectors/ we pull the path
# list from there (single source of truth). For the others we hardcode
# the defaults here.
def _build_default_admin_paths():
    paths = {
        'wordpress':  ['/wp-login.php', '/xmlrpc.php'],
        'magento':    ['/admin/', '/index.php/admin/'],
        'prestashop': [],   # PrestaShop randomizes admin paths; operator must declare in vhosts.conf
        'opencart':   ['/admin/index.php'],
        'phpmyadmin': ['/index.php'],
        'unknown':    [],
    }
    try:
        from detectors.joomla import JoomlaDetector
        paths[JoomlaDetector.CMS_NAME] = list(JoomlaDetector.ADMIN_PATHS)
    except ImportError:
        paths.setdefault('joomla', ['/administrator/index.php'])
    try:
        from detectors.drupal import DrupalDetector
        paths[DrupalDetector.CMS_NAME] = list(DrupalDetector.ADMIN_PATHS)
    except ImportError:
        paths.setdefault('drupal', ['/user/login'])
    return paths


DEFAULT_ADMIN_PATHS = _build_default_admin_paths()


# Common docroot locations to probe for a given site name.
DOCROOT_CANDIDATES = [
    '/home/{site}/public_html',
    '/home/{site}/www',
    '/var/www/{site}',
    '/var/www/{site}/public_html',
    '/var/www/html/{site}',
    '/usr/local/lsws/{site}/html',
]


class CMSRegistry:
    """In-memory site -> CMS classification, persisted to the cms_sites table."""

    def __init__(self, config, db, logfiles_list_path):
        self.config = config
        self.db = db
        self.logfiles_list_path = logfiles_list_path
        self.enabled = config.getboolean('cms_detection', 'enabled', fallback=True)
        self.refresh_interval = config.getint(
            'cms_detection', 'refresh_interval', fallback=21600  # 6h
        )
        self.vhosts_overrides_path = config.get(
            'cms_detection', 'vhosts_overrides',
            fallback='/opt/wp-guardian/vhosts.conf',
        )
        self._sites = {}            # site -> dict
        self._lock = threading.Lock()
        self._last_refresh = 0

    # ----- Public API -----

    def get(self, site):
        """Return the registry entry for a site, or a synthetic 'unknown' record."""
        if not site:
            return self._unknown('')
        with self._lock:
            entry = self._sites.get(site)
            if entry:
                return entry
        return self._unknown(site)

    def all(self):
        with self._lock:
            return dict(self._sites)

    def refresh(self):
        """Rebuild the registry. Safe to call from a periodic loop."""
        if not self.enabled:
            return
        try:
            sites = self._discover_sites()
            overrides = self._load_vhosts_overrides()

            new_map = {}
            for site, docroot in sites.items():
                ov = overrides.get(site)
                if ov:
                    cms = ov.get('cms', 'unknown')
                    paths = ov.get('admin_paths') or list(DEFAULT_ADMIN_PATHS.get(cms, []))
                    overridden = True
                else:
                    cms = self._fingerprint(docroot)
                    paths = list(DEFAULT_ADMIN_PATHS.get(cms, []))
                    overridden = False

                entry = {
                    'site': site,
                    'cms': cms,
                    'docroot': docroot,
                    'admin_paths': paths,
                    'overridden': overridden,
                    'detected_at': int(time.time()),
                }
                new_map[site] = entry
                try:
                    self.db.cms_sites_upsert(site, cms, docroot, paths, overridden)
                except Exception as e:
                    logger.warning("cms_sites_upsert failed for {s}: {e}".format(s=site, e=e))

            with self._lock:
                self._sites = new_map
                self._last_refresh = time.time()

            logger.info("CMS registry refreshed: %d sites (%s)",
                        len(new_map), self._summarize(new_map))
        except Exception as e:
            logger.error("CMS registry refresh failed: %s", e)

    def needs_refresh(self):
        return (time.time() - self._last_refresh) >= self.refresh_interval

    # ----- Internals -----

    def _unknown(self, site):
        return {
            'site': site,
            'cms': 'unknown',
            'docroot': '',
            'admin_paths': [],
            'overridden': False,
            'detected_at': 0,
        }

    def _discover_sites(self):
        """Read logfiles.txt and derive {site_name: docroot} pairs.

        Site name comes from the standard /home/<site>/logs/... layout used
        by CyberPanel, OLS, and similar control panels. For other layouts
        the operator can pre-populate cms_sites via vhosts.conf.
        """
        sites = {}
        if not os.path.isfile(self.logfiles_list_path):
            return sites

        with open(self.logfiles_list_path, 'r') as f:
            for line in f:
                path = line.strip()
                if not path or path.startswith('#'):
                    continue
                site = self._extract_site_from_logpath(path)
                if not site:
                    continue
                docroot = self._find_docroot(site)
                sites[site] = docroot or ''
        return sites

    def _extract_site_from_logpath(self, log_path):
        """Pull <site> out of /home/<site>/logs/..."""
        parts = log_path.replace('\\', '/').split('/')
        if len(parts) >= 4 and parts[1] == 'home' and parts[3] == 'logs':
            return parts[2]
        return None

    def _find_docroot(self, site):
        for tmpl in DOCROOT_CANDIDATES:
            candidate = tmpl.format(site=site)
            if os.path.isdir(candidate):
                return candidate
        return None

    def _fingerprint(self, docroot):
        if not docroot or not os.path.isdir(docroot):
            return 'unknown'
        for cms, files, dirs in CMS_FINGERPRINTS:
            if all(os.path.isfile(os.path.join(docroot, f)) for f in files) and \
               all(os.path.isdir(os.path.join(docroot, d)) for d in dirs):
                return cms
        return 'unknown'

    def _load_vhosts_overrides(self):
        """Parse vhosts.conf — INI per site. Empty / missing file is OK."""
        if not os.path.isfile(self.vhosts_overrides_path):
            return {}

        parser = configparser.ConfigParser()
        try:
            parser.read(self.vhosts_overrides_path)
        except Exception as e:
            logger.warning("vhosts.conf parse failed: %s", e)
            return {}

        out = {}
        for section in parser.sections():
            entry = {}
            if parser.has_option(section, 'cms'):
                entry['cms'] = parser.get(section, 'cms').strip().lower()
            if parser.has_option(section, 'admin_paths'):
                raw = parser.get(section, 'admin_paths')
                entry['admin_paths'] = [
                    p.strip().lower() for p in raw.split(',') if p.strip()
                ]
            if parser.has_option(section, 'post_flood_threshold'):
                try:
                    entry['post_flood_threshold'] = parser.getint(section, 'post_flood_threshold')
                except ValueError:
                    pass
            out[section] = entry
        return out

    def _summarize(self, sites_map):
        counts = {}
        for entry in sites_map.values():
            counts[entry['cms']] = counts.get(entry['cms'], 0) + 1
        return ', '.join('%s=%d' % (k, v) for k, v in sorted(counts.items()))
