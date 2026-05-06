"""
WP-Guardian Host Profile Detector (task #122).

Each managed host has a profile of static-ish facts that decide which
posture and host-health checks apply. Most flags are auto-detected on
first run and re-detected daily; a few (notably behind_perimeter_firewall)
must be set in [posture] config because they are not derivable from the
host alone.

Detection is deliberately defensive — every probe is wrapped so a single
unexpected layout doesn't kill the whole detector. A field we couldn't
determine falls back to the safe default ('none' / False).

Profile fields (see migrations/008_posture_audit.sql for the schema):
  is_linux, is_cloudlinux, is_multi_tenant, is_single_site,
  web_server (apache|ols|nginx|none),
  db_server (mariadb|mysql|none),
  mta (postfix|none),
  has_modsec,
  behind_perimeter_firewall,
  distro_id, distro_version,
  extras (free-form dict serialized as JSON)
"""

import logging
import os
import socket
import subprocess

logger = logging.getLogger('wp-guardian.host_profile')


def _safe_run(cmd, timeout=5):
    """Run a command and return (returncode, stdout). Never raises."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            universal_newlines=True,
        )
        return proc.returncode, proc.stdout or ''
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.debug("Probe failed (%s): %s", ' '.join(cmd), e)
        return -1, ''


def _read_text(path, max_bytes=65536):
    """Read a small text file. Returns '' on any error."""
    try:
        with open(path, 'r') as f:
            return f.read(max_bytes)
    except (IOError, OSError):
        return ''


def _parse_os_release(content):
    """Parse /etc/os-release output into a dict."""
    out = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        value = value.strip().strip('"').strip("'")
        out[key.strip()] = value
    return out


class HostProfileDetector:
    """Detects + caches the current host's profile.

    Usage from the daemon:
        detector = HostProfileDetector(config, db)
        profile = detector.get_or_detect()  # cached / fresh
        profile = detector.detect_now()     # force re-detect
    """

    def __init__(self, config, db, hostname=None):
        self.config = config
        self.db = db
        self.hostname = hostname or self._resolve_hostname()
        self.refresh_seconds = config.getint(
            'posture', 'profile_refresh_seconds', fallback=86400
        )
        # behind_perimeter_firewall is a config-driven override because it
        # describes the network around the host, not the host itself.
        self._perimeter_override = self._read_perimeter_override()

    @staticmethod
    def _resolve_hostname():
        try:
            return socket.gethostname() or 'localhost'
        except Exception:
            return 'localhost'

    def _read_perimeter_override(self):
        """Return True/False/None for the perimeter flag.

        None means "auto" (we'll guess False — safer to assume we're exposed).
        """
        if not self.config.has_section('posture'):
            return None
        if not self.config.has_option('posture', 'behind_perimeter_firewall'):
            return None
        raw = self.config.get('posture', 'behind_perimeter_firewall', fallback='auto').strip().lower()
        if raw in ('true', 'yes', '1', 'on'):
            return True
        if raw in ('false', 'no', '0', 'off'):
            return False
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def get_or_detect(self):
        """Return the cached profile if fresh; otherwise re-detect.

        Cache freshness is `refresh_seconds` from the stored detected_at.
        """
        import time
        cached = self.db.host_profile_get(self.hostname)
        if cached is not None:
            age = int(time.time()) - int(cached.get('detected_at') or 0)
            if age < self.refresh_seconds:
                return cached
        return self.detect_now()

    def detect_now(self, detection_method='auto'):
        """Run every probe and persist the result. Returns the new profile."""
        profile = self._build_profile()
        self.db.host_profile_upsert(
            self.hostname, profile, detection_method=detection_method
        )
        logger.info(
            "Host profile detected: distro=%s/%s web=%s db=%s mta=%s "
            "cloudlinux=%s multi_tenant=%s single_site=%s modsec=%s perimeter=%s",
            profile.get('distro_id') or '?',
            profile.get('distro_version') or '?',
            profile.get('web_server'),
            profile.get('db_server'),
            profile.get('mta'),
            profile.get('is_cloudlinux'),
            profile.get('is_multi_tenant'),
            profile.get('is_single_site'),
            profile.get('has_modsec'),
            profile.get('behind_perimeter_firewall'),
        )
        return self.db.host_profile_get(self.hostname)

    # ------------------------------------------------------------------
    # Probe implementations
    # ------------------------------------------------------------------
    def _build_profile(self):
        is_linux = self._detect_linux()
        distro_id, distro_version = self._detect_distro()
        is_cloudlinux = self._detect_cloudlinux(distro_id)
        web_server = self._detect_web_server()
        db_server = self._detect_db_server()
        mta = self._detect_mta()
        has_modsec = self._detect_modsec(web_server)
        is_multi_tenant, is_single_site = self._detect_tenancy()

        if self._perimeter_override is None:
            behind_perimeter = False
        else:
            behind_perimeter = self._perimeter_override

        extras = {
            'kernel': self._detect_kernel(),
        }

        return {
            'host': self.hostname,
            'is_linux': is_linux,
            'is_cloudlinux': is_cloudlinux,
            'is_multi_tenant': is_multi_tenant,
            'is_single_site': is_single_site,
            'web_server': web_server,
            'db_server': db_server,
            'mta': mta,
            'has_modsec': has_modsec,
            'behind_perimeter_firewall': behind_perimeter,
            'distro_id': distro_id,
            'distro_version': distro_version,
            'extras': extras,
        }

    def _detect_linux(self):
        try:
            import platform
            return platform.system().lower() == 'linux'
        except Exception:
            return os.path.exists('/proc/version')

    def _detect_distro(self):
        """Return (id, version) from /etc/os-release if present."""
        content = _read_text('/etc/os-release')
        if not content:
            return ('', '')
        info = _parse_os_release(content)
        return (info.get('ID', '') or '', info.get('VERSION_ID', '') or '')

    def _detect_cloudlinux(self, distro_id):
        """CloudLinux ships its own /etc/os-release ID, plus /proc/lve/list
        as a kernel-side proof of life."""
        if (distro_id or '').lower() in ('cloudlinux', 'cl'):
            return True
        # Fallback: kernel module visibility
        if os.path.exists('/proc/lve/list'):
            return True
        return False

    def _detect_web_server(self):
        """Detect the *running* web server, not the installed-but-idle one.

        Real-world hosts can have multiple web servers installed at once.
        On CloudLinux+Apache boxes lshttpd is sometimes installed-then-masked
        when the operator switches stack — disk-based detection alone would
        wrongly report 'ols'. So: query systemd first; only fall back to
        path probes if systemd can't tell us (e.g. no systemd, or running
        in a chroot during install).

        Order: ols, apache, nginx — first match wins. Disk fallback uses
        the same precedence but with a sanity check that the binary exists.
        """
        # systemd probe — units that come back 'active' win
        unit_to_label = [
            ('lshttpd',  'ols'),
            ('lsws',     'ols'),
            ('httpd',    'apache'),
            ('apache2',  'apache'),
            ('nginx',    'nginx'),
        ]
        for unit, label in unit_to_label:
            rc, out = _safe_run(['systemctl', 'is-active', '--quiet', unit])
            if rc == 0:
                return label

        # systemd unavailable / nothing active. Fall back to disk presence.
        # Require both a config dir AND a binary so 'leftover from old stack'
        # configs don't trip the detector.
        if (os.path.isdir('/usr/local/lsws')
                and (os.path.exists('/usr/local/lsws/bin/lshttpd')
                     or os.path.exists('/usr/local/lsws/bin/openlitespeed'))):
            return 'ols'
        if ((os.path.exists('/usr/sbin/httpd') and os.path.isdir('/etc/httpd'))
                or (os.path.exists('/usr/sbin/apache2')
                    and os.path.isdir('/etc/apache2'))):
            return 'apache'
        if os.path.exists('/usr/sbin/nginx') and os.path.isdir('/etc/nginx'):
            return 'nginx'
        return 'none'

    def _detect_db_server(self):
        """Detect MariaDB before MySQL — MariaDB ships a fork that answers to
        both socket names, but the binary is usually only one."""
        if os.path.exists('/usr/bin/mariadb') or os.path.exists('/usr/sbin/mariadbd'):
            return 'mariadb'
        if os.path.exists('/usr/bin/mysql') and os.path.exists('/usr/sbin/mysqld'):
            return 'mysql'
        # Fallback: socket presence
        for sock in ('/var/lib/mysql/mysql.sock',
                     '/var/run/mysqld/mysqld.sock',
                     '/var/run/mariadb/mariadb.sock'):
            if os.path.exists(sock):
                # We can't tell flavor from a socket alone; default to mariadb
                # because it's the more common choice in the maiahost stack.
                return 'mariadb'
        return 'none'

    def _detect_mta(self):
        if os.path.exists('/usr/sbin/postfix') or os.path.isdir('/etc/postfix'):
            return 'postfix'
        return 'none'

    def _detect_modsec(self, web_server):
        """Look for mod_security config presence. We don't try to verify it's
        enabled — Apache config can be elaborate. The check itself will dig
        deeper if needed."""
        candidates = [
            '/etc/httpd/modsecurity.d',
            '/etc/httpd/conf.d/mod_security.conf',
            '/etc/apache2/mods-enabled/security2.load',
            '/etc/modsecurity',
            '/usr/local/lsws/conf/modsec.conf',
        ]
        for path in candidates:
            if os.path.exists(path):
                return True
        return False

    def _detect_tenancy(self):
        """Return (is_multi_tenant, is_single_site).

        Heuristic:
          * is_multi_tenant: there are at least 2 entries in /home that look
            like tenant accounts (each owning a public_html or web/ subdir).
          * is_single_site: opposite — at most one tenant-shaped /home entry.

        These are intentionally a bit loose. Operators with a non-standard
        layout can override via [posture] is_multi_tenant in config.
        """
        # Config override wins
        if self.config.has_option('posture', 'is_multi_tenant'):
            raw = self.config.get('posture', 'is_multi_tenant', fallback='auto').strip().lower()
            if raw in ('true', 'yes', '1', 'on'):
                return (True, False)
            if raw in ('false', 'no', '0', 'off'):
                return (False, True)

        try:
            entries = os.listdir('/home')
        except OSError:
            return (False, True)

        tenant_count = 0
        for name in entries:
            if name.startswith('.'):
                continue
            home = os.path.join('/home', name)
            if not os.path.isdir(home):
                continue
            if (os.path.isdir(os.path.join(home, 'public_html'))
                    or os.path.isdir(os.path.join(home, 'web'))
                    or os.path.isdir(os.path.join(home, 'logs'))):
                tenant_count += 1
                if tenant_count >= 2:
                    break

        if tenant_count >= 2:
            return (True, False)
        return (False, True)

    def _detect_kernel(self):
        rc, out = _safe_run(['uname', '-r'])
        return out.strip() if rc == 0 else ''
