#!/usr/bin/env python3
"""
WP-Guardian: WordPress & Server Security Monitoring Daemon
Main entry point — initializes all modules and runs the monitoring loop.
"""

import sys
import os
import signal
import logging
import time
import argparse
import subprocess
import threading
import re
import glob as glob_module
from collections import defaultdict

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.config import load_config, load_whitelist_file, load_tripwire_file, parse_duration
from modules.database import GuardianDB
from modules.whitelist import WhitelistManager
from modules.blocker import Blocker
from backends.factory import create_backend
from actions.telegram import TelegramAlerter
from actions.telegram_commands import TelegramCommander


def get_version(base_dir=None):
    """Read the application version from VERSION file."""
    if not base_dir:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    version_file = os.path.join(base_dir, 'VERSION')
    try:
        with open(version_file, 'r') as f:
            return f.read().strip()
    except (IOError, OSError):
        return 'unknown'


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
def setup_logging(config, base_dir=None):
    log_level = config.get('general', 'log_level', fallback='INFO').upper()
    if base_dir:
        log_dir = os.path.join(base_dir, 'logs')
    else:
        log_dir = config.get('paths', 'logs_dir', fallback='/opt/wp-guardian/logs')
    os.makedirs(log_dir, exist_ok=True)

    # Main logger
    logger = logging.getLogger('wp-guardian')
    logger.setLevel(getattr(logging, log_level, logging.INFO))

    # File handler
    fh = logging.FileHandler(os.path.join(log_dir, 'guardian.log'))
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(fh)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, log_level, logging.INFO))
    ch.setFormatter(logging.Formatter(
        '[%(asctime)s] [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    ))
    logger.addHandler(ch)

    # Block log (separate file)
    block_logger = logging.getLogger('wp-guardian.blocks')
    bh = logging.FileHandler(os.path.join(log_dir, 'blocked.log'))
    bh.setFormatter(logging.Formatter('%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
    block_logger.addHandler(bh)

    return logger


# ---------------------------------------------------------------------------
# Hit Tracker — in-memory counters with time windows
# ---------------------------------------------------------------------------
class HitTracker:
    """Tracks hit counts per IP within a sliding time window."""

    def __init__(self, time_window=300):
        self.time_window = time_window
        self._hits = defaultdict(list)  # ip -> [timestamp, timestamp, ...]

    def add(self, ip):
        """Record a hit and return current count within window."""
        now = time.time()
        self._hits[ip].append(now)
        # Prune old entries
        cutoff = now - self.time_window
        self._hits[ip] = [t for t in self._hits[ip] if t > cutoff]
        return len(self._hits[ip])

    def get_count(self, ip):
        """Get current hit count within window."""
        now = time.time()
        cutoff = now - self.time_window
        self._hits[ip] = [t for t in self._hits[ip] if t > cutoff]
        return len(self._hits[ip])

    def cleanup(self):
        """Remove stale entries."""
        now = time.time()
        cutoff = now - self.time_window
        stale = [ip for ip, hits in self._hits.items() if not hits or hits[-1] < cutoff]
        for ip in stale:
            del self._hits[ip]


# ---------------------------------------------------------------------------
# Web Log Parser
# ---------------------------------------------------------------------------
class WebDetector:
    """Parses web access logs and detects attacks."""

    def __init__(self, config, blocker, db, tripwires, whitelist=None):
        self.blocker = blocker
        self.db = db
        self.tripwires = tripwires
        self.whitelist = whitelist
        self.time_window = config.getint('thresholds', 'time_window', fallback=300)

        # Thresholds
        self.wp_login_threshold = config.getint('thresholds', 'wp_login_threshold', fallback=10)
        self.xmlrpc_threshold = config.getint('thresholds', 'xmlrpc_threshold', fallback=5)
        self.author_enum_threshold = config.getint('thresholds', 'author_enum_threshold', fallback=8)
        self.php_404_threshold = config.getint('thresholds', 'php_404_threshold', fallback=20)
        self.general_404_threshold = config.getint('thresholds', 'general_404_threshold', fallback=50)

        # Auth tracking
        self.trust_duration = config.getint('auth_tracking', 'wp_trust_duration', fallback=24) * 3600

        # Hit trackers (separate per rule type)
        self.hits_login = HitTracker(self.time_window)
        self.hits_xmlrpc = HitTracker(self.time_window)
        self.hits_author = HitTracker(self.time_window)
        self.hits_php404 = HitTracker(self.time_window)
        self.hits_404 = HitTracker(self.time_window)

        # Structural tripwires (always active, no file needed)
        self.structural_patterns = [
            re.compile(r'/wp-content/uploads/.*\.php', re.IGNORECASE),
        ]

        # Pattern tripwires — INSTANT block (known malicious, no legitimate use ever)
        self.instant_patterns = [
            (re.compile(r'/(alfa|c99|r57|wso|b374k|eval-stdin)\.php', re.IGNORECASE), 'Known webshell'),
        ]

        # Short PHP filenames that are legitimate (not suspicious)
        self.legit_short_php = {
            '/api.php', '/ajax.php', '/public.php',
            '/cron.php', '/rss.php', '/feed.php',
        }

        # Paths that should NEVER be tripwires (legitimate WordPress/app paths)
        self.safe_path_patterns = [
            re.compile(r'^/wp-admin/'),           # All WordPress admin pages
            re.compile(r'^/wp-includes/'),         # WordPress core includes
            re.compile(r'^.*/wp-admin/'),          # Subdir WP admin (e.g., /blog/wp-admin/)
        ]

        # Pattern tripwires — THRESHOLD based (suspicious but could be a mistake)
        self.suspicious_patterns = [
            re.compile(r'^/[a-z0-9]{1,4}\.php$'),
            re.compile(r'^/[a-z]{6,}\.php$'),
            re.compile(r'/wp-content/themes/[^/]+/(db|admin|shell|config|cmd)\.php', re.IGNORECASE),
            re.compile(r'^/(wp-good|wp-plain|xmrlpc)\.php$'),
        ]

        self.hits_suspicious = HitTracker(self.time_window)
        self.suspicious_threshold = 3

        # Login isolation detection
        self.login_isolation_threshold = config.getint('thresholds', 'login_isolation_threshold', fallback=3)
        self.login_isolation_window = config.getint('thresholds', 'login_isolation_window', fallback=120)

    def process_line(self, line, site=''):
        """Process a single access log line."""
        # OLS wraps lines in quotes — strip them
        if line.startswith('"'):
            line = line[1:]
        if line.endswith('"'):
            line = line[:-1]

        # Parse the line: IP - - [date] "METHOD /path HTTP/x.x" STATUS SIZE ...
        ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
        if not ip_match:
            return

        ip = ip_match.group(1)

        # Extract request
        req_match = re.search(r'"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) ([^ ]+) HTTP', line)
        if not req_match:
            return

        method = req_match.group(1)
        path = req_match.group(2)

        # Extract status
        status_match = re.search(r'" (\d{3}) ', line)
        if not status_match:
            return

        status = status_match.group(1)

        # Clean path — remove query string, lowercase
        clean_path = re.sub(r'\?.*$', '', path).lower()

        # ----- WHITELIST EARLY BYPASS -----
        # Skip all detection for whitelisted IPs, but still record successful WP logins
        if self.whitelist and self.whitelist.is_whitelisted(ip):
            if method == 'POST' and 'wp-login.php' in clean_path and status == '302':
                self.db.record_auth(ip, 'wordpress', 'unknown', site='', country='', city='')
            return

        # ----- LOGIN ISOLATION: track CSS loads (real browser signal) -----
        if clean_path.endswith('.css'):
            self.db.login_isolation_record_css(ip)

        # ----- AUTHENTICATION TRACKING -----
        if method == 'POST' and 'wp-login.php' in clean_path and status == '302':
            self.db.record_auth(ip, 'wordpress', 'unknown', site='', country='', city='')
            return

        # ----- TRIPWIRE RULES (instant block for non-authenticated) -----

        # Skip safe paths (wp-admin, wp-includes — always legitimate)
        for pattern in self.safe_path_patterns:
            if pattern.search(clean_path):
                return

        # Check structural tripwires first (e.g., PHP in uploads)
        for pattern in self.structural_patterns:
            if pattern.search(clean_path):
                if self.db.is_ip_authenticated(ip, self.trust_duration):
                    logging.getLogger('wp-guardian.web').warning(
                        f"Authenticated IP {ip} hit structural tripwire: {clean_path}"
                    )
                    return
                self.blocker.block(ip, f"PHP in uploads: {clean_path}", service='web', site=site)
                return

        # Check instant-block patterns (known webshells)
        if clean_path.endswith('.php'):
            for pattern, description in self.instant_patterns:
                if pattern.search(clean_path):
                    if self.db.is_ip_authenticated(ip, self.trust_duration):
                        logging.getLogger('wp-guardian.web').warning(
                            f"Authenticated IP {ip} hit instant pattern: {description} ({clean_path})"
                        )
                        return
                    self.blocker.block(ip, f"{description}: {clean_path}", service='web', site=site)
                    return

        # Check suspicious patterns (threshold-based)
        if clean_path.endswith('.php') and status in ('404', '401', '403'):
            if clean_path not in self.legit_short_php:
                for pattern in self.suspicious_patterns:
                    if pattern.search(clean_path):
                        count = self.hits_suspicious.add(ip)
                        if count >= self.suspicious_threshold:
                            self.blocker.block(ip, f"Suspicious PHP scanning ({count} pattern hits in {self.time_window}s)", service='web', site=site)
                        return

        # Check file-based tripwires (PHP only)
        if clean_path.endswith('.php') and clean_path in self.tripwires:
            if self.db.is_ip_authenticated(ip, self.trust_duration):
                logging.getLogger('wp-guardian.web').warning(
                    f"Authenticated IP {ip} hit tripwire: {clean_path}"
                )
                return
            self.db.record_tripwire_hit(clean_path)
            self.blocker.block(ip, f"Tripwire: {clean_path}", service='web', site=site)
            return

        # ----- LOGIN ISOLATION DETECTION -----
        if 'wp-login.php' in clean_path:
            if not self.db.is_ip_authenticated(ip, self.trust_duration):
                login_hits, has_css = self.db.login_isolation_record_hit(ip)
                if login_hits >= self.login_isolation_threshold and not has_css:
                    self.blocker.block(
                        ip,
                        f"Login isolation: {login_hits} wp-login.php hits, zero CSS loads",
                        service='web',
                        site=site
                    )
                    return

        # ----- THRESHOLD RULES -----

        # wp-login.php brute force
        if 'wp-login.php' in clean_path and method == 'POST' and status != '302':
            count = self.hits_login.add(ip)
            if count >= self.wp_login_threshold:
                self.blocker.block(ip, f"wp-login brute force ({count} in {self.time_window}s)", service='web', site=site)
            return

        # xmlrpc.php
        if 'xmlrpc.php' in clean_path:
            count = self.hits_xmlrpc.add(ip)
            if count >= self.xmlrpc_threshold:
                self.blocker.block(ip, f"xmlrpc abuse ({count} in {self.time_window}s)", service='web', site=site)
            return

        # Author enumeration
        if re.search(r'\?author=\d', path):
            count = self.hits_author.add(ip)
            if count >= self.author_enum_threshold:
                self.blocker.block(ip, f"Author enumeration ({count} in {self.time_window}s)", service='web', site=site)
            return

        # PHP file 404s
        if status in ('404', '401') and clean_path.endswith('.php'):
            count = self.hits_php404.add(ip)
            if count >= self.php_404_threshold:
                self.blocker.block(ip, f"PHP scanning ({count} 404s in {self.time_window}s)", service='web', site=site)
            return

        # General 404 storm
        if status in ('404', '403'):
            count = self.hits_404.add(ip)
            if count >= self.general_404_threshold:
                self.blocker.block(ip, f"404 storm ({count} in {self.time_window}s)", service='web', site=site)
            return


# ---------------------------------------------------------------------------
# Mail Log Parser
# ---------------------------------------------------------------------------
class MailDetector:
    """Parses /var/log/maillog for SMTP and IMAP/POP3 attacks."""

    def __init__(self, config, blocker, db, whitelist=None):
        self.blocker = blocker
        self.db = db
        self.whitelist = whitelist
        self.time_window = config.getint('thresholds', 'time_window', fallback=300)

        self.smtp_threshold = config.getint('thresholds', 'smtp_auth_fail_threshold', fallback=5)
        self.imap_threshold = config.getint('thresholds', 'imap_auth_fail_threshold', fallback=5)

        self.hits_smtp = HitTracker(self.time_window)
        self.hits_imap = HitTracker(self.time_window)

    def process_line(self, line):
        """Process a single maillog line."""

        # SMTP failed auth
        if 'authentication failed' in line.lower():
            ip_match = re.search(r'unknown\[(\d+\.\d+\.\d+\.\d+)\]', line)
            if not ip_match:
                ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', line)
            if ip_match:
                ip = ip_match.group(1)
                if self.whitelist and self.whitelist.is_whitelisted(ip):
                    return
                count = self.hits_smtp.add(ip)
                if count >= self.smtp_threshold:
                    self.blocker.block(ip, f"SMTP auth brute force ({count} in {self.time_window}s)", service='smtp')
            return

        # SMTP successful auth — record for geo tracking
        if 'sasl_username=' in line:
            ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', line)
            user_match = re.search(r'sasl_username=(\S+)', line)
            if ip_match and user_match:
                ip = ip_match.group(1)
                username = user_match.group(1)
                self.db.record_auth(ip, 'smtp', username)
            return

        # Dovecot failed auth (IMAP/POP3)
        if 'auth failed' in line:
            ip_match = re.search(r'rip=(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                if self.whitelist and self.whitelist.is_whitelisted(ip):
                    return
                count = self.hits_imap.add(ip)
                if count >= self.imap_threshold:
                    service = 'imap' if 'imap-login' in line else 'pop3'
                    self.blocker.block(ip, f"{service.upper()} auth brute force ({count} in {self.time_window}s)",
                                      service=service)
            return

        # Dovecot successful auth — record for geo tracking
        if 'Login: user=' in line:
            ip_match = re.search(r'rip=(\d+\.\d+\.\d+\.\d+)', line)
            user_match = re.search(r'user=<([^>]+)>', line)
            if ip_match and user_match:
                ip = ip_match.group(1)
                username = user_match.group(1)
                service = 'imap' if 'imap-login' in line else 'pop3'
                self.db.record_auth(ip, service, username)
            return


# ---------------------------------------------------------------------------
# SSH Log Parser
# ---------------------------------------------------------------------------
class SSHDetector:
    """Parses /var/log/secure for SSH attacks."""

    def __init__(self, config, blocker, db, whitelist=None):
        self.blocker = blocker
        self.db = db
        self.whitelist = whitelist
        self.time_window = config.getint('thresholds', 'time_window', fallback=300)

        self.ssh_threshold = config.getint('thresholds', 'ssh_fail_threshold', fallback=3)
        self.instant_block_invalid = config.getboolean(
            'thresholds', 'ssh_invalid_user_instant_block', fallback=True
        )

        self.hits_ssh = HitTracker(self.time_window)

    def process_line(self, line):
        """Process a single secure log line."""

        # Invalid user — instant block
        if 'Invalid user' in line or 'invalid user' in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if ip_match and self.instant_block_invalid:
                ip = ip_match.group(1)
                if self.whitelist and self.whitelist.is_whitelisted(ip):
                    return
                user_match = re.search(r'[Ii]nvalid user (\S+)', line)
                username = user_match.group(1) if user_match else 'unknown'
                self.blocker.block(ip, f"SSH invalid user: {username}", service='ssh')
            return

        # Failed password
        if 'Failed password' in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                if self.whitelist and self.whitelist.is_whitelisted(ip):
                    return
                count = self.hits_ssh.add(ip)
                if count >= self.ssh_threshold:
                    self.blocker.block(ip, f"SSH brute force ({count} in {self.time_window}s)", service='ssh')
            return

        # Successful login — record for geo tracking
        if 'Accepted password' in line or 'Accepted publickey' in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            user_match = re.search(r'for (\S+) from', line)
            if ip_match and user_match:
                ip = ip_match.group(1)
                username = user_match.group(1)
                self.db.record_auth(ip, 'ssh', username)
            return


# ---------------------------------------------------------------------------
# Log Tailer — follows multiple log files
# ---------------------------------------------------------------------------
class LogTailer:
    """Tails multiple log files and dispatches lines to detectors."""

    # Regex to extract domain from tail --verbose headers
    _TAIL_HEADER_RE = re.compile(r'^==> /home/([^/]+)/')

    def __init__(self, log_files, detector, name='tailer', track_site=False):
        self.log_files = log_files
        self.detector = detector
        self.name = name
        self.track_site = track_site
        self.process = None
        self.thread = None
        self.running = False
        self.logger = logging.getLogger(f'wp-guardian.{name}')

    def start(self):
        """Start tailing logs in a background thread."""
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True, name=self.name)
        self.thread.start()
        self.logger.info(f"Started tailing {len(self.log_files)} log file(s)")

    def _run(self):
        """Main tail loop."""
        cmd = ['tail', '-F', '-n', '0']
        if self.track_site:
            cmd.append('--verbose')
        cmd += self.log_files

        current_site = ''

        while self.running:
            try:
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    universal_newlines=True,
                    bufsize=1
                )

                for line in self.process.stdout:
                    if not self.running:
                        break
                    line = line.strip()
                    if not line:
                        continue

                    # Track which log file (domain) we're reading from
                    if self.track_site and line.startswith('==>'):
                        header_match = self._TAIL_HEADER_RE.match(line)
                        if header_match:
                            current_site = header_match.group(1)
                        continue

                    try:
                        if self.track_site:
                            self.detector.process_line(line, site=current_site)
                        else:
                            self.detector.process_line(line)
                    except Exception as e:
                        self.logger.error(f"Error processing line: {e}")

            except Exception as e:
                self.logger.error(f"Tail process error: {e}")
                if self.running:
                    time.sleep(5)  # Wait before retry

    def stop(self):
        """Stop tailing."""
        self.running = False
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()


# ---------------------------------------------------------------------------
# Log Discovery
# ---------------------------------------------------------------------------
def discover_access_logs():
    """Find all access log files on the system."""
    patterns = [
        '/home/*/logs/*.access_log',
        '/home/*/logs/*.access.log',
        '/var/log/httpd/*access*',
        '/var/log/apache2/*access*',
        '/var/log/nginx/*access*',
        '/usr/local/lsws/logs/*access*',
    ]

    found = set()
    for pattern in patterns:
        for path in glob_module.glob(pattern):
            if os.path.isfile(path) and os.path.getsize(path) > 0:
                found.add(path)

    return sorted(found)


# ---------------------------------------------------------------------------
# Main Guardian Daemon
# ---------------------------------------------------------------------------
class Guardian:
    def __init__(self, config_path=None):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.config = load_config(config_path)
        self.logger = setup_logging(self.config, self.base_dir)
        self.running = False
        self.tailers = []

        self.version = get_version(self.base_dir)
        self.logger.info("=" * 60)
        self.logger.info(f"WP-Guardian v{self.version} starting up")
        self.logger.info("=" * 60)

        # Initialize database
        db_path = self.config.get('database', 'path',
                                  fallback=os.path.join(self.base_dir, 'state', 'guardian.db'))
        self.db = GuardianDB(db_path, base_dir=self.base_dir)

        # Initialize firewall backend
        backend_type = self.config.get('firewall', 'backend', fallback='csf')
        try:
            self.firewall = create_backend(self.config)
        except Exception as e:
            self.logger.error(f"Firewall backend '{backend_type}' failed to initialize: {e}")
            self.logger.error("Starting in dry-run mode (no blocking)")
            self.firewall = None
            self.config.set('general', 'dry_run', 'true')

        # Initialize Telegram
        self.telegram = TelegramAlerter(self.config)

        # Initialize whitelist
        self._whitelist_file = self.config.get('whitelist', 'file',
                                               fallback=os.path.join(self.base_dir, 'whitelist.conf'))
        file_ips = load_whitelist_file(self._whitelist_file)
        self.whitelist = WhitelistManager(self.db, self.firewall, file_ips)
        self._whitelist_mtime = 0
        try:
            self._whitelist_mtime = os.path.getmtime(self._whitelist_file)
        except OSError:
            pass

        # Initialize blocker
        self.blocker = Blocker(self.config, self.db, self.whitelist, self.firewall, self.telegram)

        # Initialize Telegram command handler
        self.telegram_cmd = TelegramCommander(self.config, self.db, self.blocker, self.whitelist)

        # Load tripwires
        tripwire_file = os.path.join(self.base_dir, 'tripwires.txt')
        self.tripwires = load_tripwire_file(tripwire_file)
        # Also load from database
        db_tripwires = self.db.load_tripwires()
        self.tripwires.update(db_tripwires.keys())
        self.logger.info(f"Loaded {len(self.tripwires)} tripwire paths")

        # Ensure firewall rules exist (backend-specific setup)
        if self.firewall:
            self.firewall.ensure_firewall_rules()

        # Log configuration summary
        dry_run = self.config.getboolean('general', 'dry_run', fallback=False)
        self.logger.info(f"Dry-run mode: {dry_run}")
        self.logger.info(f"Firewall backend: {backend_type}")
        self.logger.info(f"Telegram: {'enabled' if self.telegram.enabled else 'disabled'}")
        self.logger.info(f"Telegram commands: {'enabled' if self.telegram_cmd.enabled else 'disabled'}")
        self.logger.info(f"Whitelist entries: {len(file_ips)}")
        self.logger.info(f"Tripwires: {len(self.tripwires)}")

    def _load_web_logs(self):
        """Load web access log paths from logfiles.txt."""
        logfiles_list = self.config.get('general', 'logfiles_list',
                                        fallback=os.path.join(self.base_dir, 'logfiles.txt'))
        logs = []

        if not os.path.exists(logfiles_list):
            self.logger.error(f"Logfiles list not found: {logfiles_list}")
            return logs

        with open(logfiles_list, 'r') as f:
            for line in f:
                path = line.strip()
                if path and not path.startswith('#') and os.path.exists(path):
                    logs.append(path)

        self.logger.info(f"Found {len(logs)} web access logs")
        return logs

    def start(self):
        """Start the guardian daemon."""
        self.running = True

        # Signal handlers
        signal.signal(signal.SIGTERM, self._shutdown)
        signal.signal(signal.SIGINT, self._shutdown)

        # Start web log tailing
        web_logs = self._load_web_logs()
        if web_logs:
            web_detector = WebDetector(self.config, self.blocker, self.db, self.tripwires, self.whitelist)
            web_tailer = LogTailer(web_logs, web_detector, name='web', track_site=True)
            web_tailer.start()
            self.tailers.append(web_tailer)

        # Start mail log tailing
        mail_log = self.config.get('log_paths', 'mail_log', fallback='/var/log/maillog')
        if os.path.exists(mail_log):
            mail_detector = MailDetector(self.config, self.blocker, self.db, self.whitelist)
            mail_tailer = LogTailer([mail_log], mail_detector, name='mail')
            mail_tailer.start()
            self.tailers.append(mail_tailer)
        else:
            self.logger.warning(f"Mail log not found: {mail_log}")

        # Start SSH log tailing
        secure_log = self.config.get('log_paths', 'secure_log', fallback='/var/log/secure')
        if os.path.exists(secure_log):
            ssh_detector = SSHDetector(self.config, self.blocker, self.db, self.whitelist)
            ssh_tailer = LogTailer([secure_log], ssh_detector, name='ssh')
            ssh_tailer.start()
            self.tailers.append(ssh_tailer)
        else:
            self.logger.warning(f"Secure log not found: {secure_log}")

        self.logger.info(f"Guardian running with {len(self.tailers)} log tailer(s)")

        # Start Telegram command handler (polling thread)
        self.telegram_cmd.start()

        # Periodic task settings
        last_cleanup = 0
        last_summary = 0
        last_tracker_cleanup = 0
        last_log_discovery = 0
        last_auto_analyze = 0
        last_whitelist_check = 0
        last_friendly_refresh = 0
        cleanup_interval = 3600        # Hourly
        summary_interval = 86400       # Daily
        tracker_interval = 300         # Every 5 minutes
        whitelist_check_interval = 60  # Every 60 seconds
        friendly_refresh_interval = 300  # Every 5 minutes

        # Auto-analysis settings
        auto_analyze_enabled = self.config.getboolean('log_analysis', 'auto_analyze', fallback=False)
        auto_analyze_interval = parse_duration(
            self.config.get('log_analysis', 'interval', fallback='24h')
        )
        auto_discover_enabled = self.config.getboolean('log_analysis', 'auto_discover', fallback=False)
        discover_interval = parse_duration(
            self.config.get('log_analysis', 'discover_interval', fallback='24h')
        )

        try:
            while self.running:
                now = time.time()

                # Cleanup expired data
                if now - last_cleanup > cleanup_interval:
                    auth_retention = self.config.getint('database', 'auth_retention_days', fallback=90)
                    history_retention = self.config.getint('database', 'ip_history_retention_days', fallback=180)
                    self.db.cleanup_expired(auth_retention, history_retention)

                    iso_retention = self.config.getint('thresholds', 'login_isolation_retention_hours', fallback=48)
                    removed = self.db.login_isolation_cleanup(iso_retention * 3600)
                    if removed > 0:
                        self.logger.debug(f"Cleaned {removed} expired login isolation entries")

                    last_cleanup = now

                # Daily summary
                if now - last_summary > summary_interval:
                    stats = self.db.get_stats()
                    self.telegram.alert_daily_summary(stats)
                    self.logger.info(f"Daily stats: {dict(stats)}")
                    last_summary = now

                # Clean up in-memory trackers
                if now - last_tracker_cleanup > tracker_interval:
                    last_tracker_cleanup = now

                # Whitelist file auto-reload
                if now - last_whitelist_check > whitelist_check_interval:
                    try:
                        current_mtime = os.path.getmtime(self._whitelist_file)
                        if current_mtime != self._whitelist_mtime:
                            self.whitelist.reload_file(self._whitelist_file)
                            self._whitelist_mtime = current_mtime
                            self.logger.info(f"Whitelist file changed, reloaded from {self._whitelist_file}")
                    except OSError:
                        pass
                    last_whitelist_check = now

                # Refresh firewall friendly list
                if now - last_friendly_refresh > friendly_refresh_interval:
                    if self.firewall and self.firewall.supports_friendly_list:
                        try:
                            self.firewall.refresh_friendly_list()
                        except Exception as e:
                            self.logger.error(f"Friendly list refresh failed: {e}")
                    last_friendly_refresh = now

                # Auto log discovery
                if auto_discover_enabled and now - last_log_discovery > discover_interval:
                    self._auto_discover_logs()
                    last_log_discovery = now

                # Auto analysis
                if auto_analyze_enabled and now - last_auto_analyze > auto_analyze_interval:
                    self._auto_analyze()
                    last_auto_analyze = now

                time.sleep(1)

        except KeyboardInterrupt:
            pass

        self._shutdown()

    def _auto_discover_logs(self):
        """Periodic log discovery — find new log files and update logfiles.txt."""
        try:
            logs = discover_access_logs()
            logfiles_path = self.config.get('general', 'logfiles_list',
                                            fallback=os.path.join(self.base_dir, 'logfiles.txt'))

            # Read existing
            existing = set()
            if os.path.exists(logfiles_path):
                with open(logfiles_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            existing.add(line)

            new_logs = set(logs) - existing
            if new_logs:
                with open(logfiles_path, 'a') as f:
                    for path in sorted(new_logs):
                        f.write(path + '\n')
                self.logger.info(f"Auto-discovery: added {len(new_logs)} new log files")
                self.telegram.send(
                    f"📋 <b>WP-Guardian — Log Discovery</b>\n"
                    f"Found {len(new_logs)} new access log file(s).\n"
                    f"Restart the daemon to start monitoring them.",
                    priority='INFO'
                )
        except Exception as e:
            self.logger.error(f"Auto log discovery failed: {e}")

    def _auto_analyze(self):
        """Periodic tripwire analysis — run log analyzer and incrementally import."""
        try:
            analyzer_path = os.path.join(self.base_dir, 'tools', 'log-analyzer.sh')
            if not os.path.exists(analyzer_path):
                self.logger.warning("Log analyzer not found, skipping auto-analysis")
                return

            # Run analyzer to temp file
            tmp_output = os.path.join(self.base_dir, 'state', 'auto-tripwires.tmp')
            result = subprocess.run(
                ['bash', analyzer_path, '-o', tmp_output],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=300
            )

            if result.returncode != 0:
                self.logger.warning(f"Log analyzer returned non-zero: {result.stderr}")

            if os.path.exists(tmp_output):
                added = self.db.import_tripwires_incremental(tmp_output)
                os.remove(tmp_output)

                if added > 0:
                    # Reload tripwires into memory
                    db_tripwires = self.db.load_tripwires()
                    tripwire_file = os.path.join(self.base_dir, 'tripwires.txt')
                    self.tripwires = load_tripwire_file(tripwire_file)
                    self.tripwires.update(db_tripwires.keys())

                    self.logger.info(f"Auto-analysis: added {added} new tripwires")
                    self.telegram.send(
                        f"🔍 <b>WP-Guardian — Auto-Analysis</b>\n"
                        f"Added {added} new tripwire path(s).\n"
                        f"Total active: {len(self.tripwires)}",
                        priority='INFO'
                    )
                else:
                    self.logger.debug("Auto-analysis: no new tripwires found")
        except subprocess.TimeoutExpired:
            self.logger.error("Auto-analysis timed out (300s)")
        except Exception as e:
            self.logger.error(f"Auto-analysis failed: {e}")

    def _shutdown(self, signum=None, frame=None):
        """Graceful shutdown."""
        if not self.running:
            return

        self.logger.info("WP-Guardian shutting down...")
        self.running = False

        # Stop Telegram command polling
        self.telegram_cmd.stop()

        for tailer in self.tailers:
            tailer.stop()

        self.db.close()
        self.logger.info("Shutdown complete")

    def status(self):
        """Print current status."""
        stats = self.db.get_stats()
        backend_type = self.config.get('firewall', 'backend', fallback='csf')
        fw_counts = self.firewall.get_block_counts() if self.firewall else {}

        schema_version = self.db.get_schema_version()

        print("\n" + "=" * 50)
        print(f"  WP-Guardian v{self.version}")
        print("=" * 50)
        print(f"  Schema version:     {schema_version}")
        print(f"  Firewall backend:   {backend_type}")
        print(f"  IPs tracked:        {stats['total_ips_tracked']}")
        print(f"  Blocks today:       {stats['total_blocks_today']}")
        print(f"  Active Tier 1:      {stats['active_tier1']}")
        print(f"  Active Tier 2:      {stats['active_tier2']}")
        print(f"  Active Tier 3:      {stats['active_tier3']}")
        print(f"  Whitelist entries:  {stats['whitelist_count']}")
        print(f"  Tripwires:          {stats['tripwire_count']}")
        print(f"  Auth sessions today: {stats['auth_sessions_today']}")

        if fw_counts:
            print(f"\n  Firewall block lists:")
            for name, count in fw_counts.items():
                print(f"    {name}: {count}")

        print("=" * 50 + "\n")


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description='WP-Guardian Security Daemon')
    parser.add_argument('--config', '-c', default=None, help='Path to config file')
    parser.add_argument('--dry-run', action='store_true', help='Log actions but do not block')
    parser.add_argument('--status', action='store_true', help='Show current status and exit')
    parser.add_argument('--import-tripwires', metavar='FILE', help='Import tripwire list from file')
    parser.add_argument('--import-tripwires-incremental', metavar='FILE',
                        help='Import NEW tripwires from file (keep existing)')
    parser.add_argument('--whitelist-add', metavar='IP', help='Add IP to whitelist')
    parser.add_argument('--whitelist-remove', metavar='IP', help='Remove IP from whitelist')
    parser.add_argument('--whitelist-list', action='store_true', help='List all whitelist entries')
    parser.add_argument('--unblock', metavar='IP', help='Unblock an IP from all systems')
    parser.add_argument('--history', metavar='IP', help='Show block history for an IP')
    parser.add_argument('--flush', nargs='?', const='all', metavar='TABLE',
                        help='Flush data. Options: all, tripwires, blocks, auth, isolation (default: all)')
    parser.add_argument('--discover-logs', action='store_true',
                        help='Find access logs on this server')
    parser.add_argument('--discover-logs-save', action='store_true',
                        help='Find access logs and save to logfiles.txt')
    parser.add_argument('--auto-analyze', action='store_true',
                        help='Run log analyzer and incrementally import new tripwires')
    parser.add_argument('--telegram-setup', action='store_true',
                        help='Interactive Telegram bot setup wizard')
    parser.add_argument('--telegram-test', action='store_true',
                        help='Send a test message via Telegram')
    parser.add_argument('--test-backend', action='store_true',
                        help='Test firewall backend connectivity')
    parser.add_argument('--version', action='store_true',
                        help='Show version and exit')
    parser.add_argument('--db-version', action='store_true',
                        help='Show database schema version and exit')
    parser.add_argument('--migrate', action='store_true',
                        help='Run pending database migrations and exit')

    args = parser.parse_args()

    # --- Commands that don't need full Guardian init ---

    base_dir = os.path.dirname(os.path.abspath(__file__))

    # Version display
    if args.version:
        version = get_version(base_dir)
        print(f"WP-Guardian v{version}")
        return

    # Database schema version
    if args.db_version:
        from modules.migrator import get_schema_version as _get_sv
        db_path_arg = args.config  # reuse config to find DB, or use default
        config = load_config(args.config)
        db_path = config.get('database', 'path',
                             fallback=os.path.join(base_dir, 'state', 'guardian.db'))
        if os.path.exists(db_path):
            import sqlite3 as _sqlite3
            conn = _sqlite3.connect(db_path)
            sv = _get_sv(conn)
            conn.close()
            print(f"Database schema version: {sv}")
        else:
            print("Database not found. It will be created on first run.")
        return

    # Run migrations manually
    if args.migrate:
        from modules.migrator import run_migrations, get_schema_version as _get_sv
        config = load_config(args.config)
        db_path = config.get('database', 'path',
                             fallback=os.path.join(base_dir, 'state', 'guardian.db'))
        migrations_dir = os.path.join(base_dir, 'migrations')
        if not os.path.exists(db_path):
            print("Database not found. Run the daemon first to create it.")
            return
        import sqlite3 as _sqlite3
        conn = _sqlite3.connect(db_path)
        before = _get_sv(conn)
        applied = run_migrations(conn, migrations_dir)
        after = _get_sv(conn)
        conn.close()
        if applied > 0:
            print(f"Applied {applied} migration(s). Schema version: {before} -> {after}")
        else:
            print(f"Database is up to date (schema version {after})")
        return

    # Telegram setup wizard
    if args.telegram_setup:
        from tools.telegram_setup import telegram_setup_wizard
        config_path = args.config
        if not config_path:
            # Try to find config in script directory
            base = os.path.dirname(os.path.abspath(__file__))
            for candidate in [os.path.join(base, 'wp-guardian.conf'), '/opt/wp-guardian/wp-guardian.conf']:
                if os.path.exists(candidate):
                    config_path = candidate
                    break
        telegram_setup_wizard(config_path)
        return

    # Log discovery (no daemon needed)
    if args.discover_logs or args.discover_logs_save:
        logs = discover_access_logs()
        if not logs:
            print("No access logs found on this system.")
            print("Searched patterns:")
            print("  /home/*/logs/*.access_log")
            print("  /var/log/httpd/*access*")
            print("  /var/log/apache2/*access*")
            print("  /var/log/nginx/*access*")
            print("  /usr/local/lsws/logs/*access*")
            return

        print(f"\nFound {len(logs)} access log file(s):\n")
        for log in logs:
            size = os.path.getsize(log)
            size_str = f"{size / 1024 / 1024:.1f} MB" if size > 1024*1024 else f"{size / 1024:.1f} KB"
            print(f"  {log}  ({size_str})")

        if args.discover_logs_save:
            base = os.path.dirname(os.path.abspath(__file__))
            logfiles_path = os.path.join(base, 'logfiles.txt')

            # Merge with existing
            existing = set()
            if os.path.exists(logfiles_path):
                with open(logfiles_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            existing.add(line)

            new_logs = set(logs) - existing
            all_logs = sorted(existing | set(logs))

            with open(logfiles_path, 'w') as f:
                f.write("# WP-Guardian — Monitored access log files\n")
                f.write(f"# Auto-discovered on {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total: {len(all_logs)} files\n\n")
                for path in all_logs:
                    f.write(path + '\n')

            print(f"\nSaved to {logfiles_path}")
            if new_logs:
                print(f"  Added {len(new_logs)} new log file(s)")
            print(f"  Total: {len(all_logs)} log files")
        return

    # --- Commands that need Guardian init ---

    guardian = Guardian(args.config)

    if args.dry_run:
        guardian.config.set('general', 'dry_run', 'true')
        guardian.blocker.dry_run = True

    # Command modes
    if args.status:
        guardian.status()
        return

    if args.test_backend:
        backend_type = guardian.config.get('firewall', 'backend', fallback='csf')
        print(f"\nTesting firewall backend: {backend_type}")
        if guardian.firewall:
            result = guardian.firewall.test_connection()
            if result:
                print(f"  ✓ Connection successful")
                counts = guardian.firewall.get_block_counts()
                if counts:
                    print(f"  Block counts: {counts}")
            else:
                print(f"  ✗ Connection FAILED")
        else:
            print(f"  ✗ No firewall backend configured")
        return

    if args.import_tripwires:
        count = guardian.db.import_tripwires(args.import_tripwires)
        print(f"Imported {count} tripwires")
        return

    if args.import_tripwires_incremental:
        added = guardian.db.import_tripwires_incremental(args.import_tripwires_incremental)
        print(f"Incremental import: {added} new tripwires added")
        return

    if args.auto_analyze:
        print("Running log analyzer and incremental import...")
        guardian._auto_analyze()
        print("Done.")
        return

    if args.whitelist_add:
        guardian.whitelist.add(args.whitelist_add, reason='CLI add')
        print(f"Added {args.whitelist_add} to whitelist")
        return

    if args.whitelist_remove:
        guardian.whitelist.remove(args.whitelist_remove)
        print(f"Removed {args.whitelist_remove} from whitelist")
        return

    if args.whitelist_list:
        entries = guardian.whitelist.list_all()
        print(f"\nWhitelist ({len(entries)} entries):")
        for e in entries:
            print(f"  {e['ip']:20s} type={e['type']:12s} source={e.get('source', 'db')}")
        return

    if args.unblock:
        guardian.blocker.unblock(args.unblock)
        print(f"Unblocked {args.unblock}")
        return

    if args.flush:
        target = args.flush.lower()
        conn = guardian.db.conn

        if target in ('all', 'tripwires'):
            count = conn.execute("SELECT COUNT(*) FROM tripwires").fetchone()[0]
            conn.execute("DELETE FROM tripwires")
            print(f"Flushed {count} tripwires")

        if target in ('all', 'blocks'):
            count1 = conn.execute("SELECT COUNT(*) FROM ip_history").fetchone()[0]
            count2 = conn.execute("SELECT COUNT(*) FROM block_log").fetchone()[0]
            conn.execute("DELETE FROM ip_history")
            conn.execute("DELETE FROM block_log")
            print(f"Flushed {count1} IP history entries and {count2} block log entries")

        if target in ('all', 'isolation'):
            count = conn.execute("SELECT COUNT(*) FROM login_isolation").fetchone()[0]
            conn.execute("DELETE FROM login_isolation")
            print(f"Flushed {count} login isolation entries")

        if target in ('all', 'auth'):
            count1 = conn.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0]
            count2 = conn.execute("SELECT COUNT(*) FROM account_baselines").fetchone()[0]
            conn.execute("DELETE FROM auth_sessions")
            conn.execute("DELETE FROM account_baselines")
            print(f"Flushed {count1} auth sessions and {count2} baselines")

        conn.commit()
        print("Done.")
        return

    if args.history:
        blocks = guardian.db.get_block_history(args.history)
        ip_data = guardian.db.get_ip(args.history)
        if ip_data:
            print(f"\nIP: {args.history}")
            print(f"  First seen: {time.ctime(ip_data['first_seen'])}")
            print(f"  Last seen:  {time.ctime(ip_data['last_seen'])}")
            print(f"  Total hits: {ip_data['total_hits']}")
            print(f"  Current tier: {ip_data['current_tier']}")
            print(f"  Block count: {ip_data['block_count']}")
            print(f"  Country: {ip_data['geoip_country']}")
        if blocks:
            print(f"\n  Block history ({len(blocks)} entries):")
            for b in blocks:
                print(f"    {time.ctime(b['timestamp'])} tier={b['tier']} "
                      f"service={b['service']} via={b['blocker']} reason={b['reason']}")
        else:
            print(f"  No block history found for {args.history}")
        return

    # Telegram test
    if args.telegram_test:
        if guardian.telegram.enabled:
            result = guardian.telegram.send(
                "🧪 <b>WP-Guardian Test Message</b>\n"
                "If you see this, Telegram alerts are working!",
                priority='INFO'
            )
            print("Test message sent!" if result else "Failed to send test message.")
        else:
            print("Telegram is not enabled. Run --telegram-setup first.")
        return

    # Default: run the daemon
    guardian.start()


if __name__ == '__main__':
    main()
