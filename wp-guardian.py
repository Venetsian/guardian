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

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.config import load_config, load_whitelist_file, load_tripwire_file, parse_duration
from modules.database import GuardianDB
from modules.whitelist import WhitelistManager
from modules.blocker import Blocker
from modules.geoip import GeoIPResolver
from modules.mail_backend import MailBackend
from modules.compromise import CompromiseAction
from modules.digest import DigestBuffer
from modules.verbosity import VerbosityRouter
from backends.factory import create_backend
from actions.telegram import TelegramAlerter
from actions.telegram_commands import TelegramCommander
from detectors import (
    WebDetector,
    MailDetector,
    SSHDetector,
    RoundcubeDetector,
    DistributedAuthDetector,
    PostFloodDetector,
)


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

        # Apply profile overrides BEFORE any detector reads thresholds
        self._apply_profile()

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

        # GeoIP resolver (optional, fails safe). Initialized before the
        # blocker so block() can enrich ip_history and Telegram alerts with
        # country / city / ASN.
        try:
            self.geoip = GeoIPResolver(self.config)
            if not self.geoip.enabled:
                self.geoip = None
        except Exception as e:
            self.logger.error(f"GeoIP init failed: {e}")
            self.geoip = None

        # Initialize blocker
        self.blocker = Blocker(self.config, self.db, self.whitelist, self.firewall, self.telegram,
                               geoip=self.geoip)

        # Mail backend (optional, recipe-based)
        try:
            self.mail_backend = MailBackend(self.config, guardian_db=self.db)
        except Exception as e:
            self.logger.error(f"MailBackend init failed: {e}")
            self.mail_backend = None

        # Compromise action orchestrator
        self.compromise_action = CompromiseAction(
            self.config, self.db, self.blocker, self.mail_backend, self.telegram
        )

        # Distributed-auth detector — only useful with geoip enabled
        if self.config.getboolean('compromise_detection', 'enabled', fallback=False):
            if not self.geoip:
                self.logger.warning(
                    "compromise_detection.enabled=true but GeoIP is unavailable; "
                    "country/ASN rules will never trigger. Only the IP-count rule will work."
                )
            self.distributed_auth_detector = DistributedAuthDetector(
                self.config, self.db, self.compromise_action
            )
        else:
            self.distributed_auth_detector = None

        # Digest buffer + blocker wiring
        hostname = ''
        try:
            import socket
            hostname = socket.gethostname()
        except Exception:
            pass
        self.digest_buffer = DigestBuffer(self.config, self.db, self.telegram, hostname=hostname)
        self.blocker.set_digest_buffer(self.digest_buffer)

        # Verbosity router — per-rule immediate/digest/silent routing
        self.verbosity_router = VerbosityRouter(self.config, self.base_dir)
        self.blocker.set_router(self.verbosity_router)

        # Load tripwires
        tripwire_file = os.path.join(self.base_dir, 'tripwires.txt')
        self.tripwires = load_tripwire_file(tripwire_file)
        # Also load from database
        db_tripwires = self.db.load_tripwires()
        self.tripwires.update(db_tripwires.keys())
        self.logger.info(f"Loaded {len(self.tripwires)} tripwire paths")

        # CMS site registry (v1.5)
        from modules.cms_registry import CMSRegistry
        logfiles_path = self.config.get(
            'general', 'logfiles_list',
            fallback=os.path.join(self.base_dir, 'logfiles.txt'),
        )
        self.cms_registry = CMSRegistry(self.config, self.db, logfiles_path)
        if self.cms_registry.enabled:
            self.cms_registry.refresh()
            self.logger.info(f"CMS registry: {len(self.cms_registry.all())} sites")
        else:
            self.logger.info("CMS registry disabled")

        # POST-flood detector (v1.5) — opt-in via config
        self.post_flood_detector = PostFloodDetector(
            self.config, self.blocker, self.db, self.whitelist,
            cms_registry=self.cms_registry,
        )
        if self.post_flood_detector.enabled:
            self.logger.info(
                f"POST-flood detector active (threshold={self.post_flood_detector.threshold}/"
                f"{self.post_flood_detector.window}s, behavioral_required="
                f"{self.post_flood_detector.behavioral_required})"
            )
        else:
            self.logger.info("POST-flood detector disabled")

        # Posture-audit + host-health (v1.6+, task #122)
        try:
            from modules.host_profile import HostProfileDetector
            from modules.posture import PostureAuditor
            self.host_profile_detector = HostProfileDetector(
                self.config, self.db, hostname=hostname,
            )
            self.posture_auditor = PostureAuditor(
                self.config, self.db, self.host_profile_detector,
                telegram=self.telegram, hostname=hostname, base_dir=self.base_dir,
            )
        except Exception as e:
            self.logger.error(f"Posture auditor init failed: {e}")
            self.host_profile_detector = None
            self.posture_auditor = None

        # Initialize Telegram command handler (after tripwires so we can pass the set)
        self.telegram_cmd = TelegramCommander(
            self.config, self.db, self.blocker, self.whitelist,
            self.tripwires, self.base_dir,
            mail_backend=self.mail_backend,
            compromise_action=self.compromise_action,
            verbosity_router=self.verbosity_router,
        )

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

    def _apply_profile(self):
        """Apply [profile] mode=migration threshold overrides (v1.4+).

        Migration mode loosens brute-force thresholds for the post-cutover
        period when legitimate users are fat-fingering creds. Compromise
        detection country/ASN rules are NOT loosened — those signals indicate
        compromise regardless of mode.
        """
        profile = 'steady'
        try:
            profile = self.config.get('profile', 'mode', fallback='steady').strip().lower()
        except Exception:
            pass

        if profile not in ('steady', 'migration'):
            self.logger.warning("Unknown profile mode '{p}', defaulting to steady".format(p=profile))
            profile = 'steady'

        self.logger.info("Profile: {p}".format(p=profile))

        if profile != 'migration':
            return

        overrides = [
            ('thresholds', 'smtp_auth_fail_threshold', '15'),
            ('thresholds', 'imap_auth_fail_threshold', '15'),
            ('thresholds', 'roundcube_fail_threshold', '15'),
            ('thresholds', 'ssh_fail_threshold', '8'),
            ('thresholds', 'time_window', '600'),
            ('thresholds', 'wp_login_threshold', '25'),
            ('compromise_detection', 'threshold_distinct_ips', '30'),
        ]
        for section, key, value in overrides:
            if not self.config.has_section(section):
                self.config.add_section(section)
            self.config.set(section, key, value)
        self.logger.info("Migration profile overrides applied")

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
            web_detector = WebDetector(
                self.config, self.blocker, self.db, self.tripwires, self.whitelist,
                post_flood_detector=self.post_flood_detector,
                cms_registry=self.cms_registry,
            )
            web_tailer = LogTailer(web_logs, web_detector, name='web', track_site=True)
            web_tailer.start()
            self.tailers.append(web_tailer)

        # Start mail log tailing
        mail_log = self.config.get('log_paths', 'mail_log', fallback='/var/log/maillog')
        if os.path.exists(mail_log):
            mail_detector = MailDetector(
                self.config, self.blocker, self.db, self.whitelist,
                geoip=self.geoip,
                distributed_auth_detector=self.distributed_auth_detector,
            )
            mail_tailer = LogTailer([mail_log], mail_detector, name='mail')
            mail_tailer.start()
            self.tailers.append(mail_tailer)
        else:
            self.logger.warning(f"Mail log not found: {mail_log}")

        # Start SSH log tailing
        secure_log = self.config.get('log_paths', 'secure_log', fallback='/var/log/secure')
        if os.path.exists(secure_log):
            ssh_detector = SSHDetector(
                self.config, self.blocker, self.db, self.whitelist,
                geoip=self.geoip,
                distributed_auth_detector=self.distributed_auth_detector,
            )
            ssh_tailer = LogTailer([secure_log], ssh_detector, name='ssh')
            ssh_tailer.start()
            self.tailers.append(ssh_tailer)
        else:
            self.logger.warning(f"Secure log not found: {secure_log}")

        # Start Roundcube error log tailing (v1.4+)
        roundcube_log = self.config.get(
            'log_paths', 'roundcube_log',
            fallback='/var/www/roundcube/logs/errors.log'
        )
        if os.path.exists(roundcube_log):
            rc_detector = RoundcubeDetector(self.config, self.blocker, self.db, self.whitelist)
            rc_tailer = LogTailer([roundcube_log], rc_detector, name='roundcube')
            rc_tailer.start()
            self.tailers.append(rc_tailer)
            self.logger.info("Roundcube detector active")
        else:
            self.logger.info(f"Roundcube log not found: {roundcube_log} (skipping)")

        self.logger.info(f"Guardian running with {len(self.tailers)} log tailer(s)")

        # Start Telegram command handler (polling thread)
        self.telegram_cmd.start()

        # Periodic task settings
        last_cleanup = 0
        last_summary = 0
        last_tracker_cleanup = 0
        last_log_discovery = 0
        last_whitelist_check = 0
        last_friendly_refresh = 0
        last_cms_refresh = time.time()  # already refreshed at startup
        cleanup_interval = 3600        # Hourly
        summary_interval = 86400       # Daily
        tracker_interval = 300         # Every 5 minutes
        whitelist_check_interval = 60  # Every 60 seconds
        friendly_refresh_interval = 300  # Every 5 minutes

        # Auto-discovery settings
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

                # CMS registry refresh (v1.5)
                if self.cms_registry.enabled and (now - last_cms_refresh) > self.cms_registry.refresh_interval:
                    self.cms_registry.refresh()
                    last_cms_refresh = now

                # Alert digest flush (v1.4+)
                try:
                    self.digest_buffer.flush_if_due()
                except Exception as e:
                    self.logger.error(f"Digest flush error: {e}")

                # Posture-audit + host-health daily run (v1.6+)
                if self.posture_auditor is not None:
                    try:
                        self.posture_auditor.run_if_due()
                    except Exception as e:
                        self.logger.error(f"Posture run error: {e}")

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

    def _analyze_tripwires(self):
        """Run log analyzer and show NEW tripwire candidates (does not import)."""
        analyzer_path = os.path.join(self.base_dir, 'tools', 'log-analyzer.sh')
        if not os.path.exists(analyzer_path):
            print(f"Log analyzer not found: {analyzer_path}")
            return

        # Run analyzer to temp file
        tmp_output = os.path.join(self.base_dir, 'state', 'auto-tripwires.tmp')
        print("Running log analyzer...")
        result = subprocess.run(
            ['bash', analyzer_path, '-o', tmp_output],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=300
        )

        if result.returncode != 0:
            print(f"Warning: log analyzer returned non-zero exit code")
            if result.stderr:
                print(f"  stderr: {result.stderr.strip()}")

        if not os.path.exists(tmp_output):
            print("No output from log analyzer.")
            return

        # Load candidates from analyzer output
        candidates = set()
        with open(tmp_output, 'r') as f:
            for line in f:
                path = line.strip().lower()
                if path and not path.startswith('#'):
                    candidates.add(path)

        os.remove(tmp_output)

        # Filter against existing tripwires (DB + file)
        existing = self.db.get_all_tripwire_paths()
        tripwire_file = os.path.join(self.base_dir, 'tripwires.txt')
        file_paths = load_tripwire_file(tripwire_file)
        existing.update(file_paths)

        new_paths = sorted(candidates - existing)

        print(f"Analyzer found {len(candidates)} total candidates.")
        print(f"Existing tripwires: {len(existing)}")
        print(f"NEW candidates: {len(new_paths)}")

        if not new_paths:
            print("\nNo new tripwires to review.")
            return

        # Display new candidates
        print(f"\n{'PATH':<70s}")
        print("-" * 70)
        for path in new_paths:
            print(f"  {path}")

        # Save to file for review and import
        output_file = os.path.join(self.base_dir, 'state', 'new-tripwires.txt')
        with open(output_file, 'w') as f:
            for path in new_paths:
                f.write(path + '\n')

        print(f"\nSaved to: {output_file}")
        print(f"Review the file, remove any false positives, then import:")
        print(f"  python3 {os.path.join(self.base_dir, 'wp-guardian.py')} --import-tripwires-incremental {output_file}")

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

        if self.geoip:
            try:
                self.geoip.close()
            except Exception:
                pass

        # Final digest flush before we exit
        try:
            if self.digest_buffer:
                self.digest_buffer.flush_if_due(force=True)
        except Exception:
            pass

        self.db.close()
        self.logger.info("Shutdown complete")

    # ------------------------------------------------------------------
    # v1.4 — CLI helpers (auth-map, auth-suspects, hunt-compromises)
    # ------------------------------------------------------------------
    def print_auth_map(self, username, days=30):
        """--auth-map <username> output."""
        rows = self.db.auth_map_for_user(username, days=days)
        summary = self.db.auth_map_summary(username, days=days)

        print("")
        print(f"Auth map for {username} (last {days} days)")
        print("")
        if not rows:
            print("  No successful authentications recorded.")
            return

        print("{ip:<18s} {country:<8s} {city:<15s} {asn:<7s} {org:<20s} {first:<20s} {last:<20s} {count:>6s}  Services".format(
            ip='IP', country='Country', city='City', asn='ASN',
            org='ASN Org', first='First Seen', last='Last Seen', count='Count'
        ))
        print("-" * 130)
        for row in rows[:200]:
            first_ts = time.strftime('%Y-%m-%d %H:%M', time.localtime(row['first_seen']))
            last_ts = time.strftime('%Y-%m-%d %H:%M', time.localtime(row['last_seen']))
            asn_str = str(row['asn']) if row['asn'] else '-'
            print("{ip:<18s} {country:<8s} {city:<15.15s} {asn:<7s} {org:<20.20s} {first:<20s} {last:<20s} {count:>6d}  {svc}".format(
                ip=row['ip'],
                country=row['country'] or '-',
                city=row['city'] or '-',
                asn=asn_str,
                org=row['asn_org'] or '-',
                first=first_ts,
                last=last_ts,
                count=row['count'],
                svc=','.join(row['services']),
            ))

        print("")
        print("Summary:")
        print(f"  Total auths:        {summary['total_auths']}")
        print(f"  Distinct IPs:       {summary['distinct_ips']}")
        print(f"  Distinct countries: {summary['distinct_countries']}")
        print(f"  Distinct ASNs:      {summary['distinct_asns']}")

        if self.db.has_open_compromise(username):
            print("")
            print(f"⚠  This account has an OPEN compromise event.")
            print(f"   Use --list-compromise-events to view details.")

    def print_auth_suspects(self, days=7, min_ips=10):
        """--auth-suspects output."""
        rows = self.db.suspect_accounts(days=days, min_distinct_ips=min_ips)
        print("")
        print(f"Accounts with distributed-source authentication (last {days} days, min {min_ips} IPs)")
        print("")
        if not rows:
            print("  No accounts matched.")
            return

        print("{user:<40s} {ips:>5s}  {countries:>9s}  {asns:>5s}  {total:>6s}  {first:<20s}  {last:<20s}  Status".format(
            user='Username', ips='IPs', countries='Countries', asns='ASNs',
            total='Auths', first='First', last='Last'
        ))
        print("-" * 130)
        for row in rows:
            first_ts = time.strftime('%Y-%m-%d %H:%M', time.localtime(row['first_seen']))
            last_ts = time.strftime('%Y-%m-%d %H:%M', time.localtime(row['last_seen']))

            if self.db.has_open_compromise(row['username']):
                status = 'COMPROMISED'
            elif (row['distinct_countries'] >= 3
                  or row['distinct_asns'] >= 5
                  or row['distinct_ips'] >= 20):
                status = 'SUSPICIOUS'
            else:
                status = 'review'

            print("{user:<40.40s} {ips:>5d}  {c:>9d}  {a:>5d}  {t:>6d}  {first:<20s}  {last:<20s}  {status}".format(
                user=row['username'],
                ips=row['distinct_ips'],
                c=row['distinct_countries'],
                a=row['distinct_asns'],
                t=row['total_auths'],
                first=first_ts, last=last_ts,
                status=status,
            ))

    def hunt_compromises(self, days=7, auto_act=False):
        """--hunt-compromises — replay the live detector's sliding-window logic
        against historical auth data.

        The live DistributedAuthDetector evaluates each account against a
        sliding window of width [compromise_detection] window_seconds (default
        3600 = 1 hour). The hunt has to do the same or it will surface
        mobile-user false positives — a legitimate T-Mobile CGNAT user might
        use 30+ IPs spread over a week, but never more than a handful within
        any single hour.

        Algorithm:
          1) Cheap prefilter: ignore accounts whose 7-day totals can't
             possibly hit any threshold (no rule can trip if the account's
             entire history is smaller than the smallest threshold).
          2) For each surviving candidate, slide a window anchored on each
             of its own auth timestamps and compute the peak counts.
             We don't need to anchor on arbitrary moments — a window's peak
             can only shift at an auth event boundary.
          3) Report accounts whose PEAK window counts cross any threshold.
        """
        if not self.config.getboolean('compromise_detection', 'enabled', fallback=False):
            print("")
            print("Note: [compromise_detection] enabled=false. Using configured thresholds for hunt anyway.")

        threshold_c = self.config.getint('compromise_detection', 'threshold_distinct_countries', fallback=3)
        threshold_a = self.config.getint('compromise_detection', 'threshold_distinct_asns', fallback=5)
        threshold_i = self.config.getint('compromise_detection', 'threshold_distinct_ips', fallback=20)
        window = self.config.getint('compromise_detection', 'window_seconds', fallback=3600)

        cutoff = int(time.time()) - days * 86400
        cur = self.db.conn.execute(
            "SELECT COUNT(*) AS n, COUNT(DISTINCT username) AS u "
            "FROM auth_sessions WHERE timestamp >= ?", (cutoff,)
        ).fetchone()
        total_auths = cur['n']
        total_users = cur['u']

        print("")
        print(f"Scanning {total_auths} successful auths across {total_users} distinct usernames")
        print(f"(last {days} days, sliding-window={window}s, "
              f"thresholds: {threshold_c} countries / {threshold_a} ASNs / {threshold_i} IPs)")
        print("")

        # ---- Step 1: cheap prefilter over the whole range ------------------
        # If the account's 7-day total count can't cross any threshold, no
        # 1-hour window ever will (a window's count is bounded by the total).
        # This lets us skip the expensive per-account sliding walk for the
        # vast majority of users.
        min_threshold = min(threshold_c, threshold_a, threshold_i)
        prefilter_cursor = self.db.conn.execute(
            "SELECT username, "
            "       COUNT(DISTINCT ip) AS ips, "
            "       COUNT(DISTINCT CASE WHEN geoip_country != '' THEN geoip_country END) AS countries, "
            "       COUNT(DISTINCT CASE WHEN geoip_asn > 0 THEN geoip_asn END) AS asns "
            "FROM auth_sessions WHERE timestamp >= ? AND username != '' "
            "GROUP BY username "
            "HAVING ips >= ? OR countries >= ? OR asns >= ? "
            "ORDER BY ips DESC",
            (cutoff, threshold_i, threshold_c, threshold_a)
        )
        prefilter_hits = prefilter_cursor.fetchall()

        if not prefilter_hits:
            print("No accounts triggered compromise rules over the last {d} days.".format(d=days))
            return

        print(f"Prefilter: {len(prefilter_hits)} account(s) with 7-day totals that could cross a threshold.")
        print(f"Running sliding-{window}s-window replay on each...")
        print("")

        # ---- Step 2: sliding-window replay per candidate -------------------
        findings = []
        false_positives = []  # accounts that survived prefilter but peak < threshold
        for row in prefilter_hits:
            user = row['username']
            peak = self._peak_window_counts(user, cutoff, window)

            triggered_rule = None
            # Same precedence as the live detector: countries first, then ASN, then IP
            if peak['countries'] >= threshold_c:
                triggered_rule = 'countries'
            elif peak['asns'] >= threshold_a:
                triggered_rule = 'asns'
            elif peak['ips'] >= threshold_i:
                triggered_rule = 'ips'

            if triggered_rule:
                findings.append({
                    'username': user,
                    'rule': triggered_rule,
                    'counts': peak,
                    'totals': {
                        'ips': row['ips'],
                        'countries': row['countries'],
                        'asns': row['asns'],
                    },
                    'anchor_ts': peak['anchor_ts'],
                })
            else:
                false_positives.append({
                    'username': user,
                    'peak': peak,
                    'totals': {
                        'ips': row['ips'],
                        'countries': row['countries'],
                        'asns': row['asns'],
                    },
                })

        if not findings:
            print(f"No accounts triggered compromise rules within any {window}s sliding window.")
            if false_positives:
                print("")
                print(f"{len(false_positives)} account(s) had high 7-day totals but no single-window hit:")
                print("(these are the accounts that would have been false positives under a total-range hunt)")
                print("")
                print("{u:<40s}  {pi:>8s}  {pc:>8s}  {pa:>8s}  {ti:>8s}  {tc:>8s}  {ta:>8s}".format(
                    u='Username', pi='peak_ips', pc='peak_cc', pa='peak_asn',
                    ti='tot_ips', tc='tot_cc', ta='tot_asn'
                ))
                print("-" * 100)
                for fp in false_positives[:20]:
                    p = fp['peak']
                    t = fp['totals']
                    print("{u:<40.40s}  {pi:>8d}  {pc:>8d}  {pa:>8d}  {ti:>8d}  {tc:>8d}  {ta:>8d}".format(
                        u=fp['username'],
                        pi=p['ips'], pc=p['countries'], pa=p['asns'],
                        ti=t['ips'], tc=t['countries'], ta=t['asns'],
                    ))
            return

        print(f"Found {len(findings)} account(s) that triggered compromise rules within the sliding window:")
        print("")

        for idx, finding in enumerate(findings, start=1):
            user = finding['username']
            rule = finding['rule']
            peak = finding['counts']
            totals = finding['totals']
            anchor = time.strftime('%Y-%m-%d %H:%M', time.localtime(finding['anchor_ts']))

            print(f"[{idx}] {user}")
            print(f"    Peak {window}s window starting {anchor}:")
            print(f"      Distinct IPs       : {peak['ips']:>4d}   (7d total: {totals['ips']})")
            print(f"      Distinct countries : {peak['countries']:>4d}   (7d total: {totals['countries']})")
            print(f"      Distinct ASNs      : {peak['asns']:>4d}   (7d total: {totals['asns']})")
            print(f"    Triggered rule: {rule}")
            if self.db.has_open_compromise(user):
                print(f"    Status: already has OPEN compromise event")
            print("")

        if false_positives:
            print(f"Prefilter caught {len(false_positives)} additional account(s) with high 7-day totals")
            print(f"but no single-window threshold hit (typically legitimate mobile/CGNAT users).")
            print(f"These are NOT being flagged — the sliding window cleared them.")
            print("")

        if auto_act:
            print("--auto-act flag set: applying configured compromise_action...")
            print("")
            for finding in findings:
                if self.db.has_open_compromise(finding['username']):
                    print(f"  skipping {finding['username']} (already has open event)")
                    continue
                self.compromise_action.handle(
                    username=finding['username'],
                    service='smtp',
                    trigger_rule=finding['rule'],
                    counts=finding['counts'],
                    window_seconds=window,
                    actor='cli:--hunt-compromises --auto-act',
                )
        else:
            print("Run with --auto-act to apply the configured compromise_action.")
            print("Run with --auth-map <user> to see the full per-IP breakdown.")

    def _peak_window_counts(self, username, cutoff_ts, window_seconds):
        """Slide a window of width `window_seconds` over a user's auth history
        (from `cutoff_ts` onward) and return the peak counts across all window
        positions.

        We only need to anchor windows at actual auth event timestamps — a
        window's distinct-count can only change when an event enters or leaves
        the window, and the local maxima occur at event arrivals.

        Returns a dict compatible with db.distinct_auth_counts() output plus
        an `anchor_ts` key marking where the peak was found.
        """
        # Pull the full sorted history for this user within the hunt range.
        rows = self.db.conn.execute(
            "SELECT timestamp, ip, geoip_country, geoip_asn "
            "FROM auth_sessions "
            "WHERE username = ? AND timestamp >= ? "
            "ORDER BY timestamp ASC",
            (username, int(cutoff_ts))
        ).fetchall()

        if not rows:
            return {'countries': 0, 'asns': 0, 'ips': 0, 'anchor_ts': 0}

        # Two-pointer sliding window, walking `right` forward and bumping
        # `left` when window span exceeds window_seconds.
        left = 0
        ips = {}
        countries = {}
        asns = {}
        peak = {'countries': 0, 'asns': 0, 'ips': 0, 'anchor_ts': rows[0]['timestamp']}

        def add(d, key):
            if not key:
                return
            d[key] = d.get(key, 0) + 1

        def remove(d, key):
            if not key:
                return
            cnt = d.get(key, 0)
            if cnt <= 1:
                d.pop(key, None)
            else:
                d[key] = cnt - 1

        for right in range(len(rows)):
            r = rows[right]
            add(ips, r['ip'])
            add(countries, r['geoip_country'])
            add(asns, r['geoip_asn'] if r['geoip_asn'] and r['geoip_asn'] > 0 else None)

            # Shrink window from the left while span > window_seconds
            while rows[right]['timestamp'] - rows[left]['timestamp'] > window_seconds:
                lr = rows[left]
                remove(ips, lr['ip'])
                remove(countries, lr['geoip_country'])
                remove(asns, lr['geoip_asn'] if lr['geoip_asn'] and lr['geoip_asn'] > 0 else None)
                left += 1

            # Record peaks
            ci = len(ips)
            cc = len(countries)
            ca = len(asns)
            # Primary ranking: countries > asns > ips (match live detector's
            # rule precedence). Use a triple-max, anchoring the timestamp on
            # whichever metric is currently at its global peak.
            if ci > peak['ips'] or cc > peak['countries'] or ca > peak['asns']:
                peak['ips'] = max(peak['ips'], ci)
                peak['countries'] = max(peak['countries'], cc)
                peak['asns'] = max(peak['asns'], ca)
                peak['anchor_ts'] = rows[left]['timestamp']

        return peak

    def list_compromise_events_cli(self, open_only=False, limit=50):
        rows = self.db.list_compromise_events(open_only=open_only, limit=limit)
        if not rows:
            print("No compromise events recorded.")
            return
        header = "Open compromise events:" if open_only else "Compromise events:"
        print("")
        print(header)
        print("")
        print("{id:<5s}  {when:<20s}  {user:<40s}  {rule:<10s}  {action:<18s}  {status}".format(
            id='ID', when='Detected', user='Username', rule='Trigger',
            action='Action', status='Status'
        ))
        print("-" * 120)
        for r in rows:
            when = time.strftime('%Y-%m-%d %H:%M', time.localtime(r['detected_at']))
            status = 'resolved' if r['resolved_at'] else 'OPEN'
            print("{id:<5d}  {when:<20s}  {user:<40.40s}  {rule:<10s}  {action:<18s}  {status}".format(
                id=r['id'], when=when, user=r['username'],
                rule=r['trigger_rule'], action=r['action_taken'], status=status
            ))

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
    parser.add_argument('--analyze-tripwires', action='store_true',
                        help='Run log analyzer and show NEW tripwire candidates (does not import)')
    parser.add_argument('--remove-tripwire', metavar='PATH',
                        help='Remove a tripwire path from DB and file')
    parser.add_argument('--list-tripwires', nargs='?', const='', metavar='PATTERN',
                        help='List tripwires (optionally filter by pattern)')
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

    # v1.4 — Per-account auth / compromise detection
    parser.add_argument('--auth-map', metavar='USERNAME',
                        help='Show per-IP auth map for a username')
    parser.add_argument('--auth-suspects', action='store_true',
                        help='List accounts with distributed-source auth patterns')
    parser.add_argument('--hunt-compromises', action='store_true',
                        help='Scan historical auth data for compromised accounts')
    parser.add_argument('--auto-act', action='store_true',
                        help='With --hunt-compromises: apply configured compromise action')
    parser.add_argument('--days', type=int, default=None,
                        help='Look-back window in days (auth-map/suspects/hunt)')
    parser.add_argument('--min-ips', type=int, default=10,
                        help='Minimum distinct IPs threshold for --auth-suspects (default 10)')
    parser.add_argument('--disable-mailbox', metavar='USERNAME',
                        help='Disable a mailbox via mail_backend')
    parser.add_argument('--enable-mailbox', metavar='USERNAME',
                        help='Re-enable a mailbox via mail_backend')
    parser.add_argument('--reason', metavar='TEXT', default='',
                        help='Reason string for mailbox enable/disable')
    parser.add_argument('--list-compromise-events', action='store_true',
                        help='List compromise_events rows')
    parser.add_argument('--open-only', action='store_true',
                        help='With --list-compromise-events: only show unresolved')
    parser.add_argument('--resolve-compromise', type=int, metavar='ID',
                        help='Mark a compromise event as resolved')
    parser.add_argument('--note', metavar='TEXT', default='',
                        help='Note to attach to --resolve-compromise')
    parser.add_argument('--upgrade-config', action='store_true',
                        help='Check for new config options and run upgrade wizard')

    # v1.6 — Posture-audit + host-health (task #122)
    parser.add_argument('--posture-run', action='store_true',
                        help='Run all applicable posture/health checks now')
    parser.add_argument('--posture-status', action='store_true',
                        help='Show current posture-audit status table')
    parser.add_argument('--posture-events', action='store_true',
                        help='Show recent posture-audit transition events')
    parser.add_argument('--posture-profile', action='store_true',
                        help='Show the detected host profile')
    parser.add_argument('--refresh', action='store_true',
                        help='With --posture-profile or --posture-run: re-detect the host profile first')

    args = parser.parse_args()

    # --- Commands that don't need full Guardian init ---

    base_dir = os.path.dirname(os.path.abspath(__file__))

    # Version display
    if args.version:
        version = get_version(base_dir)
        print(f"WP-Guardian v{version}")
        return

    # Config upgrade wizard
    if args.upgrade_config:
        tool_path = os.path.join(base_dir, 'tools', 'config-upgrade.py')
        if not os.path.exists(tool_path):
            print("Error: tools/config-upgrade.py not found")
            sys.exit(1)
        cmd_args = [sys.executable, tool_path]
        if args.config:
            cmd_args.extend(['--config', args.config])
        # Pass --auto if running non-interactively (piped stdin)
        if hasattr(args, 'auto_act') and args.auto_act:
            cmd_args.append('--auto')
        sys.exit(subprocess.call(cmd_args))

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

    if args.analyze_tripwires:
        guardian._analyze_tripwires()
        return

    if args.remove_tripwire:
        path = args.remove_tripwire.strip().lower()
        if not path.startswith('/'):
            path = '/' + path
        removed_from_db = guardian.db.remove_tripwire(path)

        # Also remove from tripwires.txt file
        tripwire_file = os.path.join(base_dir, 'tripwires.txt')
        removed_from_file = False
        if os.path.exists(tripwire_file):
            with open(tripwire_file, 'r') as f:
                lines = f.readlines()
            new_lines = [line for line in lines if line.strip().lower() != path]
            if len(new_lines) < len(lines):
                with open(tripwire_file, 'w') as f:
                    f.writelines(new_lines)
                removed_from_file = True

        # Also remove from in-memory set
        guardian.tripwires.discard(path)

        if removed_from_db or removed_from_file:
            parts = []
            if removed_from_db:
                parts.append("database")
            if removed_from_file:
                parts.append("tripwires.txt")
            print(f"Removed tripwire '{path}' from: {', '.join(parts)}")
        else:
            print(f"Tripwire not found: {path}")
        return

    if args.list_tripwires is not None:
        pattern = args.list_tripwires if args.list_tripwires else None
        total = guardian.db.count_tripwires()

        # Also count file-only tripwires
        tripwire_file = os.path.join(base_dir, 'tripwires.txt')
        file_paths = load_tripwire_file(tripwire_file)

        if pattern:
            results = guardian.db.search_tripwires(pattern=pattern, limit=50)
            # Also search file-only paths
            file_matches = [p for p in sorted(file_paths) if pattern.lower() in p]
            db_paths = set(r['path'] for r in results)
            file_only_matches = [p for p in file_matches if p not in db_paths]

            print(f"\nTripwires matching \"{pattern}\" (of {total} in DB + {len(file_paths)} in file):")
            print(f"{'PATH':<70s} {'HITS':>6s}  SOURCE")
            print("-" * 90)
            for t in results:
                source = "db+file" if t['path'] in file_paths else "db"
                print(f"  {t['path']:<68s} {t['hit_count']:>6d}  {source}")
            for p in file_only_matches[:50 - len(results)]:
                print(f"  {p:<68s} {'?':>6s}  file")
        else:
            limit = 20
            results = guardian.db.search_tripwires(pattern=None, limit=limit)
            print(f"\nActive Tripwires: {total} in DB, {len(file_paths)} in file")
            print(f"\nTop {limit} by hit count:")
            print(f"{'PATH':<70s} {'HITS':>6s}  {'CATEGORY':<15s}")
            print("-" * 95)
            for t in results:
                print(f"  {t['path']:<68s} {t['hit_count']:>6d}  {t['category']}")
            print(f"\nSearch: --list-tripwires <pattern>")
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

    # v1.4 — Auth map / suspects / hunt
    if args.auth_map:
        days = args.days if args.days is not None else 30
        guardian.print_auth_map(args.auth_map, days=days)
        return

    if args.auth_suspects:
        days = args.days if args.days is not None else 7
        guardian.print_auth_suspects(days=days, min_ips=args.min_ips)
        return

    if args.hunt_compromises:
        days = args.days if args.days is not None else 7
        guardian.hunt_compromises(days=days, auto_act=args.auto_act)
        return

    if args.disable_mailbox:
        username = args.disable_mailbox
        if not guardian.mail_backend or not guardian.mail_backend.enabled:
            err = getattr(guardian.mail_backend, 'init_error', None) if guardian.mail_backend else None
            if err:
                print(f"Mail backend failed to initialize: {err}")
            else:
                print("Mail backend not configured. Set [mail_backend] type in wp-guardian.conf.")
            return
        try:
            changed = guardian.mail_backend.disable_mailbox(username)
            # password_reset strategy records its own action (with hash);
            # toggle_enabled needs a separate record
            if guardian.mail_backend.disable_strategy == 'toggle_enabled':
                guardian.db.insert_mailbox_action(
                    username=username, action='disable', actor='cli',
                    reason=args.reason or 'manual CLI disable',
                    success=True,
                )
            if changed:
                print(f"Disabled mailbox: {username}")
            else:
                print(f"Mailbox already disabled or not found: {username}")
        except Exception as e:
            guardian.db.insert_mailbox_action(
                username=username, action='disable', actor='cli',
                reason=args.reason or 'manual CLI disable',
                success=False, error_message=str(e),
            )
            print(f"Failed to disable {username}: {e}")
        return

    if args.enable_mailbox:
        username = args.enable_mailbox
        if not guardian.mail_backend or not guardian.mail_backend.enabled:
            err = getattr(guardian.mail_backend, 'init_error', None) if guardian.mail_backend else None
            if err:
                print(f"Mail backend failed to initialize: {err}")
            else:
                print("Mail backend not configured. Set [mail_backend] type in wp-guardian.conf.")
            return
        try:
            changed = guardian.mail_backend.enable_mailbox(username)
            if guardian.mail_backend.disable_strategy == 'toggle_enabled':
                guardian.db.insert_mailbox_action(
                    username=username, action='enable', actor='cli',
                    reason=args.reason or 'manual CLI enable',
                    success=True,
                )
            if changed:
                print(f"Enabled mailbox: {username}")
            else:
                print(f"Mailbox already enabled or not found: {username}")
        except Exception as e:
            guardian.db.insert_mailbox_action(
                username=username, action='enable', actor='cli',
                reason=args.reason or 'manual CLI enable',
                success=False, error_message=str(e),
            )
            print(f"Failed to enable {username}: {e}")
        return

    if args.list_compromise_events:
        guardian.list_compromise_events_cli(open_only=args.open_only)
        return

    if args.resolve_compromise:
        event_id = args.resolve_compromise
        event = guardian.db.get_compromise_event(event_id)
        if not event:
            print(f"No compromise event with id {event_id}")
            return
        if event['resolved_at']:
            print(f"Event {event_id} is already resolved.")
            return
        guardian.db.resolve_compromise_event(event_id, resolved_by='cli', note=args.note)
        print(f"Resolved compromise event {event_id} ({event['username']})")
        return

    # v1.6 — Posture audit / host-health
    if args.posture_profile:
        if not guardian.host_profile_detector:
            print("Posture auditor not initialized. Check logs for errors.")
            return
        if args.refresh:
            profile = guardian.host_profile_detector.detect_now(detection_method='cli')
        else:
            profile = guardian.host_profile_detector.get_or_detect()
        if not profile:
            print("Could not determine host profile.")
            return
        detected_at = profile.get('detected_at') or 0
        when = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(detected_at)) if detected_at else 'never'
        print("")
        print(f"Host profile for {profile['host']}  (detected {when}, method={profile['detection_method']})")
        print("-" * 68)
        print(f"  is_linux                  : {profile['is_linux']}")
        print(f"  distro                    : {profile['distro_id']} {profile['distro_version']}")
        print(f"  is_cloudlinux             : {profile['is_cloudlinux']}")
        print(f"  is_multi_tenant           : {profile['is_multi_tenant']}")
        print(f"  is_single_site            : {profile['is_single_site']}")
        print(f"  web_server                : {profile['web_server']}")
        print(f"  db_server                 : {profile['db_server']}")
        print(f"  mta                       : {profile['mta']}")
        print(f"  has_modsec                : {profile['has_modsec']}")
        print(f"  behind_perimeter_firewall : {profile['behind_perimeter_firewall']}")
        if profile.get('extras'):
            print("  extras                    :")
            for k, v in profile['extras'].items():
                print(f"      {k}: {v}")
        return

    if args.posture_run:
        if not guardian.posture_auditor:
            print("Posture auditor not initialized. Check logs for errors.")
            return
        results = guardian.posture_auditor.run_now(force_profile_refresh=args.refresh)
        if not results:
            print("No checks ran.")
            return
        print("")
        print(f"Posture run on {guardian.posture_auditor.hostname}")
        print(f"{'CHECK_ID':<24s} {'STATUS':<10s} {'SEV':<10s} {'XSN':<5s}  DETAIL")
        print("-" * 100)
        for cid, r in results.items():
            xsn = 'yes' if r['transition'] else ''
            detail = (r['detail'] or '')[:60]
            print(f"  {cid:<22s} {r['status']:<10s} {r['severity']:<10s} {xsn:<5s}  {detail}")
        print("")
        return

    if args.posture_status:
        if not guardian.posture_auditor:
            print("Posture auditor not initialized. Check logs for errors.")
            return
        rows = guardian.posture_auditor.status_table()
        if not rows:
            print("No posture state recorded yet. Run --posture-run first.")
            return
        print("")
        print(f"Posture state for {guardian.posture_auditor.hostname}")
        print(f"{'MODULE':<10s} {'CHECK_ID':<22s} {'STATUS':<10s} {'SEV':<10s} {'LAST_RUN':<20s}  DETAIL")
        print("-" * 110)
        for r in rows:
            last_run = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r['last_run_at']))
            detail = (r['detail'] or '')[:50]
            print(f"  {r['module']:<8s} {r['check_id']:<22s} {r['status']:<10s} {r['severity']:<10s} {last_run:<20s}  {detail}")
        print("")
        return

    if args.posture_events:
        if not guardian.posture_auditor:
            print("Posture auditor not initialized. Check logs for errors.")
            return
        events = guardian.posture_auditor.recent_events(limit=50)
        if not events:
            print("No posture events recorded.")
            return
        print("")
        print(f"Recent posture events for {guardian.posture_auditor.hostname}")
        print(f"{'WHEN':<20s} {'CHECK_ID':<22s} {'FROM':<10s} -> {'TO':<10s} {'SEV':<10s}  DETAIL")
        print("-" * 120)
        for e in events:
            when = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e['occurred_at']))
            detail = (e['detail'] or '')[:40]
            print(f"  {when:<18s} {e['check_id']:<22s} {e['from_status']:<10s} -> {e['to_status']:<10s} {e['severity']:<10s}  {detail}")
        print("")
        return

    # Default: run the daemon
    guardian.start()


if __name__ == '__main__':
    main()
