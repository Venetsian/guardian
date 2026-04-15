#!/usr/bin/env python3
"""
WP-Guardian Maillog Backfill Tool (v1.4+)

One-shot import of recent maillog history into `auth_sessions` so that
DistributedAuthDetector has warm context, and --auth-map / --hunt-compromises
have real data on day one.

Usage:
    python3 tools/backfill_maillog.py [--days 7] [--maillog /var/log/maillog]
                                       [--also-rotated] [--dry-run]

Reuses the same regex logic as MailDetector for successful SMTP / IMAP / POP3
authentication. Skips duplicate rows via an idempotency check against the DB.
"""

import argparse
import glob
import gzip
import io
import os
import re
import sys
import time
import calendar

# Add project root to path so we can import modules/*
HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
sys.path.insert(0, PROJECT_ROOT)

from modules.config import load_config  # noqa: E402
from modules.database import GuardianDB  # noqa: E402
from modules.geoip import GeoIPResolver  # noqa: E402


SMTP_SUCCESS_RE = re.compile(
    r'\[(?P<ip>\d+\.\d+\.\d+\.\d+)\].*sasl_username=(?P<user>\S+)'
)
IMAP_SUCCESS_RE = re.compile(
    r'Login: user=<(?P<user>[^>]+)>.*rip=(?P<ip>\d+\.\d+\.\d+\.\d+)'
)
# Syslog timestamp prefix: "Apr 14 15:11:15" (year not present — we assume
# the log's mtime year, adjusted for log rotation edge cases).
SYSLOG_TS_RE = re.compile(
    r'^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})'
)
MONTHS = {m: i + 1 for i, m in enumerate(
    ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
     'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
)}


def parse_syslog_timestamp(line, default_year):
    """Parse a syslog-format timestamp at the start of a line to epoch seconds.
    Uses default_year as the year (syslog has no year). Returns None on failure.
    """
    m = SYSLOG_TS_RE.match(line)
    if not m:
        return None
    try:
        mon = MONTHS[m.group('mon')]
        day = int(m.group('day'))
        t = (default_year, mon, day,
             int(m.group('h')), int(m.group('m')), int(m.group('s')),
             0, 0, -1)
        # Use calendar.timegm for UTC or time.mktime for local?
        # Syslog writes in server local time — use mktime.
        return int(time.mktime(t))
    except (KeyError, ValueError):
        return None


def open_log(path):
    """Open a maillog file, transparently handling .gz."""
    if path.endswith('.gz'):
        return io.TextIOWrapper(gzip.open(path, 'rb'), encoding='utf-8', errors='replace')
    return open(path, 'r', encoding='utf-8', errors='replace')


def gather_log_files(main_path, also_rotated):
    """Return list of log files to scan, oldest first."""
    files = []
    if also_rotated:
        patterns = [main_path + '.*']
        for pattern in patterns:
            for p in glob.glob(pattern):
                if os.path.isfile(p):
                    files.append(p)
        # sort rotated files — maillog.1 newest among rotated, maillog.10 oldest.
        # Oldest first means higher numeric suffixes first.
        def rotated_key(p):
            base = os.path.basename(p)
            for part in base.split('.')[::-1]:
                if part.isdigit():
                    return -int(part)
            return 0
        files.sort(key=rotated_key)
    if os.path.isfile(main_path):
        files.append(main_path)
    return files


def process_file(path, db, geoip, cutoff_ts, dry_run, stats):
    """Parse one maillog file, inserting new auth rows."""
    # Default year = the file's mtime year
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = time.time()
    default_year = time.localtime(mtime).tm_year

    try:
        fh = open_log(path)
    except Exception as e:
        print("! Cannot open {p}: {e}".format(p=path, e=e))
        return

    print("Scanning {p}...".format(p=path))
    file_inserted = 0

    try:
        for line in fh:
            stats['lines'] += 1

            ts = parse_syslog_timestamp(line, default_year)
            if ts is None:
                continue
            if ts < cutoff_ts:
                continue

            ip = None
            user = None
            service = None

            if 'sasl_username=' in line:
                m = SMTP_SUCCESS_RE.search(line)
                if m:
                    ip = m.group('ip')
                    user = m.group('user')
                    service = 'smtp'
            elif 'Login: user=' in line:
                m = IMAP_SUCCESS_RE.search(line)
                if m:
                    ip = m.group('ip')
                    user = m.group('user')
                    service = 'imap' if 'imap-login' in line else 'pop3'

            if not (ip and user):
                continue

            stats['matched'] += 1

            # Idempotency check
            if db.auth_session_exists(ip, user, ts):
                stats['skipped'] += 1
                continue

            if dry_run:
                stats['would_insert'] += 1
                continue

            geo = None
            if geoip and geoip.enabled:
                geo = geoip.lookup(ip)

            db.record_auth(ip, service, user, geo=geo, timestamp=ts)
            stats['inserted'] += 1
            file_inserted += 1

            if stats['inserted'] % 500 == 0:
                print("  ... {n} inserted".format(n=stats['inserted']))
    finally:
        fh.close()

    print("  done — {n} new rows from this file".format(n=file_inserted))


def main():
    parser = argparse.ArgumentParser(description='Backfill maillog history into WP-Guardian')
    parser.add_argument('--days', type=int, default=7,
                        help='Only import events from the last N days (default 7)')
    parser.add_argument('--maillog', default='/var/log/maillog',
                        help='Path to the current maillog (default /var/log/maillog)')
    parser.add_argument('--also-rotated', action='store_true',
                        help='Also scan rotated logs (maillog.1, maillog.2.gz, ...)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Parse and count but do not insert')
    parser.add_argument('--config', default=None,
                        help='Path to wp-guardian.conf')
    args = parser.parse_args()

    cutoff_ts = int(time.time()) - args.days * 86400

    config = load_config(args.config)
    db_path = config.get(
        'database', 'path',
        fallback=os.path.join(PROJECT_ROOT, 'state', 'guardian.db')
    )
    db = GuardianDB(db_path, base_dir=PROJECT_ROOT)

    try:
        geoip = GeoIPResolver(config)
    except Exception as e:
        print("GeoIP init failed: {e} (continuing without geo enrichment)".format(e=e))
        geoip = None

    files = gather_log_files(args.maillog, args.also_rotated)
    if not files:
        print("No log files found at {p}".format(p=args.maillog))
        return 1

    stats = {
        'lines': 0, 'matched': 0, 'skipped': 0,
        'inserted': 0, 'would_insert': 0,
    }

    start = time.time()
    for path in files:
        process_file(path, db, geoip, cutoff_ts, args.dry_run, stats)
    duration = time.time() - start

    print("")
    print("Backfill complete in {d:.1f}s".format(d=duration))
    print("  Lines scanned:   {n}".format(n=stats['lines']))
    print("  Matched (auth):  {n}".format(n=stats['matched']))
    print("  Skipped (dup):   {n}".format(n=stats['skipped']))
    if args.dry_run:
        print("  Would insert:    {n}".format(n=stats['would_insert']))
    else:
        print("  Inserted:        {n}".format(n=stats['inserted']))

    if geoip:
        try:
            geoip.close()
        except Exception:
            pass
    db.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
