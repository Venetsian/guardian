#!/usr/bin/env python3
"""
WP-Guardian Maillog Backfill Tool (v1.4+)

One-shot import of recent maillog history into `auth_sessions` so that
DistributedAuthDetector has warm context, and --auth-map / --hunt-compromises
have real data on day one.

v1.7.15 adds `--outbound`, which replays the same logs into `outbound_activity`.
That matters more than it sounds: the outbound VOLUME corroboration check
compares an account against its own history and is inert until the table holds
`outbound_min_observation_days` (default 14) of it. A host with rotated logs
already has that history on disk — backfilling arms the check immediately
instead of leaving a two-week blind spot after install.

Usage:
    python3 tools/backfill_maillog.py [--days 7] [--maillog /var/log/maillog]
                                       [--also-rotated] [--dry-run]

    # Arm the outbound baseline from a month of rotated logs
    python3 tools/backfill_maillog.py --outbound-only --also-rotated --days 30

Reuses the same regex logic as MailDetector for successful SMTP / IMAP / POP3
authentication, and the real OutboundTracker for the queue-ID correlation — so
a backfilled row is produced by exactly the code path that produces a live one.
Skips duplicate rows via an idempotency check against the DB.
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
from modules.outbound import (  # noqa: E402
    OutboundTracker, parse_qmgr, parse_submission,
)


# Postfix logs `sasl_method=` ONLY on successful SMTP auths — it's set after
# SASL completes. Failed-auth lines contain `sasl_username=` too (the client's
# attempted username) but NEVER `sasl_method=`. We require sasl_method= here
# so we don't record every failed SMTP auth as a "success".
SMTP_SUCCESS_RE = re.compile(
    r'client=[^,\s]*\[(?P<ip>\d+\.\d+\.\d+\.\d+)\].*sasl_method=\S+.*sasl_username=(?P<user>\S+)'
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
    """Return list of log files to scan, oldest first.

    Handles two rotated-log naming conventions:
      - Debian/Ubuntu: maillog.1, maillog.2.gz, maillog.3.gz, ...
      - RHEL/AlmaLinux logrotate dateext: maillog-YYYYMMDD, maillog-YYYYMMDD.gz

    For the dash-date form we sort oldest-first by the date suffix.
    For the numeric form we sort oldest-first by descending numeric suffix.
    """
    files = []

    if also_rotated:
        # Numeric-suffix rotated files (maillog.1, maillog.2.gz, ...)
        numeric = []
        for p in glob.glob(main_path + '.*'):
            if os.path.isfile(p):
                base = os.path.basename(p)
                # Skip if it's actually a dash-date file that happened to glob-match
                suffix_parts = base[len(os.path.basename(main_path)) + 1:].split('.')
                if suffix_parts and suffix_parts[0].isdigit():
                    numeric.append(p)

        def numeric_key(p):
            base = os.path.basename(p)
            for part in base.split('.')[::-1]:
                if part.isdigit():
                    return -int(part)
            return 0
        numeric.sort(key=numeric_key)

        # Dash-date rotated files (maillog-YYYYMMDD, maillog-YYYYMMDD.gz)
        # E.g. /var/log/maillog → /var/log/maillog-20260329
        dated = []
        date_re = re.compile(r'-(\d{8})(?:\.gz)?$')
        for p in glob.glob(main_path + '-*'):
            if os.path.isfile(p) and date_re.search(p):
                dated.append(p)
        dated.sort()  # lexical sort on YYYYMMDD == chronological, oldest first

        files.extend(numeric)
        files.extend(dated)

    if os.path.isfile(main_path):
        files.append(main_path)
    return files


class _DedupeWriter:
    """DB proxy that makes an outbound backfill safely re-runnable.

    Only the tracker's `record_outbound` is intercepted. The live daemon keeps
    writing straight through to GuardianDB with no extra SELECT per message.
    """

    def __init__(self, db, dry_run, stats):
        self._db = db
        self._dry_run = dry_run
        self._stats = stats

    def record_outbound(self, username, ip, nrcpt, size_bytes=0, queue_id='',
                        timestamp=None):
        if self._db.outbound_exists(queue_id, timestamp):
            self._stats['ob_skipped'] += 1
            return
        if self._dry_run:
            self._stats['ob_would'] += 1
            return
        self._db.record_outbound(username=username, ip=ip, nrcpt=nrcpt,
                                 size_bytes=size_bytes, queue_id=queue_id,
                                 timestamp=timestamp)
        self._stats['ob_inserted'] += 1


def process_file(path, db, geoip, cutoff_ts, dry_run, stats,
                 tracker=None, auth_enabled=True):
    """Parse one maillog file, inserting new auth rows.

    `tracker` is a live OutboundTracker whose pending queue-ID map is shared
    across every file in the run. That sharing is load-bearing: logrotate can
    split a message's submission line from its qmgr line across two files, and
    files are processed oldest-first precisely so the join still lands.
    """
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

            # SMTP: gated on sasl_method= (only present on real successes).
            # Extra belt-and-braces: skip any line that contains the
            # string 'authentication failed' just in case a future Postfix
            # variant logs sasl_method= on a failure path.
            if 'sasl_method=' in line and 'authentication failed' not in line:
                m = SMTP_SUCCESS_RE.search(line)
                if m:
                    ip = m.group('ip')
                    user = m.group('user')
                    service = 'smtp'
            elif 'Login: user=' in line and 'dovecot' in line:
                m = IMAP_SUCCESS_RE.search(line)
                if m:
                    ip = m.group('ip')
                    user = m.group('user')
                    service = 'imap' if 'imap-login' in line else 'pop3'

            # --- outbound correlation (v1.7.15) ---
            # Runs before the auth early-exit because a qmgr line carries no
            # ip/user and would otherwise never be reached. `now=ts` is the
            # important part: the tracker's TTL has to be measured in LOG time
            # when replaying history, not against the wall clock, or every
            # pending entry looks infinitely expired.
            if tracker is not None:
                if service == 'smtp':
                    qid = parse_submission(line)
                    if qid:
                        tracker.note_submission(qid, user, ip, now=ts)
                elif 'nrcpt=' in line:
                    parsed = parse_qmgr(line)
                    if parsed:
                        tracker.note_delivery(parsed[0], parsed[1], parsed[2],
                                              now=ts)

            if not (ip and user):
                continue
            if not auth_enabled:
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
                        help='Only import events from the last N days (default 7; '
                             'use 30 for --outbound, to match outbound_baseline_days)')
    parser.add_argument('--maillog', default='/var/log/maillog',
                        help='Path to the current maillog (default /var/log/maillog)')
    parser.add_argument('--also-rotated', action='store_true',
                        help='Also scan rotated logs (maillog.1, maillog.2.gz, ...)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Parse and count but do not insert')
    parser.add_argument('--outbound', action='store_true',
                        help='Also backfill outbound_activity, arming the volume '
                             'corroboration baseline immediately instead of after '
                             'outbound_min_observation_days of live running')
    parser.add_argument('--outbound-only', action='store_true',
                        help='Backfill outbound_activity and skip auth_sessions '
                             '(for a host whose auth history is already imported)')
    parser.add_argument('--config', default=None,
                        help='Path to wp-guardian.conf')
    args = parser.parse_args()

    do_outbound = args.outbound or args.outbound_only
    do_auth = not args.outbound_only

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
        'ob_inserted': 0, 'ob_would': 0, 'ob_skipped': 0,
    }

    tracker = None
    if do_outbound:
        # One tracker for the whole run, so its pending map survives file
        # boundaries (see process_file).
        tracker = OutboundTracker(config, _DedupeWriter(db, args.dry_run, stats))
        if not tracker.enabled:
            print("Note: [compromise_detection] outbound_monitoring is false in "
                  "the config, but --outbound was requested — enabling for this "
                  "run only.")
            tracker.enabled = True
        if args.days < 14:
            print("Note: --days {d} is short for an outbound baseline. The volume "
                  "check needs outbound_min_observation_days (default 14) of "
                  "history before it arms at all.".format(d=args.days))

    start = time.time()
    for path in files:
        process_file(path, db, geoip, cutoff_ts, args.dry_run, stats,
                     tracker=tracker, auth_enabled=do_auth)
    duration = time.time() - start

    print("")
    print("Backfill complete in {d:.1f}s".format(d=duration))
    print("  Lines scanned:   {n}".format(n=stats['lines']))
    if do_auth:
        print("  Matched (auth):  {n}".format(n=stats['matched']))
        print("  Skipped (dup):   {n}".format(n=stats['skipped']))
        if args.dry_run:
            print("  Would insert:    {n}".format(n=stats['would_insert']))
        else:
            print("  Inserted:        {n}".format(n=stats['inserted']))

    if tracker is not None:
        ts_ = tracker.stats
        print("")
        print("Outbound correlation")
        print("  Submissions:     {n}".format(n=ts_['submissions']))
        # 'recorded' counts joins that reached the writer, whether it inserted
        # them or skipped them as duplicates — adding ob_skipped here would
        # double-count every row on a re-run.
        print("  Joined (sent):   {n}".format(n=ts_['recorded']))
        print("  Unmatched:       {n}  (inbound mail — correctly ignored)".format(
            n=ts_['unmatched']))
        print("  Never queued:    {n}  (authenticated, no message sent)".format(
            n=ts_['expired'] + tracker.pending_count()))
        print("  Skipped (dup):   {n}".format(n=stats['ob_skipped']))
        if args.dry_run:
            print("  Would insert:    {n}".format(n=stats['ob_would']))
        else:
            print("  Inserted:        {n}".format(n=stats['ob_inserted']))
        if ts_['errors']:
            print("  Errors:          {n}".format(n=ts_['errors']))
        if not args.dry_run and stats['ob_inserted']:
            try:
                days = db.outbound_observation_days()
                need = config.getint('compromise_detection',
                                     'outbound_min_observation_days', fallback=14)
                print("")
                print("  History now spans {d:.1f} days — volume baseline {s}".format(
                    d=days, s="ARMED" if days >= need else
                    "still inert (needs {n})".format(n=need)))
                print("  Verify with: python3 wp-guardian.py --outbound-stats --days 30")
            except Exception:
                pass

    if geoip:
        try:
            geoip.close()
        except Exception:
            pass
    db.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
