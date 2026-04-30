#!/usr/bin/env python3
"""
WP-Guardian ip_history Geo-Backfill Tool (v1.4.2+)

One-shot enrichment of `ip_history` rows that shipped without geo data
because of the v1.4.0–v1.4.1 wiring bug where `Blocker` was constructed
before `GeoIPResolver` and never received the resolver. The bug is fixed
in v1.4.2; this tool repairs the historical rows.

Usage:
    python3 tools/backfill_ip_history.py [--dry-run] [--limit N]
                                          [--all] [--batch-size 1000]
                                          [--config PATH]

Defaults to scanning only rows where geoip_country is empty AND geoip_asn
is 0 (the v1.4.0–v1.4.1 victims). Pass --all to re-resolve every row,
e.g. after a GeoLite2 database refresh.

Idempotent: re-running picks up only rows that are still missing data
(unless --all is given).
"""

import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
sys.path.insert(0, PROJECT_ROOT)

from modules.config import load_config  # noqa: E402
from modules.database import GuardianDB  # noqa: E402
from modules.geoip import GeoIPResolver  # noqa: E402


def select_rows(db, include_all, limit):
    """Return a list of (ip,) tuples to enrich."""
    if include_all:
        sql = "SELECT ip FROM ip_history ORDER BY last_seen DESC"
    else:
        sql = (
            "SELECT ip FROM ip_history "
            "WHERE (geoip_country IS NULL OR geoip_country = '') "
            "  AND (geoip_asn IS NULL OR geoip_asn = 0) "
            "ORDER BY last_seen DESC"
        )
    if limit and limit > 0:
        sql += " LIMIT {n}".format(n=int(limit))
    cursor = db.conn.execute(sql)
    return [row['ip'] for row in cursor.fetchall()]


def update_row(db, ip, geo):
    """Apply the resolved geo dict to one ip_history row."""
    db.conn.execute(
        "UPDATE ip_history "
        "SET geoip_country = ?, geoip_city = ?, "
        "    geoip_asn = ?, geoip_asn_org = ? "
        "WHERE ip = ?",
        (geo.get('country', '') or '',
         geo.get('city', '') or '',
         int(geo.get('asn', 0) or 0),
         geo.get('asn_org', '') or '',
         ip)
    )


def main():
    parser = argparse.ArgumentParser(
        description='Backfill geo data into ip_history rows missed by the '
                    'v1.4.0–v1.4.1 Blocker/GeoIP wiring bug.'
    )
    parser.add_argument('--dry-run', action='store_true',
                        help='Look up but do not write — print counts only')
    parser.add_argument('--limit', type=int, default=0,
                        help='Stop after N rows (0 = no limit)')
    parser.add_argument('--all', action='store_true', dest='include_all',
                        help='Re-resolve every row (default: only blank rows)')
    parser.add_argument('--batch-size', type=int, default=1000,
                        help='Commit every N updates (default 1000)')
    parser.add_argument('--config', default=None,
                        help='Path to wp-guardian.conf')
    args = parser.parse_args()

    config = load_config(args.config)

    if not config.getboolean('geoip', 'enabled', fallback=False):
        print("ERROR: [geoip] enabled = false in config — nothing to do.")
        print("       Enable GeoIP and ensure the .mmdb files are in place,")
        print("       then re-run this tool.")
        return 2

    db_path = config.get(
        'database', 'path',
        fallback=os.path.join(PROJECT_ROOT, 'state', 'guardian.db')
    )
    db = GuardianDB(db_path, base_dir=PROJECT_ROOT)

    try:
        geoip = GeoIPResolver(config)
    except Exception as e:
        print("ERROR: GeoIP init failed: {e}".format(e=e))
        db.close()
        return 2

    if not geoip.enabled:
        print("ERROR: GeoIP resolver disabled at runtime "
              "(missing .mmdb file or geoip2 library?). Cannot backfill.")
        db.close()
        return 2

    rows = select_rows(db, args.include_all, args.limit)
    total = len(rows)
    if total == 0:
        print("Nothing to do — no rows match.")
        geoip.close()
        db.close()
        return 0

    mode = 'all rows' if args.include_all else 'blank rows only'
    print("Resolving {n} ip_history rows ({mode}){dry}.".format(
        n=total, mode=mode,
        dry=' [DRY-RUN]' if args.dry_run else ''
    ))

    stats = {'looked_up': 0, 'updated': 0, 'no_match': 0, 'errors': 0}
    start = time.time()
    pending = 0

    for i, ip in enumerate(rows, 1):
        try:
            geo = geoip.lookup(ip)
        except Exception as e:
            stats['errors'] += 1
            print("! lookup failed for {ip}: {e}".format(ip=ip, e=e))
            continue

        stats['looked_up'] += 1

        if not geo or (not geo.get('country') and not geo.get('asn')):
            stats['no_match'] += 1
            continue

        if args.dry_run:
            stats['updated'] += 1
            continue

        try:
            update_row(db, ip, geo)
            stats['updated'] += 1
            pending += 1
        except Exception as e:
            stats['errors'] += 1
            print("! update failed for {ip}: {e}".format(ip=ip, e=e))

        if pending >= args.batch_size:
            db.conn.commit()
            pending = 0

        if i % 500 == 0:
            print("  ... {i}/{n}  updated={u}  no-match={nm}".format(
                i=i, n=total, u=stats['updated'], nm=stats['no_match']
            ))

    if pending > 0 and not args.dry_run:
        db.conn.commit()

    duration = time.time() - start
    print("")
    print("Backfill complete in {d:.1f}s".format(d=duration))
    print("  Rows scanned:   {n}".format(n=total))
    print("  Looked up:      {n}".format(n=stats['looked_up']))
    print("  {label}:{pad}{n}".format(
        label='Would update' if args.dry_run else 'Updated',
        pad=' ' * (5 if args.dry_run else 9),
        n=stats['updated']
    ))
    print("  No geo match:   {n}".format(n=stats['no_match']))
    if stats['errors']:
        print("  Errors:         {n}".format(n=stats['errors']))

    geoip.close()
    db.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
