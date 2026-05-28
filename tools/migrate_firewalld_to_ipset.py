#!/usr/bin/env python3
"""
WP-Guardian — firewalld Rich Rule → ipset Migration Tool (v1.7.4+)

Folds existing per-IP/CIDR drop rich rules in the firewalld zone used by
WP-Guardian into the new ``wp_guardian_blocked`` and ``wp_guardian_cidr``
ipsets introduced by the v1.7.4 firewalld backend refactor.

Why this exists
---------------
Pre-v1.7.4 the firewalld backend added one permanent rich rule per
blocked IP, then ran ``firewall-cmd --reload`` after each block. On
hosts that have been running for a while the rich-rule list grows into
the thousands, each block triggers a full reload, and every dropped
packet walks the entire ip-saddr comparison list in nftables.

The v1.7.4 backend stores blocks in two ipsets and drops via a single
``rule source ipset="..." drop`` per set. This tool migrates legacy
rich rules into those ipsets so operators don't lose their existing
block state when upgrading.

Usage
-----
::

    python3 tools/migrate_firewalld_to_ipset.py            # do the work
    python3 tools/migrate_firewalld_to_ipset.py --dry-run  # show plan only
    python3 tools/migrate_firewalld_to_ipset.py --config PATH

The tool is idempotent — running it twice on the same host is a no-op
on the second pass because every legacy rich rule was already removed.
"""

import argparse
import logging
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
sys.path.insert(0, PROJECT_ROOT)

from modules.config import load_config  # noqa: E402
from backends.firewalld import (  # noqa: E402
    FirewalldBackend, IPSET_BLOCKED, IPSET_CIDR,
)

logger = logging.getLogger('wp-guardian.migrate-firewalld')


SERVICE_NAME = 'wp-guardian'


# Matches the exact shape the pre-v1.7.4 backend emitted via
# `_rich_rule()`:  rule family="ipv4" source address="<addr>" drop
LEGACY_RULE_RE = re.compile(
    r'^\s*rule\s+family="ipv4"\s+source\s+address="([^"]+)"\s+drop\s*$'
)


# ---------------------------------------------------------------------------
# Shelling out
# ---------------------------------------------------------------------------
def run(cmd, timeout=30, check=False):
    """Run a command, return (rc, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return (124, '', 'timeout running {}'.format(' '.join(cmd)))
    except FileNotFoundError:
        return (127, '', '{} not found'.format(cmd[0]))

    if check and result.returncode != 0:
        raise RuntimeError(
            "Command failed: {} -> rc={} stderr={}".format(
                ' '.join(cmd), result.returncode, result.stderr.strip()
            )
        )
    return (result.returncode, result.stdout.strip(), result.stderr.strip())


def systemctl_is_active(unit):
    rc, out, _ = run(['systemctl', 'is-active', unit], timeout=5)
    return rc == 0 and out.strip() == 'active'


def stop_service(unit, dry_run):
    if dry_run:
        print("DRY-RUN: would 'systemctl stop {}'".format(unit))
        return
    print("Stopping {}...".format(unit))
    rc, _, err = run(['systemctl', 'stop', unit])
    if rc != 0:
        raise RuntimeError("systemctl stop {} failed: {}".format(unit, err))


def start_service(unit, dry_run):
    if dry_run:
        print("DRY-RUN: would 'systemctl start {}'".format(unit))
        return
    print("Starting {}...".format(unit))
    rc, _, err = run(['systemctl', 'start', unit])
    if rc != 0:
        raise RuntimeError("systemctl start {} failed: {}".format(unit, err))


# ---------------------------------------------------------------------------
# Migration steps
# ---------------------------------------------------------------------------
def list_legacy_rules(zone):
    """Return [(addr, raw_rule)] for legacy WP-Guardian rich rules in zone."""
    rc, stdout, err = run([
        'firewall-cmd', '--permanent',
        '--zone={}'.format(zone), '--list-rich-rules'
    ])
    if rc != 0:
        raise RuntimeError(
            "firewall-cmd --list-rich-rules failed: {}".format(err)
        )

    legacy = []
    for raw in stdout.splitlines():
        m = LEGACY_RULE_RE.match(raw)
        if not m:
            continue
        legacy.append((m.group(1), raw.strip()))
    return legacy


def split_entries(legacy_rules):
    """Bucket addresses into ip / cidr / skipped lists."""
    ips, cidrs, skipped = [], [], []
    for addr, raw in legacy_rules:
        if '/' in addr:
            # Anything with a prefix goes into the net set. Most should
            # be /24s but we don't reject other prefix lengths — the
            # daemon owns CIDR policy, not the migration tool.
            cidrs.append((addr, raw))
        elif _looks_like_ipv4(addr):
            ips.append((addr, raw))
        else:
            skipped.append((addr, raw))
    return ips, cidrs, skipped


def _looks_like_ipv4(addr):
    parts = addr.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def add_ipset_entry(ipset, entry):
    """Add an entry to runtime + permanent ipset. Idempotent."""
    rc, _, err = run([
        'firewall-cmd', '--permanent',
        '--ipset={}'.format(ipset), '--add-entry={}'.format(entry)
    ])
    if rc != 0 and 'already' not in err.lower():
        raise RuntimeError(
            "Failed to add {} -> {} (permanent): {}".format(entry, ipset, err)
        )


def remove_rich_rule(zone, raw_rule):
    """Remove a permanent rich rule. Idempotent."""
    rc, _, err = run([
        'firewall-cmd', '--permanent',
        '--zone={}'.format(zone),
        '--remove-rich-rule={}'.format(raw_rule)
    ])
    if rc != 0:
        low = err.lower()
        if 'not_enabled' in low or 'not enabled' in low or 'not found' in low:
            return
        raise RuntimeError(
            "Failed to remove rich rule '{}': {}".format(raw_rule, err)
        )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description=(
            "Migrate legacy WP-Guardian firewalld rich rules into the "
            "v1.7.4 ipsets (wp_guardian_blocked, wp_guardian_cidr)."
        )
    )
    parser.add_argument(
        '--dry-run', action='store_true',
        help='Print the plan; do not modify firewalld or stop the daemon.'
    )
    parser.add_argument(
        '--config', default=None,
        help='Path to wp-guardian.conf (default: search standard locations).'
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(message)s')

    # ------------------------------------------------------------------
    # Sanity: backend must be firewalld
    # ------------------------------------------------------------------
    config = load_config(args.config)
    backend = config.get('firewall', 'backend', fallback='').strip().lower()
    if backend != 'firewalld':
        print("ERROR: [firewall] backend = '{}' (expected 'firewalld').".format(backend))
        print("       This migration is only for hosts using the firewalld backend.")
        return 2

    zone = config.get('firewalld', 'zone', fallback='public')
    print("Migration plan: zone={}, ipsets=({}, {})".format(
        zone, IPSET_BLOCKED, IPSET_CIDR
    ))

    # ------------------------------------------------------------------
    # Inspect current state BEFORE stopping the daemon — fast feedback
    # for --dry-run, and lets us bail cleanly if nothing to do.
    # ------------------------------------------------------------------
    rc, _, err = run(['firewall-cmd', '--state'], timeout=5)
    if rc != 0:
        print("ERROR: firewalld is not running ({}). Start it first.".format(err))
        return 2

    try:
        legacy = list_legacy_rules(zone)
    except RuntimeError as e:
        print("ERROR: {}".format(e))
        return 2

    ips, cidrs, skipped = split_entries(legacy)

    print("")
    print("Found {} legacy WP-Guardian drop rich rule(s) in zone '{}':".format(
        len(legacy), zone
    ))
    print("  - {} individual IPs   -> {}".format(len(ips), IPSET_BLOCKED))
    print("  - {} CIDR ranges      -> {}".format(len(cidrs), IPSET_CIDR))
    print("  - {} skipped (malformed / non-ipv4)".format(len(skipped)))

    if args.dry_run:
        if skipped:
            print("")
            print("Skipped rules (will be left in place):")
            for addr, raw in skipped[:20]:
                print("  ! {}".format(raw))
            if len(skipped) > 20:
                print("  ... ({} more)".format(len(skipped) - 20))
        print("")
        print("DRY-RUN: no changes made.")
        return 0

    if not legacy:
        # Still verify the new structures exist so the operator can run
        # the tool right after upgrade as a safety net.
        try:
            backend_obj = FirewalldBackend(config)
            backend_obj.ensure_firewall_rules()
        except Exception as e:
            print("WARNING: ensure_firewall_rules() failed: {}".format(e))
        print("Nothing to migrate. Done.")
        return 0

    # ------------------------------------------------------------------
    # Capture daemon state so we can restart it at the end if it was running
    # ------------------------------------------------------------------
    was_running = systemctl_is_active(SERVICE_NAME)
    print("")
    print("wp-guardian service is currently: {}".format(
        'active' if was_running else 'inactive'
    ))

    try:
        if was_running:
            stop_service(SERVICE_NAME, dry_run=False)

        # ------------------------------------------------------------------
        # Create the ipsets and ipset-referencing rich rules (idempotent)
        # ------------------------------------------------------------------
        print("Ensuring ipsets and drop rich rules exist...")
        backend_obj = FirewalldBackend(config)
        backend_obj.ensure_firewall_rules()

        # ------------------------------------------------------------------
        # Add entries to the ipsets (permanent only; runtime gets
        # rebuilt by the final reload).
        # ------------------------------------------------------------------
        print("Importing {} entries into ipsets...".format(len(ips) + len(cidrs)))
        added_ips = 0
        added_cidrs = 0
        for addr, _raw in ips:
            try:
                add_ipset_entry(IPSET_BLOCKED, addr)
                added_ips += 1
            except RuntimeError as e:
                print("  ! {}".format(e))
        for addr, _raw in cidrs:
            try:
                add_ipset_entry(IPSET_CIDR, addr)
                added_cidrs += 1
            except RuntimeError as e:
                print("  ! {}".format(e))

        # ------------------------------------------------------------------
        # Strip the legacy rich rules from the zone.
        # ------------------------------------------------------------------
        print("Removing {} legacy rich rules from zone {}...".format(
            len(legacy), zone
        ))
        removed = 0
        for _addr, raw in legacy:
            try:
                remove_rich_rule(zone, raw)
                removed += 1
            except RuntimeError as e:
                print("  ! {}".format(e))

        # ------------------------------------------------------------------
        # ONE reload — this is the only one in the entire flow.
        # ------------------------------------------------------------------
        print("Reloading firewalld (single reload)...")
        rc, _, err = run(['firewall-cmd', '--reload'], timeout=60)
        if rc != 0:
            raise RuntimeError("firewall-cmd --reload failed: {}".format(err))

    finally:
        # Whatever happened above, give the operator their daemon back.
        if was_running:
            try:
                start_service(SERVICE_NAME, dry_run=False)
            except RuntimeError as e:
                print("WARNING: could not restart {}: {}".format(SERVICE_NAME, e))
                print("         Bring it back manually: systemctl start {}".format(SERVICE_NAME))

    # ------------------------------------------------------------------
    # Post-migration summary
    # ------------------------------------------------------------------
    print("")
    print("Migration complete:")
    print("  {} rich rules removed".format(removed))
    print("  {} entries added to {}".format(added_ips, IPSET_BLOCKED))
    print("  {} entries added to {}".format(added_cidrs, IPSET_CIDR))
    if skipped:
        print("  {} rich rules skipped (left in place, manual review):".format(len(skipped)))
        for addr, raw in skipped[:20]:
            print("    - {}".format(raw))
        if len(skipped) > 20:
            print("    ... ({} more)".format(len(skipped) - 20))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
