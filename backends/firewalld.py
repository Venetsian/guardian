"""
WP-Guardian firewalld Backend
Blocking via firewalld (firewall-cmd) — the default firewall on modern
RHEL/AlmaLinux/CentOS/Fedora systems and CyberPanel 2.4+.

Strategy (v1.7.4+):
  - Two firewalld-managed ipsets:
      * wp_guardian_blocked  (hash:ip)  — individual IPs across all tiers
      * wp_guardian_cidr     (hash:net) — /24 aggregations
  - One drop rich rule per ipset in the configured zone — every blocked
    packet matches a single set lookup instead of walking thousands of
    per-IP rich rules.
  - Block/unblock = one ``firewall-cmd --ipset --add-entry`` (runtime)
    plus the same call with ``--permanent`` for reboot persistence.
    No ``--reload`` on the hot path.
  - Tier TTLs remain owned by the WP-Guardian database: we do NOT use
    per-entry ipset timeouts, so behavior matches the other backends.
    Expiry is enforced by ``Blocker.reap_expired_blocks()`` on the
    daemon's hourly cleanup tick (v1.7.9+). Before that reaper existed
    this contract was documented here but never implemented, which made
    every "24h" block on firewalld permanent — if you disable
    ``[escalation] reap_enabled``, that is the behavior you get back.

Operators upgrading from the pre-v1.7.4 rich-rule implementation should
run ``python3 tools/migrate_firewalld_to_ipset.py`` once after the
update to fold any existing per-IP rich rules into the new ipsets.
"""

import subprocess
import logging

from backends.base import FirewallBackend
from modules.config import parse_duration
from modules.conntrack import ConntrackFlusher

logger = logging.getLogger('wp-guardian.firewalld')

# ipset names — single source of truth, also used by the migration tool
IPSET_BLOCKED = 'wp_guardian_blocked'
IPSET_CIDR = 'wp_guardian_cidr'


class FirewalldBackend(FirewallBackend):
    """Firewall backend using firewalld (firewall-cmd) ipsets."""

    supports_cidr = True
    supports_friendly_list = False  # No built-in friendly list; use whitelist.conf
    # ipset entries deliberately carry no TTL (see module docstring), so the
    # reaper MUST call unblock() here — nothing else ever removes them.
    expires_own_entries = False

    def __init__(self, config):
        # Parse tier durations (kept for logging / future use; TTLs owned by DB)
        self.tier1_duration_str = config.get('escalation', 'tier1_duration', fallback='24h')
        self.tier2_duration_str = config.get('escalation', 'tier2_duration', fallback='30d')
        self.tier1_seconds = parse_duration(self.tier1_duration_str)
        self.tier2_seconds = parse_duration(self.tier2_duration_str)

        # CIDR duration
        self.cidr_duration_str = config.get('cidr', 'duration', fallback='30d')
        self.cidr_seconds = parse_duration(self.cidr_duration_str)

        # Zone to add rules to (default: public)
        self.zone = config.get('firewalld', 'zone', fallback='public')

        # Tear down a blocked source's already-established connections after
        # adding it to the set. Without this, firewalld's early
        # `ct state established,related accept` lets keep-alive floods keep
        # flowing until they close on their own. See modules/conntrack.py.
        self.conntrack = ConntrackFlusher(
            enabled=config.getboolean('firewall', 'flush_conntrack', fallback=True)
        )

        if not self.test_connection():
            raise RuntimeError(
                "firewalld is not installed or not running. "
                "Install/start firewalld or choose a different firewall backend.\n"
                "  Install: yum install firewalld && systemctl enable --now firewalld\n"
                "  Or:      apt install firewalld && systemctl enable --now firewalld"
            )

    def _run_cmd(self, args, timeout=15):
        """Run a firewall-cmd command. Returns (success, stdout, stderr)."""
        cmd = ['firewall-cmd'] + args

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=timeout
            )
            return (result.returncode == 0, result.stdout.strip(), result.stderr.strip())
        except subprocess.TimeoutExpired:
            logger.error(f"firewall-cmd timeout ({timeout}s): {' '.join(args)}")
            return (False, '', 'timeout')
        except FileNotFoundError:
            logger.error("firewall-cmd not found — is firewalld installed?")
            return (False, '', 'not found')
        except Exception as e:
            logger.error(f"firewall-cmd exception: {e}")
            return (False, '', str(e))

    def test_connection(self):
        """Verify firewalld is running."""
        success, stdout, stderr = self._run_cmd(['--state'], timeout=5)
        if success and 'running' in stdout:
            logger.info("firewalld is running")
            return True
        # Also check via systemctl
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', 'firewalld'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=5
            )
            if result.stdout.strip() == 'active':
                logger.info("firewalld is active (via systemctl)")
                return True
        except Exception:
            pass
        logger.error(f"firewalld check failed: {stderr}")
        return False

    # ------------------------------------------------------------------
    # Idempotent treatment of "already exists" / "not found" stderr
    # ------------------------------------------------------------------
    @staticmethod
    def _is_already_set(out, err):
        combined = (out + ' ' + err).lower()
        return (
            'already' in combined
            or 'already_enabled' in combined
            or 'already enabled' in combined
        )

    @staticmethod
    def _is_not_set(out, err):
        combined = (out + ' ' + err).lower()
        return (
            'not_enabled' in combined
            or 'not enabled' in combined
            or 'not found' in combined
            or 'no such' in combined
        )

    # ------------------------------------------------------------------
    # block / unblock — hot path. No --reload, no --permanent on the
    # runtime call (we issue --permanent as a separate persistence call).
    # ------------------------------------------------------------------
    def _add_entry(self, ipset, entry):
        """Add an entry to an ipset at runtime + persist via --permanent.

        Returns True if the runtime entry is in place (the daemon's DB
        is the source of truth for what should be blocked, so a failed
        --permanent leg is logged but does not poison the runtime
        success).
        """
        # Runtime — immediate effect
        rt_ok, rt_out, rt_err = self._run_cmd([
            '--ipset={}'.format(ipset), '--add-entry={}'.format(entry)
        ])
        runtime_ok = rt_ok or self._is_already_set(rt_out, rt_err)
        if not runtime_ok:
            logger.error(
                "firewalld ipset add (runtime) failed for {} -> {}: {}".format(
                    entry, ipset, rt_err
                )
            )
            return False

        # Persistence — survives reboot. Not atomic with the runtime
        # call; the daemon would re-issue on startup anyway via the DB
        # if a reboot dropped us.
        pm_ok, pm_out, pm_err = self._run_cmd([
            '--permanent', '--ipset={}'.format(ipset), '--add-entry={}'.format(entry)
        ])
        if not (pm_ok or self._is_already_set(pm_out, pm_err)):
            logger.warning(
                "firewalld ipset add (permanent) failed for {} -> {}: {} "
                "(runtime entry is in place; reboot may drop it)".format(
                    entry, ipset, pm_err
                )
            )

        return True

    def _remove_entry(self, ipset, entry):
        """Remove an entry from an ipset at runtime + permanent."""
        rt_ok, rt_out, rt_err = self._run_cmd([
            '--ipset={}'.format(ipset), '--remove-entry={}'.format(entry)
        ])
        runtime_ok = rt_ok or self._is_not_set(rt_out, rt_err)
        if not runtime_ok:
            logger.error(
                "firewalld ipset remove (runtime) failed for {} from {}: {}".format(
                    entry, ipset, rt_err
                )
            )
            return False

        pm_ok, pm_out, pm_err = self._run_cmd([
            '--permanent', '--ipset={}'.format(ipset), '--remove-entry={}'.format(entry)
        ])
        if not (pm_ok or self._is_not_set(pm_out, pm_err)):
            logger.warning(
                "firewalld ipset remove (permanent) failed for {} from {}: {} "
                "(runtime entry removed; reboot will resurrect it)".format(
                    entry, ipset, pm_err
                )
            )

        return True

    def _query_entry(self, ipset, entry):
        """Return True if entry is in ipset (runtime view)."""
        success, _, _ = self._run_cmd([
            '--ipset={}'.format(ipset), '--query-entry={}'.format(entry)
        ])
        return success

    def block(self, ip, tier, reason, service='web'):
        """Block an IP by adding it to the wp_guardian_blocked ipset."""
        ok = self._add_entry(IPSET_BLOCKED, ip)
        if ok:
            # Flush AFTER the set add so the re-evaluated NEW packet is dropped.
            torn = self.conntrack.flush_source(ip)
            torn_note = f" (tore down {torn} live conns)" if torn else ""
            logger.info(f"firewalld BLOCKED {ip} tier={tier} reason={reason}{torn_note}")
        return ok

    def unblock(self, ip):
        """Remove an IP from the wp_guardian_blocked ipset."""
        ok = self._remove_entry(IPSET_BLOCKED, ip)
        if ok:
            logger.info(f"firewalld UNBLOCKED {ip}")
        return ok

    def is_blocked(self, ip):
        """Check whether IP is in wp_guardian_blocked."""
        return self._query_entry(IPSET_BLOCKED, ip)

    def block_cidr(self, subnet, reason, service='web', duration='30d'):
        """Block a CIDR subnet by adding it to wp_guardian_cidr."""
        ok = self._add_entry(IPSET_CIDR, subnet)
        if ok:
            torn = self.conntrack.flush_source(subnet)
            torn_note = f" (tore down {torn} live conns)" if torn else ""
            logger.info(f"firewalld CIDR BLOCKED {subnet} reason={reason}{torn_note}")
        return ok

    def is_cidr_blocked(self, subnet):
        """Check whether subnet is in wp_guardian_cidr."""
        return self._query_entry(IPSET_CIDR, subnet)

    def get_block_counts(self):
        """Count entries in the two ipsets."""
        counts = {'ips': 0, 'cidr': 0, 'total': 0}

        for label, ipset in (('ips', IPSET_BLOCKED), ('cidr', IPSET_CIDR)):
            success, stdout, _ = self._run_cmd([
                '--ipset={}'.format(ipset), '--get-entries'
            ])
            if success and stdout:
                counts[label] = sum(1 for line in stdout.splitlines() if line.strip())

        counts['total'] = counts['ips'] + counts['cidr']
        return counts

    # ------------------------------------------------------------------
    # ensure_firewall_rules — idempotent startup setup
    # ------------------------------------------------------------------
    def _permanent_ipsets(self):
        """Return the list of ipset names defined permanently."""
        success, stdout, _ = self._run_cmd(['--permanent', '--get-ipsets'])
        if not success or not stdout:
            return []
        return stdout.split()

    def _permanent_rich_rules(self):
        """Return the list of permanent rich rules in self.zone."""
        success, stdout, _ = self._run_cmd([
            '--permanent', '--zone={}'.format(self.zone), '--list-rich-rules'
        ])
        if not success or not stdout:
            return []
        return [line.strip() for line in stdout.splitlines() if line.strip()]

    def _ensure_ipset(self, name, ipset_type):
        """Create a permanent ipset of the given type if it does not exist.

        Returns True if anything was created (so caller knows a reload
        is needed).
        """
        if name in self._permanent_ipsets():
            return False

        ok, _, err = self._run_cmd([
            '--permanent',
            '--new-ipset={}'.format(name),
            '--type={}'.format(ipset_type),
            '--option=family=inet',
            '--option=hashsize=4096',
            '--option=maxelem=131072',
        ])
        if not ok:
            logger.error(
                "Failed to create firewalld ipset {} (type={}): {}".format(
                    name, ipset_type, err
                )
            )
            return False

        logger.info("Created firewalld ipset {} type={}".format(name, ipset_type))
        return True

    def _ensure_drop_rule(self, ipset):
        """Ensure a permanent drop rich rule referencing the given ipset.

        Returns True if a rule was added (caller should reload).
        """
        rule = 'rule source ipset="{}" drop'.format(ipset)

        # --query-rich-rule returns 0 when present, 1 otherwise.
        present, _, _ = self._run_cmd([
            '--permanent', '--zone={}'.format(self.zone),
            '--query-rich-rule={}'.format(rule),
        ])
        if present:
            return False

        ok, _, err = self._run_cmd([
            '--permanent', '--zone={}'.format(self.zone),
            '--add-rich-rule={}'.format(rule),
        ])
        if not ok:
            logger.error(
                "Failed to add drop rich rule for ipset {} in zone {}: {}".format(
                    ipset, self.zone, err
                )
            )
            return False

        logger.info("Added drop rich rule for ipset {} in zone {}".format(ipset, self.zone))
        return True

    def ensure_firewall_rules(self):
        """Create the two ipsets and the two drop rich rules if missing.

        Reloads firewalld once at the end *only if* anything was
        actually changed. A healthy steady-state startup performs four
        idempotent queries and no reload.
        """
        changed = False
        changed |= self._ensure_ipset(IPSET_BLOCKED, 'hash:ip')
        changed |= self._ensure_ipset(IPSET_CIDR, 'hash:net')
        # Rich rules can only reference ipsets that already exist in the
        # runtime config — reload now if we created any.
        if changed:
            ok, _, err = self._run_cmd(['--reload'])
            if not ok:
                logger.error("firewall-cmd --reload failed after ipset creation: {}".format(err))

        rule_changed = False
        rule_changed |= self._ensure_drop_rule(IPSET_BLOCKED)
        rule_changed |= self._ensure_drop_rule(IPSET_CIDR)
        if rule_changed:
            ok, _, err = self._run_cmd(['--reload'])
            if not ok:
                logger.error("firewall-cmd --reload failed after rich-rule add: {}".format(err))

        logger.info(
            "firewalld backend ready: zone={} ipsets={},{}".format(
                self.zone, IPSET_BLOCKED, IPSET_CIDR
            )
        )

        # Arm-check the conntrack teardown. firewalld accepts established
        # connections before our drop rule, so without conntrack a block only
        # stops NEW connections — existing keep-alive floods keep flowing.
        if self.conntrack.enabled and not self.conntrack.usable:
            logger.warning(
                "[firewall] flush_conntrack is enabled but the 'conntrack' command "
                "is NOT installed — blocks will only stop new connections; an "
                "attacker on HTTP keep-alive keeps flooding until its connections "
                "close. Install it:  dnf install -y conntrack-tools  (RHEL/AlmaLinux) "
                "or  apt install -y conntrack  (Debian/Ubuntu)."
            )
        elif self.conntrack.usable:
            logger.info("conntrack teardown armed — blocks will drop live connections too")
