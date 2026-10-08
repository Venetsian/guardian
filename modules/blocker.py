"""
WP-Guardian Blocker Module
Central decision engine for blocking IPs.
Determines tier, checks whitelist, executes block via the configured firewall backend.
"""

import glob
import gzip
import ipaddress
import logging
import os
import re
import threading
import time
from modules.config import parse_asn_list, parse_duration, parse_service_list

logger = logging.getLogger('wp-guardian.blocker')
block_logger = logging.getLogger('wp-guardian.blocks')

# Operator-facing text for a manual block attempted while the backend is down.
UNAVAILABLE_MSG = "Firewall backend unavailable — not blocked."
# Same situation for /unblock <cidr>: "not blocked" would read as the opposite.
UNAVAILABLE_UNBLOCK_MSG = "Firewall backend unavailable — not unblocked."

# Subnet blocks released per reaper sweep (once an hour). Each release on
# firewalld is two firewall-cmd calls (runtime + permanent), and the first
# sweep after the v1.7.19 upgrade starts with ~700 overdue blocks on one host,
# so an unbounded sweep would stall the main loop. 50/hour drains it in ~14h.
CIDR_REAP_BATCH = 50

# How long a "this /24 holds a whitelisted or friendly IP" decision stands
# before the check is made again (the whitelist can change under us).
CIDR_SKIP_TTL = 3600

# A subnet block logged to blocked.log, plain or manual:
#   2026-05-26 14:03:11 CIDR-BLOCKED subnet=192.0.2.0/24 count=5 duration=30d IPs=...
#   2026-06-01 09:00:00 MANUAL-CIDR-BLOCKED subnet=198.51.100.0/24 duration=perm via=...
# "DRY-RUN CIDR ..." lines do not match: the event name must follow the stamp.
_CIDR_LOG_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?:MANUAL-)?CIDR-BLOCKED subnet=(\S+)(.*)$'
)
_CIDR_LOG_DURATION_RE = re.compile(r'(?:^|\s)duration=(\S+)')


def _norm_net(text):
    """Canonical form of a CIDR string (192.0.2.5/24 -> 192.0.2.0/24)."""
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return text


def _span(seconds):
    # Rounded, not truncated: a block with 2d 23h left reads "in 3d".
    if seconds >= 86400:
        return f"{int(round(seconds / 86400.0))}d"
    if seconds >= 3600:
        return f"{int(round(seconds / 3600.0))}h"
    return f"{max(1, int(round(seconds / 60.0)))}m"


def format_cidr_expiry(expires_at, now=None):
    """'permanent', 'in 12d', 'in 5h' or 'overdue 3d' for a cidr_blocks row."""
    if not expires_at:
        return 'permanent'
    now = time.time() if now is None else now
    delta = int(expires_at - now)
    return f"overdue {_span(-delta)}" if delta <= 0 else f"in {_span(delta)}"


def _fmt_date(ts):
    return time.strftime('%Y-%m-%d', time.localtime(ts))


class Blocker:
    def __init__(self, config, db, whitelist, firewall, telegram, geoip=None):
        self.config = config
        self.db = db
        self.whitelist = whitelist
        self.firewall = firewall
        self.telegram = telegram
        self.geoip = geoip
        self.dry_run = config.getboolean('general', 'dry_run', fallback=False)

        # Parse escalation settings
        self.tier1_duration = config.get('escalation', 'tier1_duration', fallback='24h')
        self.tier2_duration = config.get('escalation', 'tier2_duration', fallback='30d')
        self.tier2_lookback = parse_duration(config.get('escalation', 'tier2_lookback', fallback='7d'))

        # Tier durations in seconds — used to map a manual-block duration
        # ('7d', '48h', ...) onto the nearest escalation tier (the backend
        # owns the actual per-tier TTL).
        try:
            self.tier1_seconds = parse_duration(self.tier1_duration)
        except (ValueError, TypeError):
            self.tier1_seconds = 86400
        try:
            self.tier2_seconds = parse_duration(self.tier2_duration)
        except (ValueError, TypeError):
            self.tier2_seconds = 2592000

        # Block reaper settings (v1.7.9). Tier durations above are what the
        # reaper measures against; these control the sweep itself.
        self.reap_enabled = config.getboolean('escalation', 'reap_enabled', fallback=True)
        self.reap_batch_limit = config.getint('escalation', 'reap_batch_limit', fallback=500)

        # Trusted-ASN enforcement exemption (v1.7.9).
        # Same list the DistributedAuthDetector excludes from evidence — an
        # ASN we refuse to count as proof of compromise must not be firewall-
        # dropped as the attacker either. Scoped to mail services on purpose:
        # ASN 8075 is Microsoft 365 *and* Azure, and an Azure VM scanning
        # wp-login.php is a legitimate block.
        self.trusted_asns = parse_asn_list(
            config.get('compromise_detection', 'trusted_asns',
                       fallback='8075, 15169, 714')
        )
        self.trusted_asn_services = parse_service_list(
            config.get('compromise_detection', 'trusted_asn_services',
                       fallback='smtp, imap, pop3, roundcube')
        )

        # CIDR aggregation settings
        self.cidr_enabled = config.getboolean('cidr', 'enabled', fallback=True)
        self.cidr_threshold = config.getint('cidr', 'threshold', fallback=5)
        self.cidr_duration = config.get('cidr', 'duration', fallback='30d')
        # A subnet that was CIDR-blocked and let go by its duration is blocked
        # again on the first new block inside it, without waiting for the
        # threshold (v1.7.19).
        self.cidr_reblock_repeat = config.getboolean(
            'cidr', 'reblock_repeat_offenders', fallback=True)
        # What is blocked lives in the cidr_blocks table (it used to be an
        # in-memory set, lost on restart, that also kept suppressing
        # re-aggregation after a router had expired the entry). This is only a
        # short-lived "skip this /24" cache for subnets holding a whitelisted or
        # friendly IP: subnet -> time until which the decision stands.
        self._cidr_skip = {}
        # Dry-run dedupe for the "would CIDR block" log line: subnet -> until.
        self._cidr_dry_seen = {}
        # Serialises check-then-record on subnet blocks: the tailer threads,
        # the Telegram thread and the hourly reaper all touch cidr_blocks.
        self._cidr_lock = threading.RLock()

        # Backend name for logging
        self._backend_name = config.get('firewall', 'backend', fallback='csf')

        # Digest buffer (set later by Guardian.__init__). When present,
        # routine blocks (tier 1/2) may be buffered instead of sent immediately.
        self.digest_buffer = None
        # Verbosity router (set later by Guardian.__init__). Decides
        # immediate/digest/silent per rule.
        self.router = None

        # Dedup for trusted-skip alerts: (ip, service) -> last_alert_timestamp.
        # Prevents re-alerting every 5 minutes while a misconfigured client
        # keeps retrying — one heads-up per IP+service per day is enough.
        self._trusted_skip_alerts = {}
        self._trusted_skip_cooldown = 86400  # 24h

        # Same dedupe for trusted-ASN enforcement skips: (ip, service).
        self._trusted_asn_alerts = {}

        # Dry-run dedupe: ip -> time until which a repeat detection is not
        # logged again. A dry run records no tier (see record_simulated_block),
        # so without this every repeat hit from the same attacker would write
        # another block_log row for the whole of the dry run.
        self._dry_run_seen = {}
        self._dry_run_seen_max = 10000

        # Backend-outage bookkeeping. While the firewall backend is missing
        # (failed to initialise, Guardian is retrying) block() cannot enforce
        # anything and records nothing; these counters let Guardian tell the
        # operator afterwards how much went unenforced.
        self.unenforced_count = 0
        self._unenforced_ips = set()
        self._unenforced_lock = threading.Lock()
        self._unenforced_last_log = 0

    def set_digest_buffer(self, digest_buffer):
        """Wire in the digest buffer for alert routing."""
        self.digest_buffer = digest_buffer

    def set_router(self, router):
        """Wire in the verbosity router."""
        self.router = router

    def _route(self, rule, tier, severity):
        """Ask the router, or fall back to always-immediate if none wired."""
        if self.router:
            return self.router.route(rule, tier=tier, severity=severity)
        return 'immediate'

    def block(self, ip, reason, service='web', country='', city='', site='', username='', rule='block',
              force_tier=None, notify=True):
        """
        Main blocking entry point.
        Checks whitelist, determines tier, executes block, records in DB, sends alerts.
        Returns True if blocked, False if skipped.

        force_tier: when set (1/2/3), use this tier instead of the history-based
            escalation AND bypass the "already blocked" early return. Used by
            manual operator blocks (block_manual) to assert/escalate a block.
        notify: when False, the block still executes and is logged/recorded, but
            no Telegram alert/digest is emitted. Manual blocks set this False
            because the caller (Telegram /block reply, CLI --block) surfaces the
            result directly — mirrors how unblock is silent on Telegram.
        """
        # Safety: never block whitelisted IPs
        if self.whitelist.is_whitelisted(ip):
            site_tag = f" site={site}" if site else ""
            logger.info(f"WHITELIST SKIP ip={ip} service={service} reason={reason}{site_tag}")
            return False

        # Geo-enrich. Detector callers don't pass country/city, so without
        # this lookup ip_history rows and Telegram block alerts go out blank.
        geo = None
        if self.geoip and getattr(self.geoip, 'enabled', False):
            try:
                geo = self.geoip.lookup(ip)
            except Exception as e:
                logger.debug(f"GeoIP lookup failed for {ip}: {e}")
                geo = None
        if geo:
            country = country or geo.get('country', '')
            city = city or geo.get('city', '')

        # Make sure IP is tracked in DB
        self.db.track_ip(ip, service, country=country, city=city, geo=geo)

        # Safety: never firewall-drop a cloud mail relay. A manual block
        # (force_tier set) is a deliberate operator decision and overrides this.
        if force_tier is None and self._is_trusted_mail_asn(ip, service, rule, geo):
            return False

        # Already blocked — don't waste a firewall call.
        # A manual block (force_tier set) deliberately bypasses this so the
        # operator can re-assert or escalate an existing block.
        ip_data = self.db.get_ip(ip)
        if force_tier is None and ip_data and ip_data['current_tier'] > 0:
            logger.debug(f"IP {ip} already blocked at tier {ip_data['current_tier']}, skipping")
            return True  # Return True because it IS blocked, just not again

        # Determine escalation tier (force_tier overrides for manual blocks)
        tier = force_tier if force_tier is not None else self.db.determine_tier(ip, self.tier2_lookback)

        # Set duration based on tier
        if tier == 1:
            duration = self.tier1_duration
        elif tier == 2:
            duration = self.tier2_duration
        else:
            duration = 'permanent'

        # Dry run mode. record_simulated_block() keeps a review row in
        # block_log but, unlike record_block(), sets no tier: a tier here would
        # make the next REAL detection of this IP skip as "already blocked".
        if self.dry_run:
            # A manual block (force_tier) is a deliberate act, always logged.
            if force_tier is None and self._dry_run_seen_recently(ip):
                logger.debug(f"[DRY-RUN] {ip} already simulated within "
                             f"{self.tier1_duration}, skipping")
                return True
            logger.info(f"[DRY-RUN] Would block {ip} tier={tier} duration={duration} "
                       f"reason={reason} service={service}")
            block_logger.info(f"DRY-RUN ip={ip} tier={tier} duration={duration} "
                            f"service={service} reason={reason}")
            self.db.record_simulated_block(ip, tier, reason, service, duration)
            self._dry_run_remember(ip)
            return True

        # No backend at all (it failed to initialise and Guardian is retrying).
        # This is an outage, not a dry run: nothing is recorded, because a
        # block_log row or a tier would claim a block that never happened.
        firewall = self.firewall
        if firewall is None:
            self._note_unenforced(ip, reason, service)
            return False

        # Execute block via configured firewall backend
        blocked = firewall.block(ip, tier, reason, service)

        if blocked:
            # Record in database
            self.db.record_block(ip, tier, reason, service, self._backend_name, duration)

            # Write to blocked.log
            site_tag = f" site={site}" if site else ""
            user_tag = f" user={username}" if username else ""
            block_logger.info(f"BLOCKED ip={ip} tier={tier} duration={duration} "
                            f"via={self._backend_name} service={service}{site_tag}{user_tag} reason={reason}")

            # Log to main log
            logger.info(f"BLOCKED {ip} tier={tier} duration={duration} via={self._backend_name} "
                       f"service={service}{site_tag}{user_tag} reason={reason}")

            # Telegram alert routing — delegated to the verbosity router.
            # Tier-3 blocks, compromise, cidr, and block_failed are locked
            # to 'immediate' inside the router (cannot be muted).
            # Skipped entirely for manual blocks (notify=False), where the
            # operator already gets the result via the /block reply or CLI.
            if notify:
                severity = 'high' if tier >= 2 else 'medium'
                event_type = 'tier3_block' if tier >= 3 else 'block'
                level = self._route(rule, tier=tier, severity=severity)
                if level == 'immediate':
                    self.telegram.alert_block(ip, tier, reason, service, country, city, site, username)
                elif level == 'digest' and self.digest_buffer:
                    summary = "T{t} {svc} {ip}: {r}".format(
                        t=tier, svc=service, ip=ip, r=reason[:100]
                    )
                    payload = {
                        'ip': ip, 'tier': tier, 'service': service,
                        'country': country, 'city': city, 'site': site,
                        'reason': reason, 'username': username, 'rule': rule,
                    }
                    self.digest_buffer.queue(event_type, severity, summary, payload=payload)
                # else: silent — block still executes, just no Telegram notification

            # Check if this block pushes a /24 subnet over the CIDR threshold
            if self.cidr_enabled and firewall.supports_cidr:
                self._check_cidr_aggregation(ip, service)
        else:
            logger.error(f"BLOCK FAILED for {ip} via {self._backend_name}")
            block_logger.info(f"FAILED ip={ip} reason={reason} service={service}")
            # Alert on block failure — this is serious
            self.telegram.send(
                f"❌ <b>BLOCK FAILED</b>\n"
                f"IP: <code>{ip}</code>\n"
                f"Reason: {reason}\n"
                f"Backend: {self._backend_name}\n"
                f"Check firewall connectivity!",
                priority='CRITICAL'
            )

        return blocked

    def _dry_run_seen_recently(self, ip):
        expiry = self._dry_run_seen.get(ip)
        return expiry is not None and time.time() < expiry

    def _dry_run_remember(self, ip):
        now = time.time()
        self._dry_run_seen[ip] = now + self.tier1_seconds
        if len(self._dry_run_seen) > self._dry_run_seen_max:
            # Swap rather than delete in place: tailer threads share this dict.
            self._dry_run_seen = {
                k: v for k, v in list(self._dry_run_seen.items()) if v > now
            }

    def _note_unenforced(self, ip, reason, service):
        """Account for a block that could not be enforced: no backend.

        No DB write and no per-event Telegram -- Guardian sends one alert when
        the outage starts and one when it ends. The error log is limited to
        once a minute so a scan burst cannot flood guardian.log.
        """
        now = time.time()
        with self._unenforced_lock:
            self.unenforced_count += 1
            if len(self._unenforced_ips) < 5000:
                self._unenforced_ips.add(ip)
            count = self.unenforced_count
            log_now = now - self._unenforced_last_log >= 60
            if log_now:
                self._unenforced_last_log = now
        if log_now:
            logger.error(
                f"BLOCK NOT ENFORCED: no firewall backend ({self._backend_name} "
                f"unavailable) -- last ip={ip} service={service} reason={reason}; "
                f"{count} unenforced since the outage began"
            )

    def take_unenforced(self):
        """Return (events, distinct_ips) left unenforced by an outage, and reset."""
        with self._unenforced_lock:
            result = (self.unenforced_count, len(self._unenforced_ips))
            self.unenforced_count = 0
            self._unenforced_ips = set()
        return result

    def _is_trusted_mail_asn(self, ip, service, rule, geo):
        """Refuse to block an IP that belongs to a trusted cloud mail relay.

        Closes the asymmetry that broke Outlook for a client: the
        DistributedAuthDetector excludes trusted ASNs from the *evidence*
        (they relay one legitimate user through many DCs), but every
        enforcement path — compromise IP-blocking, SMTP/IMAP/POP3/Roundcube
        brute force — would still firewall-drop them. Microsoft rotates those
        relay IPs, so per-IP whitelisting is whack-a-mole; the ASN is the
        durable key.

        Scoped by service so this cannot be abused as a blanket bypass:
        ASN 8075 is Office 365 *and* Azure, and an Azure VM scanning
        wp-login.php should still be blocked.
        """
        if not self.trusted_asns:
            return False

        service_key = (service or '').lower()
        # Compromise handling inherits the exemption regardless of which
        # service the auth arrived on — it blocks by account, not by protocol.
        if service_key not in self.trusted_asn_services and rule != 'compromise':
            return False

        asn = 0
        if geo:
            try:
                asn = int(geo.get('asn', 0) or 0)
            except (TypeError, ValueError):
                asn = 0
        if asn <= 0:
            # GeoIP disabled or no answer — fall back to whatever ASN we
            # recorded for this IP previously. A relay that has authenticated
            # here before is exactly the case we must not break.
            try:
                asn = self.db.last_known_asn(ip)
            except Exception as e:
                logger.debug(f"last_known_asn lookup failed for {ip}: {e}")
                asn = 0

        if asn <= 0 or asn not in self.trusted_asns:
            return False

        logger.warning(
            f"TRUSTED-ASN SKIP ip={ip} asn={asn} service={service} rule={rule} "
            f"— cloud mail relay, not blocking"
        )
        block_logger.info(
            f"TRUSTED-ASN-SKIP ip={ip} asn={asn} service={service} rule={rule}"
        )
        self._alert_trusted_asn_skip(ip, asn, service, geo)
        return True

    def _alert_trusted_asn_skip(self, ip, asn, service, geo):
        """One Telegram heads-up per (ip, service) per day for an ASN skip.

        Routed through the same 'trusted_skip' verbosity rule as the
        authenticated-IP heads-up — same operator meaning, same mute switch.
        """
        level = self._route('trusted_skip', tier=0, severity='medium')
        if level == 'silent':
            return

        key = (ip, service)
        now = time.time()
        if now - self._trusted_asn_alerts.get(key, 0) < self._trusted_skip_cooldown:
            return
        self._trusted_asn_alerts[key] = now

        org = ''
        if geo:
            org = geo.get('asn_org', '') or ''
        org_line = f" ({org})" if org else ""

        try:
            if level == 'digest' and self.digest_buffer:
                self.digest_buffer.queue(
                    'trusted_skip', 'medium',
                    f"trusted-ASN skip {service} {ip} (AS{asn})",
                    payload={'ip': ip, 'asn': asn, 'asn_org': org,
                             'service': service, 'rule': 'trusted_skip'}
                )
            else:
                self.telegram.send(
                    f"ℹ️ <b>WP-Guardian — trusted-ASN skip</b>\n"
                    f"IP: <code>{ip}</code> is in AS{asn}{org_line},"
                    f" a trusted cloud mail relay, so it was NOT blocked"
                    f" despite tripping a {service.upper()} rule.\n"
                    f"Blocking a relay only cuts off legitimate clients.",
                    priority='MEDIUM'
                )
        except Exception as e:
            logger.debug(f"trusted-ASN skip alert failed: {e}")

    # ------------------------------------------------------------------
    # CIDR (subnet) blocks -- v1.7.19: every block is a cidr_blocks row
    # ------------------------------------------------------------------
    def _expiry_for(self, started, duration):
        """(expires_at, label) for a duration string; expires_at 0 = permanent.

        Falls back to the configured [cidr] duration, then to 30d, for text
        that does not parse -- an old log line or config typo must not leave a
        block with no end date by accident.
        """
        text = (duration or '').strip() or self.cidr_duration
        is_perm, secs = self._resolve_manual_duration(text)
        if is_perm is None:
            text = self.cidr_duration
            is_perm, secs = self._resolve_manual_duration(text)
            if is_perm is None:
                logger.warning(f"Unparseable CIDR duration '{duration}', "
                               f"using 30d")
                text, is_perm, secs = '30d', False, 30 * 86400
        if is_perm:
            return 0, 'permanent'
        return int(started) + secs, text

    def _cidr_skip_active(self, subnet, now):
        until = self._cidr_skip.get(subnet)
        return until is not None and now < until

    def _cidr_skip_remember(self, subnet, now):
        self._cidr_skip[subnet] = now + CIDR_SKIP_TTL
        if len(self._cidr_skip) > 5000:
            # Swap rather than delete in place: tailer threads share this dict.
            self._cidr_skip = {
                k: v for k, v in list(self._cidr_skip.items()) if v > now
            }

    def _check_cidr_aggregation(self, ip, service):
        """After blocking an IP, decide whether its /24 should be blocked too.

        Two triggers: the threshold (cidr_threshold blocked IPs in the /24)
        and, unless reblock_repeat_offenders is off, a repeat offender -- a /24
        that was CIDR-blocked before, ran out its duration, and now has
        another blocked IP. The second needs no count: the range already
        earned one subnet block.
        """
        firewall = self.firewall
        if firewall is None:
            return
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return
        if not isinstance(addr, ipaddress.IPv4Address):
            return
        octets = str(addr).split('.')
        subnet_prefix = '.'.join(octets[:3]) + '.'
        subnet_cidr = subnet_prefix + '0/24'

        with self._cidr_lock:
            alert = self._aggregate_subnet(ip, service, firewall,
                                           subnet_prefix, subnet_cidr)
        # Telegram outside the lock: a slow API must not hold up other threads.
        if alert:
            self._alert_cidr_block(alert)

    def _aggregate_subnet(self, ip, service, firewall, subnet_prefix, subnet_cidr):
        """The body of _check_cidr_aggregation. Returns alert data or None.
        Caller holds self._cidr_lock."""
        now = time.time()

        # Already covered by a live block (the /24 itself, or a wider manual one).
        if self.db.get_active_cidr_covering(ip, now=now):
            return None
        if self._cidr_skip_active(subnet_cidr, now):
            return None

        source = 'auto'
        previous = None
        if self.cidr_reblock_repeat:
            previous = self.db.get_expired_cidr(subnet_cidr)
            if previous is not None:
                source = 'reoffend'
        count = self.db.count_blocked_in_subnet(subnet_prefix)
        if source == 'auto' and count < self.cidr_threshold:
            return None

        # Safety: never block a subnet containing whitelisted IPs
        if self.whitelist.contains_whitelisted_ip(subnet_prefix):
            logger.warning(f"CIDR block skipped for {subnet_cidr} — contains whitelisted IPs")
            self._cidr_skip_remember(subnet_cidr, now)
            return None

        # Safety: never block a subnet containing friendly IPs
        if firewall.supports_friendly_list:
            if firewall.is_friendly_subnet(subnet_cidr):
                logger.warning(f"CIDR block skipped for {subnet_cidr} — contains friendly IPs")
                self._cidr_skip_remember(subnet_cidr, now)
                return None

        # On the firewall already. With no record that is an entry from before
        # v1.7.19 on a backend that expires it by itself: take it over, assuming
        # a full duration (the remaining TTL cannot be read back). With a record
        # it is an overdue one the reaper has not released yet -- leave it.
        if firewall.is_cidr_blocked(subnet_cidr):
            if not self.dry_run and self.db.get_cidr_block(subnet_cidr) is None:
                expires_at, label = self._expiry_for(now, self.cidr_duration)
                self.db.insert_cidr_block(
                    subnet_cidr, expires_at, label, 'adopted',
                    reason='Already on the firewall with no record',
                    service=service, backend=self._backend_name, blocked_at=now)
                logger.info(f"CIDR ADOPTED {subnet_cidr}: already blocked on "
                            f"{self._backend_name}, recorded until "
                            f"{format_cidr_expiry(expires_at, now)}")
            return None

        if source == 'reoffend':
            reason = (f"Repeat offender: {subnet_cidr} was CIDR-blocked "
                      f"{_fmt_date(previous['blocked_at'])}, expired "
                      f"{_fmt_date(previous['ended_at'] or previous['expires_at'])}; "
                      f"{ip} blocked again")
        else:
            reason = f"CIDR aggregation: {count} blocked IPs in {subnet_cidr}"

        if self.dry_run:
            if now >= self._cidr_dry_seen.get(subnet_cidr, 0):
                self._cidr_dry_seen[subnet_cidr] = now + CIDR_SKIP_TTL
                logger.info(f"[DRY-RUN] Would CIDR block {subnet_cidr} ({count} IPs, {source})")
                block_logger.info(f"DRY-RUN CIDR subnet={subnet_cidr} count={count}")
            return None

        # Get the individual IPs for the alert
        blocked_ips = self.db.get_blocked_ips_in_subnet(subnet_prefix)

        # Block the subnet
        cidr_blocked = firewall.block_cidr(
            subnet_cidr, reason, service, self.cidr_duration
        )
        if not cidr_blocked:
            logger.warning(f"CIDR block failed or skipped for {subnet_cidr}")
            return None

        expires_at, label = self._expiry_for(now, self.cidr_duration)
        try:
            self.db.insert_cidr_block(
                subnet_cidr, expires_at, label, source, reason=reason,
                service=service, backend=self._backend_name, blocked_at=now)
        except Exception as e:
            # Enforced but unrecorded: reconcile_cidrs() adopts it (permanent)
            # at the next start on a backend that can list its entries.
            logger.error(f"CIDR block for {subnet_cidr} is on the firewall but "
                         f"could not be recorded: {e}")

        # The import in reconcile_cidrs() parses this line: keep the existing
        # fields as they are and add to the end only.
        block_logger.info(f"CIDR-BLOCKED subnet={subnet_cidr} count={count} "
                        f"duration={self.cidr_duration} IPs={','.join(blocked_ips[:10])} "
                        f"source={source}")
        logger.info(f"CIDR BLOCKED {subnet_cidr} ({count} IPs) "
                    f"duration={self.cidr_duration} source={source}")

        return {'subnet': subnet_cidr, 'source': source, 'count': count,
                'ips': blocked_ips, 'ip': ip, 'previous': previous}

    def _alert_cidr_block(self, info):
        """Telegram alert for a new subnet block.

        'auto' keeps the original always-immediate 'cidr' alert. A repeat
        offender goes through the router under its own rule, so the operator
        can digest it if releasing a backlog of old blocks makes a burst.
        """
        try:
            if info['source'] == 'reoffend':
                level = self._route('cidr_reoffend', tier=0, severity='high')
                if level == 'silent':
                    return
                previous = info['previous']
                if level == 'digest' and self.digest_buffer:
                    self.digest_buffer.queue(
                        'cidr_reoffend', 'high',
                        f"CIDR re-instated {info['subnet']} (repeat offender, {info['ip']})",
                        payload={'subnet': info['subnet'], 'rule': 'cidr_reoffend',
                                 'service': '', 'reason': 'repeat offender'}
                    )
                    return
                self.telegram.send(
                    f"🟣 <b>WP-Guardian — CIDR /24 re-instated: repeat offender</b>\n"
                    f"Subnet: <code>{info['subnet']}</code>\n"
                    f"Blocked before: {_fmt_date(previous['blocked_at'])}, "
                    f"expired {_fmt_date(previous['ended_at'] or previous['expires_at'])}\n"
                    f"Blocked again: <code>{info['ip']}</code>\n"
                    f"Duration: {self.cidr_duration}",
                    priority='HIGH'
                )
                return

            blocked_ips = info['ips']
            ip_sample = ', '.join(blocked_ips[:5])
            if len(blocked_ips) > 5:
                ip_sample += f" (+{len(blocked_ips) - 5} more)"
            self.telegram.send(
                f"🟣 <b>WP-Guardian — CIDR /24 Block</b>\n"
                f"Subnet: <code>{info['subnet']}</code>\n"
                f"Blocked IPs in range: {info['count']}\n"
                f"Duration: {self.cidr_duration}\n"
                f"IPs: {ip_sample}",
                priority='HIGH'
            )
        except Exception as e:
            logger.warning(f"CIDR block alert failed for {info['subnet']}: {e}")

    def alert_trusted_skip(self, ip, service, count, window, username=''):
        """Heads-up Telegram alert when a trusted IP hits a block threshold.

        Fires when an IP with a recent successful auth (within mail_trust_duration)
        crosses a mail/roundcube failure threshold. Instead of blocking, we tell
        the operator so they can call the user about the misconfigured client.

        Deduped: one alert per (ip, service) per 24h — otherwise a client
        retrying in a loop would spam the operator every 5 minutes.
        """
        # Respect verbosity routing — operator can mute or digest these.
        level = self._route('trusted_skip', tier=0, severity='medium')
        if level == 'silent':
            return

        key = (ip, service)
        now = time.time()
        last = self._trusted_skip_alerts.get(key, 0)
        if now - last < self._trusted_skip_cooldown:
            return
        self._trusted_skip_alerts[key] = now

        user_line = f"\nAccount: <code>{username}</code>" if username else ""
        msg = (
            f"ℹ️ <b>WP-Guardian — trusted-IP skip</b>\n"
            f"IP: <code>{ip}</code> had a successful login recently,"
            f" so it's NOT being blocked despite failing {service.upper()} auth"
            f" {count} times in {window}s.{user_line}\n"
            f"Likely a misconfigured mail client. Consider calling the user."
        )
        try:
            if level == 'digest' and self.digest_buffer:
                summary = "trusted-skip {svc} {ip} ({c}/{w}s)".format(
                    svc=service, ip=ip, c=count, w=window
                )
                payload = {
                    'ip': ip, 'service': service, 'username': username,
                    'rule': 'trusted_skip', 'count': count, 'window': window,
                }
                self.digest_buffer.queue('trusted_skip', 'medium', summary, payload=payload)
            else:
                self.telegram.send(msg, priority='MEDIUM')
        except Exception as e:
            logger.debug(f"alert_trusted_skip send failed: {e}")

    def alert_guardian_disabled_skip(self, ip, service, username, count, window):
        """Heads-up when we suppress a block because WE disabled the mailbox.

        Operator-actionable in a way the other skips are not: the account is
        still out of service, and the owner is sitting there watching their
        mail client fail. Deduped per (ip, service) per 24h like the others.
        """
        level = self._route('trusted_skip', tier=0, severity='medium')
        if level == 'silent':
            return

        key = (ip, service, 'guardian-disabled')
        now = time.time()
        if now - self._trusted_skip_alerts.get(key, 0) < self._trusted_skip_cooldown:
            return
        self._trusted_skip_alerts[key] = now

        try:
            if level == 'digest' and self.digest_buffer:
                self.digest_buffer.queue(
                    'trusted_skip', 'medium',
                    f"guardian-disabled skip {service} {ip} ({username})",
                    payload={'ip': ip, 'service': service, 'username': username,
                             'rule': 'trusted_skip', 'count': count, 'window': window}
                )
            else:
                self.telegram.send(
                    f"⚠️ <b>WP-Guardian — disabled mailbox still in use</b>\n"
                    f"Account: <code>{username}</code>\n"
                    f"IP: <code>{ip}</code> (a known client of this account)\n"
                    f"Failed {service.upper()} auth {count}x in {window}s — <b>not blocked</b>,"
                    f" because Guardian disabled this mailbox and those failures are ours.\n"
                    f"Re-enable it or tell the user, or they'll keep retrying forever.",
                    priority='HIGH'
                )
        except Exception as e:
            logger.debug(f"guardian-disabled skip alert failed: {e}")

    def unblock(self, ip):
        """Manually unblock an IP from the firewall.

        Also clears the IP's block history so the next block starts at tier 1.
        Without that, unblocking a false positive armed the next escalation:
        the client retried, got re-blocked, and determine_tier() read the
        block_log row we had just overridden — so every rescue attempt
        promoted the victim one tier, 1 -> 2 -> 3 (permanent).

        Returns True only when the IP is really unblocked (or, in dry-run,
        when it would be). If the backend is missing, raises, or reports
        failure the database is left untouched and this returns False: the
        old behaviour cleared the tier and history anyway and told the
        operator "Unblocked" while the firewall still dropped the client.
        """
        if self.dry_run:
            logger.info(f"[DRY-RUN] would unblock {ip}")
            return True

        if self.firewall is None:
            logger.error(f"UNBLOCK FAILED for {ip}: no firewall backend available")
            return False

        try:
            removed = self.firewall.unblock(ip)
        except Exception as e:
            logger.error(f"UNBLOCK FAILED for {ip} via {self._backend_name}: {e}")
            return False
        if not removed:
            logger.error(f"UNBLOCK FAILED for {ip}: {self._backend_name} reported "
                         f"failure, database state left unchanged")
            return False

        # Reset tier in database
        self.db.conn.execute(
            "UPDATE ip_history SET current_tier = 0 WHERE ip = ?", (ip,)
        )
        self.db.conn.commit()

        cleared = self.db.clear_block_history(ip)

        logger.info(f"UNBLOCKED {ip} (escalation history cleared: {cleared} rows)")
        block_logger.info(f"UNBLOCKED ip={ip} cleared_blocks={cleared}")

        return True

    # ------------------------------------------------------------------
    # Block expiry reaper (v1.7.9)
    # ------------------------------------------------------------------
    def reap_expired_blocks(self, limit=None, dry_run=False):
        """Retire tier-1 / tier-2 blocks whose configured duration has elapsed.

        Nothing enforced block durations before this. Depending on the backend
        that failed in one of two opposite directions:

          * firewalld — the backend documents "the daemon's cleanup loop calls
            unblock() when an entry expires", but no such call existed, and the
            ipsets carry no per-entry timeout. Every "24h" block was permanent.
          * mikrotik / nftables / csf — the firewall expired the entry on its
            own TTL, but ip_history.current_tier stayed >0 forever, so block()
            short-circuited on "already blocked" and a returning attacker was
            never re-pushed.

        One sweep fixes both: unblock() is idempotent, so calling it on an
        already-expired entry is a no-op that still clears the stale tier.

        Returns {'expired': int, 'failed': int, 'remaining': int}.
        """
        if self.firewall is None:
            return {'expired': 0, 'failed': 0, 'remaining': 0}

        # Global dry-run must not issue real unblocks either.
        dry_run = dry_run or self.dry_run

        batch = self.reap_batch_limit if limit is None else int(limit)
        if batch <= 0:
            return {'expired': 0, 'failed': 0, 'remaining': 0}

        try:
            candidates = self.db.get_expired_blocks(
                self.tier1_seconds, self.tier2_seconds, limit=batch
            )
            total = self.db.count_expired_blocks(self.tier1_seconds, self.tier2_seconds)
        except Exception as e:
            logger.error(f"Block reaper query failed: {e}")
            return {'expired': 0, 'failed': 0, 'remaining': 0}

        if not candidates:
            return {'expired': 0, 'failed': 0, 'remaining': 0}

        expired = 0
        failed = 0
        now = time.time()

        # Backends that attach their own per-entry TTL (mikrotik, nftables,
        # csf) have already dropped these entries. There the reaper's whole
        # job is clearing the stale tier — without it, block() short-circuits
        # on "already blocked at tier N" and a returning attacker is never
        # re-pushed, even though the firewall forgot them long ago.
        self_expiring = getattr(self.firewall, 'expires_own_entries', False)

        for entry in candidates:
            ip = entry['ip']
            age_h = int((now - entry['blocked_at']) / 3600)

            if dry_run:
                logger.info(
                    f"[DRY-RUN] Would expire tier-{entry['tier']} block on {ip} "
                    f"(blocked {age_h}h ago, service={entry['service']})"
                )
                expired += 1
                continue

            if self_expiring:
                # The firewall already dropped this entry on its own TTL, so
                # calling unblock() would be a guaranteed no-op — and on
                # MikroTik a no-op costs three SSH round-trips. All that's
                # left to fix is the stale tier in our own table, which is
                # what was silently breaking re-blocking on these backends.
                ok = True
            else:
                try:
                    ok = self.firewall.unblock(ip)
                except Exception as e:
                    logger.error(f"Reaper unblock failed for {ip}: {e}")
                    ok = False

            if not ok:
                # Leave the tier set so the next sweep retries it. A backend
                # that is down must not silently drop blocks from the DB.
                failed += 1
                continue

            # block_log is left untouched on purpose — those rows are the
            # escalation evidence, so a bot that comes back gets tier 2.
            self.db.expire_block_tier(ip)
            expired += 1
            block_logger.info(
                f"EXPIRED ip={ip} tier={entry['tier']} age={age_h}h "
                f"service={entry['service']}"
            )

        remaining = max(0, total - expired)
        if expired or failed:
            how = 'tier reset only, firewall self-expires' if self_expiring \
                else f'unblocked via {self._backend_name}'
            logger.info(
                f"Block reaper: expired {expired} ({how}), failed {failed}, "
                f"{remaining} still pending"
                + (" [DRY-RUN]" if dry_run else "")
            )

        return {'expired': expired, 'failed': failed, 'remaining': remaining}

    # ------------------------------------------------------------------
    # Subnet block expiry reaper (v1.7.19)
    # ------------------------------------------------------------------
    def reap_expired_cidrs(self, limit=None, dry_run=False):
        """Release subnet blocks whose duration has elapsed.

        The CIDR twin of reap_expired_blocks(). firewalld and pfSense cannot
        expire a CIDR entry (block_cidr() ignores the duration), so before this
        a "30d" subnet block stayed in the set for good. mikrotik, nftables and
        csf expire their own entries, so there the sweep only closes the
        record -- which is what makes the subnet a repeat-offender candidate.

        Runs even when [cidr] enabled = false: blocks that exist must still end.
        Permanent rows (expires_at = 0) are never touched. No per-subnet
        Telegram: a backlog would be a flood.

        Returns {'expired': int, 'failed': int, 'remaining': int}.
        """
        firewall = self.firewall
        if firewall is None or not getattr(firewall, 'supports_cidr', False):
            return {'expired': 0, 'failed': 0, 'remaining': 0}

        dry_run = dry_run or self.dry_run

        batch = CIDR_REAP_BATCH if limit is None else int(limit)
        if batch <= 0:
            return {'expired': 0, 'failed': 0, 'remaining': 0}

        now = int(time.time())
        try:
            candidates = self.db.get_overdue_cidr_blocks(now, batch)
            total = self.db.count_overdue_cidr_blocks(now)
        except Exception as e:
            logger.error(f"CIDR reaper query failed: {e}")
            return {'expired': 0, 'failed': 0, 'remaining': 0}

        if not candidates:
            return {'expired': 0, 'failed': 0, 'remaining': 0}

        self_expiring = getattr(firewall, 'expires_own_entries', False)
        expired = 0
        failed = 0

        for rec in candidates:
            subnet = rec['subnet']
            age_d = int((now - rec['blocked_at']) / 86400)

            if dry_run:
                logger.info(
                    f"[DRY-RUN] would expire subnet block {subnet} "
                    f"(blocked {age_d}d ago, source={rec['source']})"
                )
                expired += 1
                continue

            with self._cidr_lock:
                # Re-read under the lock: an operator may have lifted it, or
                # re-applied it with a new duration (a new row), since the
                # candidates were fetched. Releasing the old row then would
                # drop the block that was just renewed.
                current = self.db.get_cidr_block_by_id(rec['id'])
                if current is None or current['status'] != 'active':
                    continue

                if self_expiring:
                    # The firewall dropped it on its own TTL: unblock_cidr()
                    # would be a guaranteed no-op (three SSH round-trips on
                    # MikroTik). It ended when it fell due.
                    ok = True
                    ended_at = rec['expires_at']
                else:
                    try:
                        ok = firewall.unblock_cidr(subnet)
                    except Exception as e:
                        logger.error(f"CIDR reaper unblock failed for {subnet}: {e}")
                        ok = False
                    # It was enforced until this moment.
                    ended_at = int(time.time())

                if not ok:
                    # Leave it active: the next sweep retries. A backend that
                    # is down must not silently drop blocks from the table.
                    failed += 1
                    continue

                self.db.end_cidr_block(rec['id'], 'expired', ended_at=ended_at)
            expired += 1
            block_logger.info(
                f"CIDR-EXPIRED subnet={subnet} age={age_d}d source={rec['source']}"
            )

        remaining = max(0, total - expired)
        how = 'record closed, firewall self-expires' if self_expiring \
            else f'unblocked via {self._backend_name}'
        logger.info(
            f"CIDR reaper: expired {expired} ({how}), failed {failed}, "
            f"{remaining} still pending"
            + (" [DRY-RUN]" if dry_run else "")
        )
        return {'expired': expired, 'failed': failed, 'remaining': remaining}

    # ------------------------------------------------------------------
    # Startup import + reconciliation (v1.7.19)
    # ------------------------------------------------------------------
    def reconcile_cidrs(self, blocked_log_dir, firewall=None):
        """Bring the cidr_blocks table in line with the firewall at startup.

        1. First run after the upgrade (table empty): rebuild the records from
           blocked.log*, one per subnet from its latest event, and tell the
           operator once.
        2. Every start, on a backend that can list its CIDR entries (firewalld):
           adopt entries nobody has a record of as permanent (never auto-release
           what we know nothing about), and re-apply active records that are
           missing from the set. The record is the desired state.

        Never runs in dry-run or without a backend. firewall= lets Guardian
        reconcile a backend BEFORE handing it to the blocker, so no block can
        write a row ahead of the import. Returns a dict of counts.
        """
        result = {'import_ran': False, 'imported': 0, 'active': 0, 'overdue': 0,
                  'expired': 0, 'removed': 0, 'adopted': 0, 'reapplied': 0,
                  'reapply_failed': 0, 'skipped': 0, 'rereleased': 0}
        firewall = firewall if firewall is not None else self.firewall
        if self.dry_run or firewall is None or not getattr(firewall, 'supports_cidr', False):
            return result

        # What does the firewall hold? None means "cannot say" (the backend
        # does not list). A backend that can list but failed raises: acting on
        # a guess would mislabel real blocks as hand-removed, so do nothing
        # this start and try again at the next one.
        try:
            lister = getattr(firewall, 'list_cidr_entries', None)
            raw = lister() if lister is not None else None
        except Exception as e:
            logger.warning(f"CIDR reconcile skipped: could not list the "
                           f"firewall's subnet entries ({e}); will retry at next start")
            return result
        entries = None if raw is None else set(_norm_net(e) for e in raw)

        with self._cidr_lock:
            if self.db.cidr_table_empty():
                result['import_ran'] = True
                self._import_cidr_log(blocked_log_dir, firewall, entries, result)
            if entries is not None:
                self._reconcile_cidr_entries(firewall, entries, result)

        if result['import_ran'] and (result['imported'] or result['adopted']):
            self._alert_cidr_import(result)
        return result

    def _parse_cidr_log(self, log_dir):
        """{subnet: (blocked_at, duration_text)} from blocked.log*, latest event wins."""
        events = {}
        for path in sorted(glob.glob(os.path.join(log_dir, 'blocked.log*'))):
            if not os.path.isfile(path):
                continue
            try:
                if path.endswith('.gz'):
                    handle = gzip.open(path, 'rt', encoding='utf-8', errors='replace')
                else:
                    handle = open(path, 'r', encoding='utf-8', errors='replace')
                with handle:
                    for line in handle:
                        if 'CIDR-BLOCKED' not in line:
                            continue
                        match = _CIDR_LOG_RE.match(line.strip())
                        if not match:
                            continue
                        try:
                            blocked_at = int(time.mktime(
                                time.strptime(match.group(1), '%Y-%m-%d %H:%M:%S')))
                            net = ipaddress.ip_network(match.group(2), strict=False)
                        except (ValueError, OverflowError):
                            continue
                        if not isinstance(net, ipaddress.IPv4Network):
                            continue
                        dur = _CIDR_LOG_DURATION_RE.search(match.group(3))
                        subnet = str(net)
                        if subnet not in events or blocked_at >= events[subnet][0]:
                            events[subnet] = (blocked_at, dur.group(1) if dur else '')
            except Exception as e:
                logger.warning(f"CIDR import: could not read {path}: {e}")
        return events

    def _import_cidr_log(self, log_dir, firewall, entries, result):
        """Create a record for each subnet found in blocked.log*."""
        events = self._parse_cidr_log(log_dir)
        now = int(time.time())
        self_expiring = getattr(firewall, 'expires_own_entries', False)

        try:
            for subnet in sorted(events):
                blocked_at, dur_text = events[subnet]
                expires_at, label = self._expiry_for(blocked_at, dur_text)
                ended_at = 0
                if entries is not None:
                    # firewalld: the set is the truth and never expires anything
                    # by itself, so a missing entry was removed by hand.
                    status = 'active' if subnet in entries else 'removed'
                    ended_at = 0 if status == 'active' else now
                elif self_expiring:
                    if expires_at == 0 or expires_at > now:
                        status = 'active'
                    else:
                        status, ended_at = 'expired', expires_at
                else:
                    # Cannot tell: assume still enforced and let the reaper try
                    # (unblock_cidr is idempotent) when it falls due.
                    status = 'active'
                self.db.insert_cidr_block(
                    subnet, expires_at, label, 'import',
                    reason='Imported from blocked.log', backend=self._backend_name,
                    blocked_at=blocked_at, status=status, ended_at=ended_at,
                    commit=False)
                result['imported'] += 1
                result[status] += 1
                if status == 'active' and 0 < expires_at <= now:
                    result['overdue'] += 1
            self.db.conn.commit()
        except Exception:
            # All or nothing: a half-written import would make the table
            # non-empty and the import would never run again.
            self.db.conn.rollback()
            raise
        logger.info(
            f"CIDR import from {log_dir}: {result['imported']} subnet(s) "
            f"({result['active']} active, {result['overdue']} of them overdue, "
            f"{result['expired']} expired, {result['removed']} removed by hand)"
        )

    def _reconcile_cidr_entries(self, firewall, entries, result):
        """Make the firewall's CIDR set and the active records agree."""
        now = int(time.time())
        records = {}
        for row in self.db.list_active_cidr_blocks():
            records[_norm_net(row['subnet'])] = row

        for entry in sorted(entries):
            if entry in records:
                continue
            try:
                ipaddress.IPv4Network(entry)
            except ValueError:
                logger.warning(f"CIDR reconcile: ignoring unparseable entry "
                               f"'{entry}' in the {self._backend_name} set")
                continue
            # Released by the reaper but back in the set: firewalld removed the
            # runtime entry and failed on the permanent one, and a reload
            # restored it. Adopting it would turn an expired block permanent.
            latest = self.db.get_latest_cidr_record(entry)
            if latest is not None and latest['status'] == 'expired':
                try:
                    ok = firewall.unblock_cidr(entry)
                except Exception as e:
                    logger.error(f"CIDR re-release of {entry} raised: {e}")
                    ok = False
                if ok:
                    result['rereleased'] += 1
                    logger.warning(f"CIDR RE-RELEASED {entry}: expired "
                                   f"{_fmt_date(latest['ended_at'] or latest['expires_at'])} "
                                   f"but back in the {self._backend_name} set")
                else:
                    logger.error(f"CIDR re-release of {entry} failed: it stays "
                                 f"in the set and is retried at the next start")
                continue
            self.db.insert_cidr_block(
                entry, 0, 'permanent', 'adopted',
                reason='In the firewall set at startup with no active record',
                backend=self._backend_name, blocked_at=now)
            result['adopted'] += 1
            logger.warning(f"CIDR ADOPTED {entry}: in the {self._backend_name} set "
                           f"with no record, kept as permanent (lift it with "
                           f"/unblock {entry})")

        for subnet in sorted(records):
            if subnet in entries:
                continue
            row = records[subnet]
            if 0 < row['expires_at'] <= now:
                # Due anyway: the reaper closes it, re-applying would only
                # block the range to release it again.
                result['skipped'] += 1
                continue
            if row['expires_at'] == 0:
                duration = 'permanent'
            else:
                duration = f"{int(row['expires_at'] - now)}s"
            try:
                ok = firewall.block_cidr(
                    row['subnet'], f"Re-applied at startup ({row['source']})",
                    row['service'] or 'web', duration)
            except Exception as e:
                logger.error(f"CIDR re-apply of {subnet} raised: {e}")
                ok = False
            if ok:
                result['reapplied'] += 1
                logger.warning(f"CIDR RE-APPLIED {subnet}: active in the database "
                               f"but missing from the {self._backend_name} set")
            else:
                result['reapply_failed'] += 1
                logger.error(f"CIDR re-apply of {subnet} failed: it stays active "
                             f"and is retried at the next start")

    def _alert_cidr_import(self, result):
        """The one Telegram summary of the first-run import."""
        lines = ["📥 <b>WP-Guardian — subnet blocks imported</b>"]
        if result['imported']:
            lines.append(
                f"Imported {result['imported']} subnet block(s) from blocked.log: "
                f"{result['active']} active (of which {result['overdue']} already past "
                f"expiry, released {CIDR_REAP_BATCH} per hour), "
                f"{result['expired']} expired (repeat-offender watch), "
                f"{result['removed']} removed by hand.")
        if result['adopted']:
            lines.append(f"{result['adopted']} entries of unknown origin found in "
                         f"the firewall, adopted as permanent.")
        message = "\n".join(lines)
        logger.info("CIDR import summary: " + message.replace("\n", " "))
        try:
            self.telegram.send(message, priority='HIGH')
        except Exception as e:
            logger.error(f"CIDR import summary alert failed: {e}")

    # ------------------------------------------------------------------
    # Operator views of subnet blocks (v1.7.19)
    # ------------------------------------------------------------------
    def cidr_cover_note(self, ip):
        """One sentence if an active subnet block covers this IP, else ''.

        /unblock <ip> and /whitelist <ip> lift the per-IP block only; the
        subnet block keeps dropping the address. A backend that cannot expire
        its entries is still enforcing an overdue row until the reaper gets to
        it, so those count there.
        """
        try:
            include_overdue = not getattr(self.firewall, 'expires_own_entries', False)
            row = self.db.get_active_cidr_covering(ip, include_overdue=include_overdue)
        except Exception as e:
            logger.debug(f"cidr_cover_note lookup failed for {ip}: {e}")
            return ''
        if not row:
            return ''
        expiry = row['expires_at']
        if not expiry:
            when = 'permanent'
        elif expiry <= time.time():
            when = f"was due {_fmt_date(expiry)}, release pending"
        else:
            when = f"expires {_fmt_date(expiry)}"
        return (f"Note: {ip} is still covered by subnet block {row['subnet']} "
                f"({when}) — /unblock {row['subnet']} to lift it.")

    def cidr_status_line(self, backend_count=None):
        """'CIDR blocks: N active (P permanent, O overdue) · backend: K · ...'"""
        try:
            counts = self.db.cidr_counts()
        except Exception as e:
            return f"CIDR blocks: unavailable ({e})"
        backend = 'n/a' if backend_count is None else backend_count
        return (f"CIDR blocks: {counts['active']} active "
                f"({counts['permanent']} permanent, {counts['overdue']} overdue) "
                f"· backend: {backend} "
                f"· repeat-offender watch: {counts['watch']}")

    def unblock_cidr_manual(self, subnet, actor='manual'):
        """Lift a subnet block (Telegram /unblock <cidr>, CLI --unblock <cidr>).

        Returns (ok, message) like block_manual(). The record is closed as
        'removed' -- an operator decision, the same as clearing a false
        positive -- so the range is NOT a repeat-offender candidate afterwards.
        A backend failure leaves the record in place: the block is still there.
        """
        subnet = (subnet or '').strip()
        try:
            net = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            return (False, f"Invalid CIDR: {subnet}")
        if not isinstance(net, ipaddress.IPv4Network):
            return (False, f"Only IPv4 CIDRs are supported: {subnet}")
        subnet = str(net)

        if self.dry_run:
            logger.info(f"[DRY-RUN] would unblock subnet {subnet}")
            return (True, f"[DRY-RUN] Would unblock {subnet}. Nothing changed.")

        if self.firewall is None:
            return (False, UNAVAILABLE_UNBLOCK_MSG)

        if not getattr(self.firewall, 'supports_cidr', False):
            return (False, f"Backend '{self._backend_name}' does not support CIDR blocks.")

        with self._cidr_lock:
            record = self.db.get_cidr_block(subnet)
            try:
                removed = self.firewall.unblock_cidr(subnet)
            except Exception as e:
                logger.error(f"CIDR UNBLOCK FAILED for {subnet} via {self._backend_name}: {e}")
                removed = False
            if not removed:
                logger.error(f"CIDR UNBLOCK FAILED for {subnet}: {self._backend_name} "
                             f"reported failure, record left unchanged")
                return (False, f"CIDR unblock FAILED for {subnet} (firewall error). "
                               f"Record left unchanged, it is still blocked.")
            if record is not None:
                self.db.end_cidr_block(record['id'], 'removed')
            cleared = self.db.clear_cidr_memory(subnet)

        block_logger.info(
            f"CIDR-UNBLOCKED subnet={subnet} "
            f"source={record['source'] if record is not None else 'none'} actor={actor}")
        logger.info(f"CIDR UNBLOCKED {subnet} via {self._backend_name} by {actor}")

        if record is not None:
            msg = (f"Unblocked {subnet} (was {record['source']}, "
                   f"{format_cidr_expiry(record['expires_at'])}).")
        elif cleared:
            msg = (f"Cleared {subnet} from the repeat-offender watch "
                   f"(it was not blocked).")
        else:
            msg = f"No record of {subnet}; removed from the firewall if it was there."
            covering = self.db.get_active_cidr_covering(str(net.network_address))
            if covering is not None and covering['subnet'] != subnet:
                msg += (f" Note: still inside subnet block {covering['subnet']} "
                        f"— /unblock {covering['subnet']} to lift it.")
        return (True, msg)

    # ------------------------------------------------------------------
    # Manual (operator-initiated) blocking — Telegram /block and CLI --block
    # ------------------------------------------------------------------
    def block_manual(self, target, duration=None, reason='', service='manual', actor='manual'):
        """Manually block an IP or CIDR range (deliberate operator action).

        target:   IPv4 ('192.0.2.50') or IPv4 CIDR ('192.0.2.0/24').
        duration: None / '' / 'perm' / 'permanent' -> permanent. Otherwise a
                  duration string ('24h', '7d', '30d'). For a single IP this
                  maps to the nearest escalation tier (the backend owns the
                  per-tier TTL); for a CIDR it is passed straight to the backend.
        actor:    free-text label of who issued the block (audit trail).

        Returns (ok: bool, message: str). The message is operator-facing — the
        Telegram handler and CLI surface it verbatim, so manual blocks do NOT
        emit a separate Telegram alert (mirrors --unblock / /unblock). The block
        is still written to blocked.log and guardian.log either way.
        """
        target = (target or '').strip()
        if not target:
            return (False, "No target given. Usage: <ip|cidr> [duration]")
        if not reason:
            reason = f"manual block via {actor}"
        if '/' in target:
            return self._block_cidr_manual(target, duration, reason, service)
        return self._block_ip_manual(target, duration, reason, service)

    def _resolve_manual_duration(self, duration):
        """Map a duration argument to (is_permanent, seconds).

        Returns (True, None) for permanent, (False, seconds) for a finite
        duration, or (None, None) if the string cannot be parsed.
        """
        if duration is None or str(duration).strip() == '':
            return (True, None)  # default: permanent
        d = str(duration).strip().lower()
        if d in ('perm', 'permanent', 'permanently', 'forever', 'inf', 'infinite'):
            return (True, None)
        try:
            secs = parse_duration(d)
        except (ValueError, TypeError):
            return (None, None)
        if not secs or secs <= 0:
            return (None, None)
        return (False, secs)

    def _duration_to_tier(self, is_permanent, seconds):
        """Pick the escalation tier whose TTL covers the requested duration."""
        if is_permanent:
            return 3
        if seconds <= self.tier1_seconds:
            return 1
        if seconds <= self.tier2_seconds:
            return 2
        return 3

    def _tier_label(self, tier):
        labels = {
            1: f"tier 1 ({self.tier1_duration})",
            2: f"tier 2 ({self.tier2_duration})",
            3: "tier 3 (permanent)",
        }
        return labels.get(tier, f"tier {tier}")

    def _block_ip_manual(self, ip, duration, reason, service):
        # Validate IPv4
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return (False, f"Invalid IP address: {ip}")
        if not isinstance(addr, ipaddress.IPv4Address):
            return (False, f"Only IPv4 addresses are supported: {ip}")

        # Never block a whitelisted IP — say so clearly instead of failing quietly.
        if self.whitelist.is_whitelisted(ip):
            return (False, f"{ip} is whitelisted — not blocking. "
                           f"Remove it from the whitelist first.")

        is_perm, seconds = self._resolve_manual_duration(duration)
        if is_perm is None:
            return (False, f"Invalid duration: {duration}. Use 24h, 7d, 30d or perm.")
        tier = self._duration_to_tier(is_perm, seconds)

        # If the IP is already marked blocked, clear the firewall entry first so
        # the new tier/TTL takes effect — and so a stale DB tier (firewall entry
        # already expired) gets re-pushed rather than silently skipped.
        ip_data = self.db.get_ip(ip)
        was_blocked = bool(ip_data and ip_data['current_tier'] > 0)
        if self.firewall is None and not self.dry_run:
            return (False, UNAVAILABLE_MSG)
        if was_blocked and not self.dry_run and self.firewall is not None:
            try:
                self.firewall.unblock(ip)
            except Exception as e:
                logger.warning(f"manual block: pre-unblock of {ip} failed: {e}")

        ok = self.block(ip, reason, service=service, rule='manual',
                        force_tier=tier, notify=False)
        if not ok:
            return (False, f"Block FAILED for {ip} (firewall error). "
                           f"Check backend connectivity.")

        suffix = " (was already blocked — re-applied)" if was_blocked else ""
        prefix = "[DRY-RUN] Would block " if self.dry_run else "Blocked "
        return (True, f"{prefix}{ip} — {self._tier_label(tier)}{suffix}.")

    def _block_cidr_manual(self, subnet, duration, reason, service):
        # Validate CIDR
        try:
            net = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            return (False, f"Invalid CIDR: {subnet}")
        if not isinstance(net, ipaddress.IPv4Network):
            return (False, f"Only IPv4 CIDRs are supported: {subnet}")
        if net.prefixlen < 16:
            return (False, f"Refusing to block {net}: wider than /16 is too "
                           f"broad (collateral risk).")
        subnet = str(net)

        is_perm, seconds = self._resolve_manual_duration(duration)
        if is_perm is None:
            return (False, f"Invalid duration: {duration}. Use 24h, 7d, 30d or perm.")
        duration_str = 'permanent' if is_perm else str(duration).strip().lower()

        # Safety: never blackhole a range that contains a whitelisted IP.
        if self.whitelist.overlaps_cidr(subnet):
            return (False, f"Refusing to block {subnet}: it contains whitelisted IP(s).")

        if self.dry_run:
            block_logger.info(f"DRY-RUN MANUAL-CIDR subnet={subnet} duration={duration_str}")
            return (True, f"[DRY-RUN] Would block {subnet} ({duration_str}).")

        # No working backend (failed to initialise). Not a dry run: say plainly
        # that nothing was blocked instead of pretending it was simulated.
        if self.firewall is None:
            return (False, UNAVAILABLE_MSG)

        if not self.firewall.supports_cidr:
            return (False, f"Backend '{self._backend_name}' does not support CIDR blocks.")

        # Safety: never blackhole a range that contains a firewall-friendly IP.
        if self.firewall.supports_friendly_list and self.firewall.is_friendly_subnet(subnet):
            return (False, f"Refusing to block {subnet}: it contains friendly IP(s).")

        now = int(time.time())
        expires_at = 0 if is_perm else now + seconds
        # A TTL on these backends is fixed when the entry is created, so a new
        # duration means removing the entry and adding it again.
        self_expiring = getattr(self.firewall, 'expires_own_entries', False)

        with self._cidr_lock:
            old = self.db.get_cidr_block(subnet)
            present = old is not None or self.firewall.is_cidr_blocked(subnet)

            if present and self_expiring:
                try:
                    removed = self.firewall.unblock_cidr(subnet)
                except Exception as e:
                    logger.error(f"manual CIDR re-apply: unblock of {subnet} failed: {e}")
                    removed = False
                if not removed:
                    return (False, f"CIDR re-apply FAILED for {subnet}: could not remove "
                                   f"the existing entry (firewall error). Nothing changed.")

            ok = self.firewall.block_cidr(subnet, reason, service, duration_str)
            if not ok:
                if present and self_expiring and old is not None:
                    # We removed it above and could not put it back: it is no
                    # longer blocked, so the record must not claim it is.
                    self.db.end_cidr_block(old['id'], 'removed')
                return (False, f"CIDR block FAILED for {subnet} (firewall error).")

            try:
                if old is not None:
                    self.db.end_cidr_block(old['id'], 'removed')
                self.db.insert_cidr_block(
                    subnet, expires_at, duration_str, 'manual', reason=reason,
                    service=service, backend=self._backend_name, blocked_at=now)
            except Exception as e:
                logger.error(f"manual CIDR block {subnet} is enforced but could "
                             f"not be recorded: {e}")

        block_logger.info(f"MANUAL-CIDR-BLOCKED subnet={subnet} duration={duration_str} "
                          f"via={self._backend_name} reason={reason}")
        logger.info(f"MANUAL CIDR BLOCK {subnet} duration={duration_str} via={self._backend_name}")
        if present:
            return (True, f"Re-applied {subnet} with the new duration ({duration_str}); "
                          f"it was already blocked.")
        return (True, f"Blocked {subnet} ({duration_str}).")
