"""
WP-Guardian Blocker Module
Central decision engine for blocking IPs.
Determines tier, checks whitelist, executes block via the configured firewall backend.
"""

import ipaddress
import logging
import time
from modules.config import parse_asn_list, parse_duration, parse_service_list

logger = logging.getLogger('wp-guardian.blocker')
block_logger = logging.getLogger('wp-guardian.blocks')


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
        # Track already-blocked subnets in memory to avoid repeated checks
        self._blocked_subnets = set()

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

        # Dry run mode
        if self.dry_run:
            logger.info(f"[DRY-RUN] Would block {ip} tier={tier} duration={duration} "
                       f"reason={reason} service={service}")
            block_logger.info(f"DRY-RUN ip={ip} tier={tier} duration={duration} "
                            f"service={service} reason={reason}")
            self.db.record_block(ip, tier, reason, service, 'dry-run', duration)
            return True

        # Execute block via configured firewall backend
        blocked = self.firewall.block(ip, tier, reason, service)

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
            if self.cidr_enabled and self.firewall.supports_cidr:
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

    def _check_cidr_aggregation(self, ip, service):
        """After blocking an IP, check if its /24 subnet should be blocked too."""
        # Extract /24 prefix: "192.0.2.123" -> "192.0.2."
        parts = ip.split('.')
        if len(parts) != 4:
            return
        subnet_prefix = '.'.join(parts[:3]) + '.'
        subnet_cidr = '.'.join(parts[:3]) + '.0/24'

        # Already blocked this subnet in this session?
        if subnet_cidr in self._blocked_subnets:
            return

        # Count blocked IPs in this /24
        count = self.db.count_blocked_in_subnet(subnet_prefix)
        if count < self.cidr_threshold:
            return

        # Check if already blocked on the firewall
        if self.firewall.is_cidr_blocked(subnet_cidr):
            self._blocked_subnets.add(subnet_cidr)
            return

        # Safety: never block a subnet containing whitelisted IPs
        if self.whitelist.contains_whitelisted_ip(subnet_prefix):
            logger.warning(f"CIDR block skipped for {subnet_cidr} — contains whitelisted IPs")
            self._blocked_subnets.add(subnet_cidr)
            return

        # Safety: never block a subnet containing friendly IPs
        if self.firewall.supports_friendly_list:
            if self.firewall.is_friendly_subnet(subnet_cidr):
                logger.warning(f"CIDR block skipped for {subnet_cidr} — contains friendly IPs")
                self._blocked_subnets.add(subnet_cidr)
                return

        # Get the individual IPs for the alert
        blocked_ips = self.db.get_blocked_ips_in_subnet(subnet_prefix)

        reason = f"CIDR aggregation: {count} blocked IPs in {subnet_cidr}"

        if self.dry_run:
            logger.info(f"[DRY-RUN] Would CIDR block {subnet_cidr} ({count} IPs)")
            block_logger.info(f"DRY-RUN CIDR subnet={subnet_cidr} count={count}")
            self._blocked_subnets.add(subnet_cidr)
            return

        # Block the subnet
        cidr_blocked = self.firewall.block_cidr(
            subnet_cidr, reason, service, self.cidr_duration
        )

        if cidr_blocked:
            self._blocked_subnets.add(subnet_cidr)

            block_logger.info(f"CIDR-BLOCKED subnet={subnet_cidr} count={count} "
                            f"duration={self.cidr_duration} IPs={','.join(blocked_ips[:10])}")
            logger.info(f"CIDR BLOCKED {subnet_cidr} ({count} IPs) duration={self.cidr_duration}")

            # Telegram alert
            ip_sample = ', '.join(blocked_ips[:5])
            if len(blocked_ips) > 5:
                ip_sample += f" (+{len(blocked_ips) - 5} more)"
            self.telegram.send(
                f"🟣 <b>WP-Guardian — CIDR /24 Block</b>\n"
                f"Subnet: <code>{subnet_cidr}</code>\n"
                f"Blocked IPs in range: {count}\n"
                f"Duration: {self.cidr_duration}\n"
                f"IPs: {ip_sample}",
                priority='HIGH'
            )
        else:
            logger.warning(f"CIDR block failed or skipped for {subnet_cidr}")

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
        """
        self.firewall.unblock(ip)

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
            logger.info(
                f"Block reaper: expired {expired}, failed {failed}, "
                f"{remaining} still pending"
                + (" [DRY-RUN]" if dry_run else "")
            )

        return {'expired': expired, 'failed': failed, 'remaining': remaining}

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

        # Dry-run, or no working backend (firewall failed to init at startup).
        if self.dry_run or self.firewall is None:
            block_logger.info(f"DRY-RUN MANUAL-CIDR subnet={subnet} duration={duration_str}")
            return (True, f"[DRY-RUN] Would block {subnet} ({duration_str}).")

        if not self.firewall.supports_cidr:
            return (False, f"Backend '{self._backend_name}' does not support CIDR blocks.")

        # Safety: never blackhole a range that contains a firewall-friendly IP.
        if self.firewall.supports_friendly_list and self.firewall.is_friendly_subnet(subnet):
            return (False, f"Refusing to block {subnet}: it contains friendly IP(s).")

        if self.firewall.is_cidr_blocked(subnet):
            self._blocked_subnets.add(subnet)
            return (True, f"{subnet} is already blocked.")

        ok = self.firewall.block_cidr(subnet, reason, service, duration_str)
        if not ok:
            return (False, f"CIDR block FAILED for {subnet} (firewall error).")

        self._blocked_subnets.add(subnet)
        block_logger.info(f"MANUAL-CIDR-BLOCKED subnet={subnet} duration={duration_str} "
                          f"via={self._backend_name} reason={reason}")
        logger.info(f"MANUAL CIDR BLOCK {subnet} duration={duration_str} via={self._backend_name}")
        return (True, f"Blocked {subnet} ({duration_str}).")
