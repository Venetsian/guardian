"""
WP-Guardian Blocker Module
Central decision engine for blocking IPs.
Determines tier, checks whitelist, executes block via the configured firewall backend.
"""

import logging
import time
from modules.config import parse_duration

logger = logging.getLogger('wp-guardian.blocker')
block_logger = logging.getLogger('wp-guardian.blocks')


class Blocker:
    def __init__(self, config, db, whitelist, firewall, telegram):
        self.config = config
        self.db = db
        self.whitelist = whitelist
        self.firewall = firewall
        self.telegram = telegram
        self.dry_run = config.getboolean('general', 'dry_run', fallback=False)

        # Parse escalation settings
        self.tier1_duration = config.get('escalation', 'tier1_duration', fallback='24h')
        self.tier2_duration = config.get('escalation', 'tier2_duration', fallback='30d')
        self.tier2_lookback = parse_duration(config.get('escalation', 'tier2_lookback', fallback='7d'))

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

    def block(self, ip, reason, service='web', country='', city='', site='', username='', rule='block'):
        """
        Main blocking entry point.
        Checks whitelist, determines tier, executes block, records in DB, sends alerts.
        Returns True if blocked, False if skipped.
        """
        # Safety: never block whitelisted IPs
        if self.whitelist.is_whitelisted(ip):
            site_tag = f" site={site}" if site else ""
            logger.info(f"WHITELIST SKIP ip={ip} service={service} reason={reason}{site_tag}")
            return False

        # Make sure IP is tracked in DB
        self.db.track_ip(ip, service, country, city)

        # Already blocked — don't waste a firewall call
        ip_data = self.db.get_ip(ip)
        if ip_data and ip_data['current_tier'] > 0:
            logger.debug(f"IP {ip} already blocked at tier {ip_data['current_tier']}, skipping")
            return True  # Return True because it IS blocked, just not again

        # Determine escalation tier
        tier = self.db.determine_tier(ip, self.tier2_lookback)

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

    def unblock(self, ip):
        """Manually unblock an IP from the firewall."""
        self.firewall.unblock(ip)

        # Reset tier in database
        self.db.conn.execute(
            "UPDATE ip_history SET current_tier = 0 WHERE ip = ?", (ip,)
        )
        self.db.conn.commit()
        logger.info(f"UNBLOCKED {ip}")
        block_logger.info(f"UNBLOCKED ip={ip}")

        return True
