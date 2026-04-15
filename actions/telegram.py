"""
WP-Guardian Telegram Module
Sends alerts via Telegram bot API.
"""

import logging
import time
import threading

logger = logging.getLogger('wp-guardian.telegram')

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class TelegramAlerter:
    def __init__(self, config):
        self.enabled = config.getboolean('telegram', 'enabled', fallback=False)
        self.bot_token = config.get('telegram', 'bot_token', fallback='')
        self.chat_id = config.get('telegram', 'chat_id', fallback='')
        self.max_per_minute = config.getint('telegram', 'max_alerts_per_minute', fallback=10)

        # Rate limiting
        self._sent_timestamps = []
        self._lock = threading.Lock()

        if self.enabled:
            if not HAS_REQUESTS:
                logger.error("Telegram enabled but 'requests' module not installed. pip install requests")
                self.enabled = False
            elif not self.bot_token or not self.chat_id:
                logger.error("Telegram enabled but bot_token or chat_id not configured")
                self.enabled = False
            else:
                logger.info("Telegram alerting enabled")

    def _rate_limited(self):
        """Check if we've exceeded the rate limit."""
        now = time.time()
        with self._lock:
            # Remove timestamps older than 60 seconds
            self._sent_timestamps = [t for t in self._sent_timestamps if now - t < 60]
            if len(self._sent_timestamps) >= self.max_per_minute:
                return True
            self._sent_timestamps.append(now)
            return False

    def send(self, message, priority='INFO'):
        """Send a Telegram message."""
        if not self.enabled:
            logger.debug(f"Telegram disabled, would send: {message[:100]}...")
            return False

        if self._rate_limited():
            logger.warning("Telegram rate limit reached, dropping alert")
            return False

        try:
            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML',
                'disable_web_page_preview': True
            }

            response = requests.post(url, json=payload, timeout=10)

            if response.status_code == 200:
                logger.debug(f"Telegram alert sent ({priority})")
                return True
            else:
                logger.error(f"Telegram API error {response.status_code}: {response.text}")
                return False

        except requests.Timeout:
            logger.error("Telegram send timeout")
            return False
        except Exception as e:
            logger.error(f"Telegram send error: {e}")
            return False

    # ------------------------------------------------------------------
    # Pre-formatted alert methods
    # ------------------------------------------------------------------
    def alert_block(self, ip, tier, reason, service, country='', city='', site=''):
        """Alert about a new block."""
        tier_emoji = {1: '🟡', 2: '🟠', 3: '🔴'}
        tier_label = {1: '24h block', 2: '30-day block', 3: 'PERMANENT block'}

        location = ''
        if country:
            location = f"\n📍 Location: {city}, {country}" if city else f"\n📍 Location: {country}"

        site_line = f"\nSite: {site}" if site else ""

        msg = (
            f"{tier_emoji.get(tier, '⚪')} <b>WP-Guardian — Tier {tier} ({tier_label.get(tier, 'block')})</b>\n"
            f"IP: <code>{ip}</code>{location}\n"
            f"Service: {service}{site_line}\n"
            f"Reason: {reason}"
        )
        self.send(msg, priority='HIGH' if tier >= 2 else 'MEDIUM')

    def alert_geo_anomaly(self, username, service, ip, country, city, expected_countries):
        """Alert about geographic anomaly."""
        expected = ', '.join(expected_countries) if expected_countries else 'unknown'
        location = f"{city}, {country}" if city else country

        msg = (
            f"🔴 <b>CRITICAL — Geographic Anomaly</b>\n"
            f"Account: <code>{username}</code>\n"
            f"Service: {service}\n"
            f"Login from: {location} (<code>{ip}</code>)\n"
            f"Known locations: {expected}\n"
            f"⚠️ Possible account compromise"
        )
        self.send(msg, priority='CRITICAL')

    def alert_impossible_travel(self, username, service, ip1, loc1, ip2, loc2, time_diff_minutes):
        """Alert about impossible travel."""
        msg = (
            f"🔴 <b>CRITICAL — Impossible Travel</b>\n"
            f"Account: <code>{username}</code>\n"
            f"Service: {service}\n"
            f"Login 1: {loc1} (<code>{ip1}</code>)\n"
            f"Login 2: {loc2} (<code>{ip2}</code>)\n"
            f"Time between: {time_diff_minutes} minutes\n"
            f"⚠️ Credential compromise likely"
        )
        self.send(msg, priority='CRITICAL')

    def alert_client_suspicious(self, ip, site, action, detail):
        """Alert about suspicious authenticated user activity."""
        msg = (
            f"⚠️ <b>Suspicious Client Activity</b>\n"
            f"Site: {site}\n"
            f"IP: <code>{ip}</code> (authenticated user)\n"
            f"Action: {action}\n"
            f"Detail: {detail}"
        )
        self.send(msg, priority='MEDIUM')

    def alert_smtp_spam(self, username, ip, count, timeframe_minutes):
        """Alert about possible SMTP spam."""
        msg = (
            f"🔴 <b>CRITICAL — SMTP Spam Detected</b>\n"
            f"Account: <code>{username}</code>\n"
            f"IP: <code>{ip}</code>\n"
            f"Emails sent: {count} in {timeframe_minutes} minutes\n"
            f"⚠️ Account may be compromised. Consider disabling."
        )
        self.send(msg, priority='CRITICAL')

    def alert_compromise(self, username, service, trigger_rule, counts,
                         ips_blocked, mailbox_disabled, event_id):
        """Alert about a detected credential compromise (v1.4+).

        Always sent immediately — never digested.
        """
        trigger_labels = {
            'countries': 'distinct countries',
            'asns': 'distinct ASNs',
            'ips': 'distinct IPs',
        }
        label = trigger_labels.get(trigger_rule, trigger_rule)
        trigger_count = counts.get(trigger_rule, 0)

        disable_line = "✅ disabled" if mailbox_disabled else "⚠️ NOT disabled (disable manually)"

        msg = (
            "🔴 <b>COMPROMISE DETECTED</b>\n"
            "Account: <code>{user}</code>\n"
            "Service: {svc}\n"
            "Trigger: {tc} {label} in the last window\n"
            "Distinct IPs: {ips}\n"
            "Distinct countries: {countries}\n"
            "Distinct ASNs: {asns}\n"
            "\n"
            "IPs blocked: {b}\n"
            "Mailbox: {dl}\n"
            "Event ID: {eid}\n"
            "\n"
            "Review: <code>wp-guardian.py --auth-map {user}</code>"
        ).format(
            user=username, svc=service,
            tc=trigger_count, label=label,
            ips=counts.get('ips', 0),
            countries=counts.get('countries', 0),
            asns=counts.get('asns', 0),
            b=ips_blocked,
            dl=disable_line,
            eid=event_id,
        )
        self.send(msg, priority='CRITICAL')

    def alert_daily_summary(self, stats):
        """Send daily summary."""
        msg = (
            f"📊 <b>WP-Guardian Daily Summary</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"Blocks today: {stats.get('total_blocks_today', 0)}\n"
            f"Active Tier 1: {stats.get('active_tier1', 0)}\n"
            f"Active Tier 2: {stats.get('active_tier2', 0)}\n"
            f"Active Tier 3: {stats.get('active_tier3', 0)}\n"
            f"IPs tracked: {stats.get('total_ips_tracked', 0)}\n"
            f"Auth sessions today: {stats.get('auth_sessions_today', 0)}\n"
            f"Active tripwires: {stats.get('tripwire_count', 0)}"
        )
        self.send(msg, priority='INFO')
