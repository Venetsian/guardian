"""
WP-Guardian Alert Digest Module (v1.4+)

Implements the digest/quiet alert modes. Low-priority events
(routine tier-1/tier-2 blocks) are buffered in the SQLite
`alert_digest_buffer` table and flushed as a single Telegram
summary message every `digest_interval` seconds.

High-priority events (compromise, tier-3, CIDR /24, BLOCK FAILED)
bypass the buffer and are always sent immediately.
"""

import json
import logging
import time
from collections import Counter

logger = logging.getLogger('wp-guardian.digest')


VALID_MODES = ('verbose', 'digest', 'quiet')


class DigestBuffer:
    def __init__(self, config, db, telegram, hostname=None):
        self.db = db
        self.telegram = telegram
        self.hostname = hostname or ''

        self.mode = config.get(
            'telegram', 'alert_mode', fallback='verbose'
        ).strip().lower()
        if self.mode not in VALID_MODES:
            logger.warning("Invalid alert_mode '{m}', falling back to 'verbose'".format(m=self.mode))
            self.mode = 'verbose'

        self.interval = config.getint('telegram', 'digest_interval', fallback=3600)
        self.max_events = config.getint('telegram', 'digest_max_events', fallback=50)
        self._last_flush = time.time()

        logger.info("Alert mode: {m} (digest_interval={i}s)".format(m=self.mode, i=self.interval))

    def is_immediate(self, event_type, severity):
        """Decide whether an event should be sent immediately or buffered.

        High-priority events always go immediately regardless of mode.
        """
        severity = (severity or 'medium').lower()
        event_type = (event_type or '').lower()

        # Always-immediate events (any mode)
        always_immediate = {
            'compromise', 'block_failed', 'mailbox_disable_failed',
            'cidr_block', 'tier3_block',
        }
        if event_type in always_immediate:
            return True
        if severity == 'critical':
            return True

        if self.mode == 'verbose':
            return True
        if self.mode == 'digest':
            # tier-1/tier-2 blocks go to digest
            return False
        if self.mode == 'quiet':
            return False

        return True

    def queue(self, event_type, severity, summary, payload=None):
        """Buffer an event. No-op for events that should be immediate."""
        if self.is_immediate(event_type, severity):
            return False
        try:
            self.db.digest_queue(event_type, severity, summary, payload=payload)
            return True
        except Exception as e:
            logger.error("Digest queue error: {e}".format(e=e))
            return False

    def flush_if_due(self, force=False):
        """Called from the Guardian periodic loop."""
        if self.mode == 'verbose':
            return
        now = time.time()
        if not force and (now - self._last_flush) < self.interval:
            return

        try:
            pending = self.db.digest_pending(max_events=max(self.max_events, 100))
        except Exception as e:
            logger.error("Digest read error: {e}".format(e=e))
            return

        if not pending:
            self._last_flush = now
            return

        try:
            message = self._format_digest(pending)
            if self.telegram and getattr(self.telegram, 'enabled', False):
                self.telegram.send(message, priority='INFO')
            else:
                logger.info("Digest ready but Telegram disabled; dropping {n} events".format(n=len(pending)))
            ids = [row['id'] for row in pending]
            self.db.digest_mark_flushed(ids)
        except Exception as e:
            logger.error("Digest flush error: {e}".format(e=e))
            return

        self._last_flush = now

    def _format_digest(self, rows):
        """Build the Telegram HTML digest body."""
        total = len(rows)
        hours = max(1, int(round((time.time() - rows[0]['queued_at']) / 3600.0)))

        # Tally by tier (from payload)
        tier_counts = Counter()
        service_counts = Counter()
        ip_counts = Counter()
        ip_meta = {}
        account_counts = Counter()

        for row in rows:
            payload = {}
            if row['payload_json']:
                try:
                    payload = json.loads(row['payload_json'])
                except Exception:
                    payload = {}
            tier = payload.get('tier')
            service = payload.get('service', '')
            ip = payload.get('ip', '')
            account = payload.get('account', '')
            country = payload.get('country', '')
            city = payload.get('city', '')

            if tier:
                tier_counts[tier] += 1
            if service:
                service_counts[service] += 1
            if ip:
                ip_counts[ip] += 1
                if ip not in ip_meta and (country or city):
                    ip_meta[ip] = "{ct}/{cy}".format(ct=country, cy=city).strip('/')
            if account:
                account_counts[account] += 1

        host_bit = " on {h}".format(h=self.hostname) if self.hostname else ""
        lines = [
            "🛡 <b>WP-Guardian Digest — last {h}h{host}</b>".format(h=hours, host=host_bit),
            "",
            "<b>{n} blocks</b>".format(n=total),
        ]

        if tier_counts:
            tier_bits = []
            for tier in sorted(tier_counts.keys()):
                tier_bits.append("{c} tier-{t}".format(c=tier_counts[tier], t=tier))
            lines.append("({tb})".format(tb=", ".join(tier_bits)))

        if service_counts:
            lines.append("")
            lines.append("<b>By service:</b>")
            for svc, count in service_counts.most_common(6):
                lines.append("  • {s}: {c}".format(s=svc, c=count))

        if ip_counts:
            lines.append("")
            lines.append("<b>Top offender IPs:</b>")
            for ip, count in ip_counts.most_common(5):
                meta = ip_meta.get(ip, '')
                meta_str = " ({m})".format(m=meta) if meta else ""
                lines.append("  • <code>{ip}</code> ({c} blocks){m}".format(ip=ip, c=count, m=meta_str))

        if account_counts:
            lines.append("")
            lines.append("<b>Top targeted accounts:</b>")
            for account, count in account_counts.most_common(5):
                lines.append("  • {a} ({c} attempts)".format(a=account, c=count))

        if total > self.max_events:
            lines.append("")
            lines.append("...(+{n} more)".format(n=total - self.max_events))

        return "\n".join(lines)
