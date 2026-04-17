"""
WP-Guardian CompromiseAction Module (v1.4+)

Orchestrates the response when a credential compromise is detected:
  - record the event
  - (optionally) block all distinct attacker IPs in the window
  - (optionally) disable the mailbox in the mail backend
  - send an IMMEDIATE Telegram alert

Valid action modes:
    alert_only       — record event + alert, do nothing else
    block_ips        — alert + block IPs
    disable_mailbox  — alert + disable mailbox
    full             — alert + block IPs + disable mailbox  (default)
"""

import logging

logger = logging.getLogger('wp-guardian.compromise')


VALID_ACTIONS = ('alert_only', 'block_ips', 'disable_mailbox', 'full')


class CompromiseAction:
    def __init__(self, config, db, blocker, mail_backend, telegram):
        self.config = config
        self.db = db
        self.blocker = blocker
        self.mail_backend = mail_backend  # may be None or disabled
        self.telegram = telegram

        self.action = config.get(
            'compromise_detection', 'action', fallback='full'
        ).strip().lower()
        if self.action not in VALID_ACTIONS:
            logger.warning(
                "Invalid compromise_detection.action '{a}', falling back to 'alert_only'".format(a=self.action)
            )
            self.action = 'alert_only'

    def handle(self, username, service, trigger_rule, counts,
               window_seconds, actor='auto:DistributedAuthDetector'):
        """Main entry point called by the detector.

        Returns the compromise_events row id.
        """
        try:
            attacker_ips = self.db.recent_auth_ips(username, window_seconds)
            sample_countries = self.db.recent_auth_countries(username, window_seconds)

            event_id = self.db.insert_compromise_event(
                username=username,
                service=service,
                trigger_rule=trigger_rule,
                counts=counts,
                window_seconds=window_seconds,
                sample_ips=attacker_ips[:20],
                sample_countries=sample_countries,
                action_taken='pending',
            )
        except Exception as e:
            logger.error("Failed to record compromise event: {e}".format(e=e))
            return 0

        ips_blocked = 0
        mailbox_disabled = False

        # Block attacker IPs
        if self.action in ('block_ips', 'full'):
            ips_blocked = self._block_ips(attacker_ips, username, service, event_id)

        # Disable mailbox
        if self.action in ('disable_mailbox', 'full'):
            if self.mail_backend and getattr(self.mail_backend, 'enabled', False):
                mailbox_disabled = self._disable_mailbox(username, event_id, actor)
            else:
                logger.warning(
                    "Cannot auto-disable {u}: mail_backend not configured".format(u=username)
                )

        # Persist outcome
        try:
            self.db.update_compromise_event(event_id, {
                'mailbox_disabled': 1 if mailbox_disabled else 0,
                'ips_blocked_count': ips_blocked,
                'action_taken': self._summarize(ips_blocked, mailbox_disabled),
            })
        except Exception as e:
            logger.error("Failed to update compromise event {i}: {e}".format(i=event_id, e=e))

        # Send immediate alert — compromise events are ALWAYS immediate
        try:
            if hasattr(self.telegram, 'alert_compromise'):
                self.telegram.alert_compromise(
                    username=username,
                    service=service,
                    trigger_rule=trigger_rule,
                    counts=counts,
                    ips_blocked=ips_blocked,
                    mailbox_disabled=mailbox_disabled,
                    event_id=event_id,
                )
            else:
                self.telegram.send(
                    "🔴 <b>COMPROMISE DETECTED</b>\n"
                    "Account: <code>{u}</code>\n"
                    "Trigger: {r}\n"
                    "IPs blocked: {b}\n"
                    "Mailbox disabled: {m}\n"
                    "Event id: {i}".format(
                        u=username, r=trigger_rule,
                        b=ips_blocked, m=mailbox_disabled, i=event_id
                    ),
                    priority='CRITICAL'
                )
        except Exception as e:
            logger.error("Failed to send compromise alert: {e}".format(e=e))

        logger.warning(
            "COMPROMISE {u} service={s} trigger={r} ips={c} blocked={b} mailbox_disabled={m} event_id={i}".format(
                u=username, s=service, r=trigger_rule,
                c=counts, b=ips_blocked, m=mailbox_disabled, i=event_id
            )
        )

        return event_id

    def _block_ips(self, ips, username, service, event_id):
        """Block each attacker IP via the blocker. Returns count blocked."""
        blocked = 0
        reason = "Compromise of {u} (event {i})".format(u=username, i=event_id)
        for ip in ips:
            try:
                if self.blocker.block(ip, reason, service=service or 'smtp',
                                      username=username, rule='compromise'):
                    blocked += 1
            except Exception as e:
                logger.error("Failed to block {ip}: {e}".format(ip=ip, e=e))
        return blocked

    def _disable_mailbox(self, username, event_id, actor):
        """Call mail_backend.disable_mailbox and record the audit row."""
        try:
            changed = self.mail_backend.disable_mailbox(username)
            self.db.insert_mailbox_action(
                username=username,
                action='disable',
                actor=actor,
                reason="compromise event {i}".format(i=event_id),
                related_compromise_id=event_id,
                success=True,
            )
            if not changed:
                logger.info(
                    "Mailbox disable for {u}: no row changed (already disabled or missing)".format(u=username)
                )
                return False
            return True
        except Exception as e:
            logger.error("Failed to disable mailbox {u}: {e}".format(u=username, e=e))
            self.db.insert_mailbox_action(
                username=username,
                action='disable',
                actor=actor,
                reason="compromise event {i}".format(i=event_id),
                related_compromise_id=event_id,
                success=False,
                error_message=str(e),
            )
            # Send separate alert — this failure is operator-actionable
            try:
                self.telegram.send(
                    "❌ <b>MAILBOX DISABLE FAILED</b>\n"
                    "Account: <code>{u}</code>\n"
                    "Event id: {i}\n"
                    "Error: {e}\n"
                    "Log in and disable manually.".format(
                        u=username, i=event_id, e=str(e)[:200]
                    ),
                    priority='CRITICAL'
                )
            except Exception:
                pass
            return False

    @staticmethod
    def _summarize(ips_blocked, mailbox_disabled):
        if ips_blocked and mailbox_disabled:
            return 'full'
        if mailbox_disabled:
            return 'mailbox_disabled'
        if ips_blocked:
            return 'ips_blocked'
        return 'alert_only'
