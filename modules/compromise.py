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

Enforcement is resolved PER TRIGGER RULE (v1.7.11+): `action_<rule>` wins over
the global `action`. See RULE_ACTION_DEFAULTS for why `asns` ships weaker.
"""

import logging
import time

from modules.config import parse_asn_list

logger = logging.getLogger('wp-guardian.compromise')


VALID_ACTIONS = ('alert_only', 'block_ips', 'disable_mailbox', 'full')

# Tolerated spelling — the obvious short form for alert_only.
ACTION_ALIASES = {'alert': 'alert_only'}

# Rules whose default enforcement is deliberately weaker than the global
# `action`. Anything absent here inherits `action`.
#
# `asns` has fired twice in production and been wrong both times
# (carol@example.org 2026-07-31, bob@example.net 2026-08-09), each
# landing on exactly 5 of 5 ASNs inside one country. Both were multi-homed
# users on US consumer carriers — a phone roaming between AT&T pools plus two
# rural ILECs reaches five ASNs without anything unusual happening. A single
# country cannot corroborate a distributed-abuse story; the `countries` rule
# is the one that caught the only real compromise on record (28 countries /
# 39 ASNs), and it keeps full enforcement.
#
# This is a code default, not just a config default, so an existing install
# gets the protection on `git pull` + restart without editing its config.
# An explicit action_asns= in the config still wins.
RULE_ACTION_DEFAULTS = {
    'asns': 'alert_only',
}


class CompromiseAction:
    def __init__(self, config, db, blocker, mail_backend, telegram):
        self.config = config
        self.db = db
        self.blocker = blocker
        self.mail_backend = mail_backend  # may be None or disabled
        self.telegram = telegram

        self.action = self._read_action(config, 'action', 'full')

        # Per-rule overrides. Resolution order: action_<rule> from config,
        # then RULE_ACTION_DEFAULTS, then the global action.
        self.rule_actions = {}
        for rule in ('countries', 'asns', 'ips'):
            configured = config.get(
                'compromise_detection', 'action_' + rule, fallback=''
            ).strip()
            if configured:
                self.rule_actions[rule] = self._read_action(
                    config, 'action_' + rule, self.action
                )
            elif rule in RULE_ACTION_DEFAULTS:
                self.rule_actions[rule] = RULE_ACTION_DEFAULTS[rule]

        for rule, act in sorted(self.rule_actions.items()):
            if act != self.action:
                logger.info(
                    "Compromise rule '{r}' enforcement: {a} (global action={g})".format(
                        r=rule, a=act, g=self.action
                    )
                )

        # Provisional-disable window. A mailbox disabled by this module is
        # restored after this many seconds unless an operator confirms the
        # compromise (/confirm <id>). 0 disables the reversal entirely.
        self.auto_reenable_seconds = config.getint(
            'compromise_detection', 'auto_reenable_hours', fallback=4
        ) * 3600
        self.reap_batch_limit = config.getint(
            'compromise_detection', 'auto_reenable_batch_limit', fallback=50
        )

        # Same list DistributedAuthDetector excludes from the evidence.
        # An ASN we refuse to count as proof cannot be the attacker we block.
        self.trusted_asns = parse_asn_list(
            config.get('compromise_detection', 'trusted_asns',
                       fallback='8075, 15169, 714')
        )

    @staticmethod
    def _read_action(config, key, fallback):
        """Read + validate one action key. Invalid values fail SAFE (weaker
        enforcement), never toward disabling a client's mailbox."""
        raw = config.get('compromise_detection', key, fallback=fallback).strip().lower()
        raw = ACTION_ALIASES.get(raw, raw)
        if raw not in VALID_ACTIONS:
            logger.warning(
                "Invalid compromise_detection.{k} '{a}', falling back to "
                "'alert_only'".format(k=key, a=raw)
            )
            return 'alert_only'
        return raw

    def resolve_action(self, trigger_rule):
        """Enforcement level for a given trigger rule."""
        return self.rule_actions.get(trigger_rule, self.action)

    def handle(self, username, service, trigger_rule, counts,
               window_seconds, actor='auto:DistributedAuthDetector'):
        """Main entry point called by the detector.

        Returns the compromise_events row id.
        """
        action = self.resolve_action(trigger_rule)
        try:
            # Every IP seen in the window — the full set is recorded on the
            # event for forensics, but only the untrusted ones are eligible
            # for blocking (see _partition_by_trust).
            observed = self.db.recent_auth_ips_with_asn(username, window_seconds)
            attacker_ips, relay_ips = self._partition_by_trust(observed)
            sample_ips = [row['ip'] for row in observed]
            sample_countries = self.db.recent_auth_countries(username, window_seconds)

            if relay_ips:
                logger.info(
                    "Compromise {u}: {n} IP(s) held back from blocking — trusted "
                    "cloud mail relay ASNs {a}".format(
                        u=username, n=len(relay_ips),
                        a=sorted({r['asn'] for r in relay_ips})
                    )
                )

            event_id = self.db.insert_compromise_event(
                username=username,
                service=service,
                trigger_rule=trigger_rule,
                counts=counts,
                window_seconds=window_seconds,
                sample_ips=sample_ips[:20],
                sample_countries=sample_countries,
                action_taken='pending',
            )
        except Exception as e:
            logger.error("Failed to record compromise event: {e}".format(e=e))
            return 0

        ips_blocked = 0
        mailbox_disabled = False

        # Block attacker IPs
        if action in ('block_ips', 'full'):
            ips_blocked = self._block_ips(attacker_ips, username, service, event_id)

        # Disable mailbox
        if action in ('disable_mailbox', 'full'):
            if self.mail_backend and getattr(self.mail_backend, 'enabled', False):
                mailbox_disabled = self._disable_mailbox(username, event_id, actor)
            else:
                logger.warning(
                    "Cannot auto-disable {u}: mail_backend not configured".format(u=username)
                )

        if action == 'alert_only' and action != self.action:
            logger.warning(
                "Compromise {u} (event {i}): rule '{r}' is configured "
                "alert_only — no IPs blocked, mailbox left enabled. Review "
                "and act manually if warranted.".format(
                    u=username, i=event_id, r=trigger_rule
                )
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
                    action=action,
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

    def _partition_by_trust(self, observed):
        """Split observed auth IPs into (blockable, trusted-relay).

        Microsoft 365 syncs a mailbox through its own cloud rather than from
        the user's PC, so the relay IP appears in the account's auth history
        and rotates constantly (40.97.x, 40.104.x, 52.96.x ...). Blocking one
        is both useless — it stops no attacker who has the password — and
        actively harmful: it silently drops the legitimate client, which
        surfaces to the user as "Waiting for your email provider" forever.
        """
        if not self.trusted_asns:
            return ([row['ip'] for row in observed], [])

        blockable = []
        relays = []
        for row in observed:
            if row.get('asn') and row['asn'] in self.trusted_asns:
                relays.append(row)
            else:
                blockable.append(row['ip'])
        return (blockable, relays)

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

    # ------------------------------------------------------------------
    # v1.7.11 — provisional disables
    # ------------------------------------------------------------------
    def reap_auto_disabled_mailboxes(self, limit=None, dry_run=False):
        """Restore mailboxes whose provisional disable window has elapsed.

        A compromise disable used to stand until a human noticed. On
        2026-08-09 that meant 16h04m of downtime for a travelling client whose
        only crime was reaching five ASNs in an hour, because the alert landed
        at 23:44 and the operator was asleep. Detection will be wrong again —
        the point of this reaper is that being wrong stops costing a full
        night of a client's mail.

        Reversing the mailbox does NOT hand access back to the sources that
        triggered the event: their IPs stay in the firewall on the normal tier
        schedule (24h minimum), reaped separately by Blocker.reap_expired_blocks.
        An attacker would need entirely fresh infrastructure to benefit.

        /confirm <id> pins a disable permanently — run it before the window
        elapses, or after, in which case it re-disables.

        Returns {'restored': int, 'failed': int, 'skipped': int, 'remaining': int}.
        """
        result = {'restored': 0, 'failed': 0, 'skipped': 0, 'remaining': 0}

        if self.auto_reenable_seconds <= 0:
            return result
        if not (self.mail_backend and getattr(self.mail_backend, 'enabled', False)):
            return result

        batch = self.reap_batch_limit if limit is None else int(limit)
        if batch <= 0:
            return result

        cutoff = int(time.time()) - self.auto_reenable_seconds
        try:
            # One row past the batch, purely to detect an overflow without a
            # second COUNT query.
            candidates = self.db.get_auto_reenable_candidates(cutoff, limit=batch + 1)
        except Exception as e:
            logger.error("Auto-reenable query failed: {e}".format(e=e))
            return result

        overflowed = len(candidates) > batch
        candidates = candidates[:batch]

        for event in candidates:
            username = event['username']
            event_id = event['id']
            age_h = int((time.time() - event['detected_at']) / 3600)

            # The operator already restored it by hand (or via /enable). Stamp
            # the event so it stops being a candidate, but touch nothing else.
            try:
                still_disabled = self.db.is_mailbox_disabled_by_guardian(username)
            except Exception as e:
                logger.error(
                    "Auto-reenable state check failed for {u}: {e}".format(u=username, e=e)
                )
                result['failed'] += 1
                continue

            if not still_disabled:
                result['skipped'] += 1
                if not dry_run:
                    self.db.mark_compromise_auto_reversed(
                        event_id,
                        note="auto-reenable skipped at {h}h: mailbox already "
                             "restored by operator".format(h=age_h)
                    )
                continue

            if dry_run:
                logger.info(
                    "[DRY-RUN] Would auto-reenable {u} (event {i}, disabled "
                    "{h}h ago, trigger={r})".format(
                        u=username, i=event_id, h=age_h, r=event['trigger_rule']
                    )
                )
                result['restored'] += 1
                continue

            try:
                changed = self.mail_backend.enable_mailbox(username)
                self.db.insert_mailbox_action(
                    username=username,
                    action='enable',
                    actor='auto:auto_reenable',
                    reason="provisional disable from compromise event {i} "
                           "expired after {h}h unconfirmed".format(i=event_id, h=age_h),
                    related_compromise_id=event_id,
                    success=True,
                )
            except Exception as e:
                logger.error(
                    "Auto-reenable failed for {u} (event {i}): {e}".format(
                        u=username, i=event_id, e=e
                    )
                )
                self.db.insert_mailbox_action(
                    username=username,
                    action='enable',
                    actor='auto:auto_reenable',
                    reason="provisional disable from compromise event {i}".format(i=event_id),
                    related_compromise_id=event_id,
                    success=False,
                    error_message=str(e),
                )
                # Leave the event unstamped so the next sweep retries. A mail
                # backend outage must not silently strand a disabled mailbox.
                result['failed'] += 1
                continue

            self.db.mark_compromise_auto_reversed(
                event_id,
                note="mailbox auto-reenabled after {h}h unconfirmed".format(h=age_h)
            )
            result['restored'] += 1
            logger.warning(
                "AUTO-REENABLE {u} (event {i}): provisional disable expired "
                "after {h}h with no operator confirmation — mailbox restored "
                "(row changed={c})".format(
                    u=username, i=event_id, h=age_h, c=changed
                )
            )

            try:
                if hasattr(self.telegram, 'alert_mailbox_auto_reenabled'):
                    self.telegram.alert_mailbox_auto_reenabled(
                        username=username,
                        event_id=event_id,
                        trigger_rule=event['trigger_rule'],
                        hours=age_h,
                    )
            except Exception as e:
                logger.error("Auto-reenable alert failed: {e}".format(e=e))

        # Failures stay queued (unstamped, so the next sweep retries), plus
        # anything the batch limit cut off. Overflow is counted as 1 rather
        # than an exact figure — compromise events are rare enough (six in this
        # detector's lifetime) that a deeper backlog is not a real scenario,
        # and this number is informational only.
        result['remaining'] = result['failed'] + (1 if overflowed else 0)
        return result

    @staticmethod
    def _summarize(ips_blocked, mailbox_disabled):
        if ips_blocked and mailbox_disabled:
            return 'full'
        if mailbox_disabled:
            return 'mailbox_disabled'
        if ips_blocked:
            return 'ips_blocked'
        return 'alert_only'
