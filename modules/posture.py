"""
WP-Guardian Posture / Host-Health Orchestrator (task #122).

Owns the daily run loop: load the host profile, iterate every registered
check, run the ones that apply, diff each result against the previously
stored state, append a posture_events row on transitions, and queue a
Telegram alert when the new severity crosses the configured floor.

Runs from the Guardian daemon's main loop via `run_if_due()`, which
checks the configured cadence and the last_run_at recorded across all
posture_state rows. Also exposed via CLI for one-off scans.

Severity-vs-alert separation:
  * Every transition is logged to posture_events regardless of severity.
  * Telegram fires only when the new severity is >= alert_severity_min
    (default 'high'). LOW/INFO transitions stay in the DB for forensics
    without being noisy.
  * SKIPPED checks (didn't apply to this host) are persisted so the CLI
    `--posture-status` can show "skipped: not applicable" rather than
    leaving them missing.
"""

import json
import logging
import time

from posture_checks import ALL_CHECKS
from posture_checks.base import Severity, Status

logger = logging.getLogger('wp-guardian.posture')


def _serialize_value(value):
    """Stable JSON encoding for diff comparisons. Falls back to str() if
    the value isn't JSON-serializable so we never lose a transition."""
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


class PostureAuditor:
    def __init__(self, config, db, host_profile_detector, telegram=None,
                 hostname=None, base_dir=None):
        self.config = config
        self.db = db
        self.profile_detector = host_profile_detector
        self.telegram = telegram
        self.base_dir = base_dir
        self.hostname = hostname or host_profile_detector.hostname

        self.enabled = config.getboolean('posture', 'enabled', fallback=True)
        self.interval = config.getint('posture', 'interval_seconds', fallback=86400)
        self.alert_severity_min = config.get(
            'posture', 'alert_severity_min', fallback=Severity.HIGH
        ).strip().lower()
        if Severity.rank(self.alert_severity_min) <= 0 and self.alert_severity_min != Severity.INFO:
            logger.warning(
                "Invalid posture.alert_severity_min '%s'; using 'high'",
                self.alert_severity_min
            )
            self.alert_severity_min = Severity.HIGH
        self.events_retention_days = config.getint(
            'posture', 'events_retention_days', fallback=30
        )

        # Instantiate every registered check once. Checks are stateless;
        # the orchestrator owns the storage.
        self.checks = []
        for check_cls in ALL_CHECKS:
            try:
                self.checks.append(check_cls())
            except Exception as e:
                logger.error(
                    "Failed to instantiate check %s: %s", check_cls.__name__, e
                )

        self._last_run_at = self._most_recent_run()

        if self.enabled:
            logger.info(
                "PostureAuditor active: %d check(s), interval=%ds, alert>=%s",
                len(self.checks), self.interval, self.alert_severity_min,
            )
        else:
            logger.info("PostureAuditor disabled via [posture] enabled=false")

    # ------------------------------------------------------------------
    # Run-loop integration
    # ------------------------------------------------------------------
    def _most_recent_run(self):
        """Highest last_run_at across all posture_state rows for this host.
        Returns 0 if nothing has ever been stored — i.e. first install."""
        try:
            row = self.db.conn.execute(
                "SELECT MAX(last_run_at) AS ts FROM posture_state WHERE host = ?",
                (self.hostname,)
            ).fetchone()
            if row and row['ts']:
                return int(row['ts'])
        except Exception as e:
            logger.debug("Unable to read last posture run: %s", e)
        return 0

    def run_if_due(self):
        """Called from the daemon's periodic loop. No-op when disabled or
        when the last run is younger than `interval`."""
        if not self.enabled:
            return False
        now = int(time.time())
        if (now - self._last_run_at) < self.interval:
            return False
        try:
            self.run_now()
        except Exception as e:
            logger.error("Posture run crashed: %s", e)
        return True

    def run_now(self, force_profile_refresh=False):
        """Execute every registered check once. Returns a results dict
        keyed by check_id with the last per-check status + events emitted."""
        if force_profile_refresh:
            profile = self.profile_detector.detect_now()
        else:
            profile = self.profile_detector.get_or_detect()

        if profile is None:
            logger.error("No host profile available; skipping posture run")
            return {}

        run_started = int(time.time())
        results = {}
        events_fired = 0

        for check in self.checks:
            try:
                applies = check.applies_to(profile)
            except Exception as e:
                logger.error(
                    "Check %s applies_to() crashed: %s", check.check_id, e
                )
                applies = False

            if not applies:
                self._record_skipped(check)
                results[check.check_id] = {
                    'status': Status.SKIPPED, 'severity': Severity.INFO,
                    'detail': 'not applicable to this host', 'transition': False,
                }
                continue

            try:
                result = check.run(profile)
            except Exception as e:
                logger.error("Check %s run() crashed: %s", check.check_id, e)
                from posture_checks.base import CheckResult
                result = CheckResult.errored(detail="check crashed: {e}".format(e=e))

            transitioned, severity = self._persist_and_diff(check, result)
            results[check.check_id] = {
                'status': result.status,
                'severity': severity,
                'detail': result.detail,
                'transition': transitioned,
            }
            if transitioned and self._should_alert(severity):
                self._fire_alert(check, result, severity)
                events_fired += 1

        # Daily TTL on posture_events
        try:
            removed = self.db.posture_events_cleanup(self.events_retention_days)
            if removed:
                logger.debug("posture_events cleanup removed %d row(s)", removed)
        except Exception as e:
            logger.debug("posture_events cleanup failed: %s", e)

        self._last_run_at = run_started
        logger.info(
            "Posture run complete: %d check(s), %d transition(s), %d alert(s)",
            len(self.checks),
            sum(1 for r in results.values() if r['transition']),
            events_fired,
        )
        return results

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------
    def _record_skipped(self, check):
        """Write a `skipped` row so the status table shows the check exists
        but doesn't apply, instead of the user wondering where it went."""
        previous = self.db.posture_state_get(self.hostname, check.module, check.check_id)
        changed = previous is None or previous['status'] != Status.SKIPPED
        self.db.posture_state_upsert(
            self.hostname, check.module, check.check_id,
            status=Status.SKIPPED, severity=Severity.INFO,
            current_value='', detail='not applicable to this host',
            changed=changed,
        )

    def _persist_and_diff(self, check, result):
        """Write the new state, compare against previous, append an event
        on transition. Returns (transitioned: bool, effective_severity: str)."""
        previous = self.db.posture_state_get(self.hostname, check.module, check.check_id)
        new_value_json = _serialize_value(result.value)
        severity = result.severity_override or check.severity

        # ERROR is sticky-but-quiet: we still record state, but we treat the
        # transition into ERROR as MEDIUM unless the check overrode severity.
        if result.status == Status.ERROR and result.severity_override is None:
            severity = Severity.MEDIUM

        prev_status = previous['status'] if previous else Status.UNKNOWN
        prev_value = previous['current_value'] if previous else ''

        transitioned = (prev_status != result.status) or (prev_value != new_value_json)

        self.db.posture_state_upsert(
            self.hostname, check.module, check.check_id,
            status=result.status, severity=severity,
            current_value=new_value_json, detail=result.detail,
            changed=transitioned,
        )

        if transitioned:
            try:
                self.db.posture_event_insert(
                    host=self.hostname, module=check.module, check_id=check.check_id,
                    from_status=prev_status, to_status=result.status,
                    from_value=prev_value, to_value=new_value_json,
                    severity=severity, detail=result.detail,
                )
            except Exception as e:
                logger.error(
                    "Failed to insert posture_event for %s: %s",
                    check.check_id, e
                )

        return transitioned, severity

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------
    def _should_alert(self, severity):
        """Filter on configured severity floor + first-run grace.

        On the very first run after install, every result is a transition
        (UNKNOWN -> something). We don't want to flood Telegram on bootstrap,
        so the first run only alerts on CRITICAL.
        """
        if not self.telegram or not getattr(self.telegram, 'enabled', False):
            return False
        if not Severity.gte(severity, self.alert_severity_min):
            return False
        if self._last_run_at == 0 and severity != Severity.CRITICAL:
            # Bootstrap dampening — let MEDIUM/HIGH transitions go to the DB
            # but stay quiet. CRITICAL still pages.
            return False
        return True

    def _fire_alert(self, check, result, severity):
        """Hand off to the Telegram alerter. Failures are logged, not raised."""
        try:
            if hasattr(self.telegram, 'alert_posture_drift'):
                self.telegram.alert_posture_drift(
                    check_id=check.check_id,
                    module=check.module,
                    severity=severity,
                    host=self.hostname,
                    status=result.status,
                    detail=result.detail,
                    description=check.description,
                )
            else:
                # Older Telegram class without the formatter — fall back
                self.telegram.send(
                    "🛡 <b>WP-Guardian posture drift</b>\n"
                    "Check: <code>{c}</code>\n"
                    "Severity: {s}\n"
                    "Host: {h}\n"
                    "Status: {st}\n"
                    "{d}".format(
                        c=check.check_id, s=severity.upper(),
                        h=self.hostname, st=result.status, d=result.detail,
                    ),
                    priority='HIGH',
                )
        except Exception as e:
            logger.error("Posture alert send failed (%s): %s", check.check_id, e)

    # ------------------------------------------------------------------
    # CLI helpers
    # ------------------------------------------------------------------
    def status_table(self, module=None):
        """Return all posture_state rows for CLI display."""
        return self.db.posture_state_all(host=self.hostname, module=module)

    def recent_events(self, limit=20, severity_min=None):
        sev_set = None
        if severity_min:
            ranks = Severity._ORDER
            try:
                idx = ranks.index(severity_min)
                sev_set = set(ranks[idx:])
            except ValueError:
                sev_set = None
        return self.db.posture_events_recent(
            host=self.hostname, severity_min=sev_set, limit=limit
        )
