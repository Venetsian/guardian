"""
Posture-audit check base class.

Each check is a small subclass that:
  * declares its `check_id`, `module`, default `severity`, and `description`
  * implements `applies_to(profile)` returning a bool
  * implements `run(profile)` returning a `CheckResult`

The orchestrator (`modules.posture.PostureAuditor`) iterates the registered
checks, skips the ones whose `applies_to` returns False (storing them as
`skipped` in posture_state), runs the rest, and diffs the result against
the previously stored state to decide whether to append a `posture_events`
row and fire a Telegram alert.

Severity-vs-status: `Status` describes whether the check is currently
passing/failing/etc. `Severity` is a static property of the check that
tells the alert pipeline how loud to be when a transition lands. Most
checks use a single severity, but a check is allowed to override it on
a per-result basis (e.g. listening-port inventory bumps severity when a
non-localhost bind appears on an unprotected host).
"""


class Severity(object):
    """String constants for severity levels.

    Ordered from quiet to loud. The orchestrator's alert filter compares
    against `alert_severity_min` (config setting) using this ordering.
    """
    INFO = 'info'
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'

    _ORDER = ('info', 'low', 'medium', 'high', 'critical')

    @classmethod
    def rank(cls, level):
        """Return the integer rank of a severity (higher = louder)."""
        try:
            return cls._ORDER.index(level)
        except ValueError:
            return 0

    @classmethod
    def gte(cls, level, threshold):
        """True if `level` is at least as loud as `threshold`."""
        return cls.rank(level) >= cls.rank(threshold)


class Status(object):
    """Run-result status. Mutually exclusive."""
    PASS = 'pass'
    FAIL = 'fail'
    WARN = 'warn'
    SKIPPED = 'skipped'   # didn't apply to this host; not an error
    ERROR = 'error'        # check itself crashed (couldn't determine)
    UNKNOWN = 'unknown'    # placeholder before the first run


class Module(object):
    """Which sibling module a check belongs to."""
    POSTURE = 'posture'   # security drift
    HEALTH = 'health'     # system health drift


class CheckResult(object):
    """Outcome of a single check run.

    `value` is a small dict capturing the measurement (e.g. {'mode': 0o755}).
    It's serialized to JSON for posture_state.current_value so transitions
    can be detected by string equality.
    `detail` is a short human-readable summary shown in CLI tables and in
    the body of Telegram alerts.
    `severity_override` lets a check escalate or de-escalate the alert
    severity for a specific run (None means use the check's default).
    """

    __slots__ = ('status', 'value', 'detail', 'severity_override')

    def __init__(self, status, value=None, detail='', severity_override=None):
        self.status = status
        self.value = value if value is not None else {}
        self.detail = detail or ''
        self.severity_override = severity_override

    @classmethod
    def passing(cls, detail='', value=None):
        return cls(Status.PASS, value=value, detail=detail)

    @classmethod
    def failing(cls, detail='', value=None, severity=None):
        return cls(Status.FAIL, value=value, detail=detail, severity_override=severity)

    @classmethod
    def warning(cls, detail='', value=None, severity=None):
        return cls(Status.WARN, value=value, detail=detail, severity_override=severity)

    @classmethod
    def errored(cls, detail='', value=None):
        return cls(Status.ERROR, value=value, detail=detail)


class Check(object):
    """Base class for posture and host-health checks.

    Subclasses must override:
      * `check_id` — a stable, lowercase, snake_case identifier (e.g. 'pwnkit')
      * `description` — one-line human description
      * `applies_to(profile)` — return True iff this check makes sense on
                                a host with the given profile dict
      * `run(profile)` — return a CheckResult

    Subclasses may override:
      * `module` — defaults to POSTURE
      * `severity` — default severity for transitions out of PASS

    Checks must NOT block for long. Anything that would take more than
    a couple of seconds to evaluate should be sampled, cached, or split
    into a worker task.
    """

    check_id = None
    module = Module.POSTURE
    severity = Severity.MEDIUM
    description = ''

    def applies_to(self, profile):
        """Return True if this check should run on a host with `profile`.

        Default: applies to every Linux host. Subclasses gate on flags like
        is_cloudlinux, is_multi_tenant, web_server, etc.
        """
        return bool(profile.get('is_linux', True))

    def run(self, profile, previous=None):
        """Execute the check. Must return a `CheckResult`.

        Args:
            profile: host profile dict from HostProfileDetector.
            previous: previously-stored state for this check, or None on
                first run. When non-None it is a dict with keys:
                  status       — last status string ('pass'/'fail'/'warn'/...)
                  value        — parsed dict of the previous current_value JSON
                  detail       — last detail string
                  last_run_at  — UNIX timestamp of the previous run
                Used by checks that need delta detection across runs
                (e.g. SMART growth in reallocated sectors). Most checks
                ignore it.

        Subclasses should catch their own expected errors and return
        `CheckResult.errored(...)` rather than raising — exceptions that
        escape are caught by the orchestrator and become ERROR results,
        but with less helpful detail.
        """
        raise NotImplementedError(
            "Check subclass {n} did not implement run()".format(n=type(self).__name__)
        )

    def __repr__(self):
        return "<Check id={id} module={m} severity={s}>".format(
            id=self.check_id, m=self.module, s=self.severity
        )
