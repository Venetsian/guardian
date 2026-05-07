"""
mod_security audit log volume — host-health module.

Verifies the audit log is being rotated. A modsec_audit.log that grows
unbounded indicates one of:
  * logrotate not configured for this file
  * logrotate config broken / stale
  * the box is under sustained heavy attack and audit volume is
    legitimately enormous

Either way the operator should know.

Severity:
  *  >= 500 MB → HIGH (rotation almost certainly missing)
  *  >= 100 MB → MEDIUM (worth verifying logrotate config)
  *  otherwise → PASS

Stored value buckets the size — we don't fire a transition every run
just because the file gained another MB of log.

Applies: has_modsec=True.
"""

import logging
import os

from posture_checks.base import Check, CheckResult, Severity, Module

logger = logging.getLogger('wp-guardian.posture.modsec_volume')


THRESHOLD_HIGH_MB = 500
THRESHOLD_MEDIUM_MB = 100

# Common locations across stacks. First match wins.
CANDIDATE_PATHS = (
    '/var/log/httpd/modsec_audit.log',
    '/var/log/apache2/modsec_audit.log',
    '/var/log/modsec_audit.log',
    '/usr/local/lsws/logs/modsec_audit.log',
    '/var/log/modsec/modsec_audit.log',
)


def _find_audit_log():
    for p in CANDIDATE_PATHS:
        if os.path.isfile(p):
            return p
    return None


class ModsecVolumeCheck(Check):
    check_id = 'modsec_volume'
    module = Module.HEALTH
    severity = Severity.MEDIUM
    description = 'mod_security audit log size (rotation health)'

    def applies_to(self, profile):
        return bool(profile.get('has_modsec'))

    def run(self, profile, previous=None):
        path = _find_audit_log()
        if path is None:
            return CheckResult.warning(
                detail=("has_modsec=true but no modsec_audit.log found in "
                        "standard locations"),
                value={'reason': 'no_audit_log'},
                severity=Severity.LOW,
            )

        try:
            size = os.path.getsize(path)
        except OSError as e:
            return CheckResult.errored(
                detail="couldn't stat {p}: {e}".format(p=path, e=e),
                value={'reason': 'stat_failed', 'path': path},
            )

        size_mb = size / (1024.0 * 1024.0)
        if size_mb >= THRESHOLD_HIGH_MB:
            bucket = 'high'
        elif size_mb >= THRESHOLD_MEDIUM_MB:
            bucket = 'medium'
        else:
            bucket = 'ok'

        value = {'bucket': bucket, 'path': path}
        detail = "{p}: {sz:.1f} MB".format(p=path, sz=size_mb)

        if size_mb >= THRESHOLD_HIGH_MB:
            return CheckResult.failing(
                detail=detail + " — rotation likely missing",
                value=value, severity=Severity.HIGH,
            )
        if size_mb >= THRESHOLD_MEDIUM_MB:
            return CheckResult.warning(
                detail=detail + " — verify logrotate is configured",
                value=value, severity=Severity.MEDIUM,
            )
        return CheckResult.passing(detail=detail, value=value)
