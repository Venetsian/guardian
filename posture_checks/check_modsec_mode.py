"""
mod_security blocking mode — pairs with `modsec_volume` (size health)
to give a complete picture of the WAF posture (#123 Layer 3).

Companion: `modsec_volume` watches the audit log size as a rotation/
volume health signal. THIS check looks at WHETHER mod_security is
actually blocking attacks vs just logging them. The two together
answer "is the WAF healthy AND doing its job?".

`SecRuleEngine` directive values:
  On             → blocking; rules can deny requests              → PASS
  DetectionOnly  → logs violations only; no blocking              → LOW
  Off            → module loaded but rules disabled               → MEDIUM

DetectionOnly is the common transitional state during rule rollout —
the operator wants to observe FPs before flipping to On. Reporting it
as LOW (rather than PASS) ensures the operator doesn't forget to
promote it after the observation period.

Off is a stronger smell — the module is using resources but not doing
its primary job. Doesn't escalate to HIGH because it's an operator
choice, not a misconfiguration that broke isolation.

Applies: has_modsec=True.
"""

import logging
import os
import re

from posture_checks.base import Check, CheckResult, Severity

logger = logging.getLogger('wp-guardian.posture.modsec_mode')


# Configuration files where SecRuleEngine is typically declared, in
# preference order. First match wins. Different stacks store the
# directive in different places.
CANDIDATE_PATHS = (
    # Apache (EL family)
    '/etc/httpd/conf.d/mod_security.conf',
    '/etc/httpd/modsecurity.d/local_rules/modsecurity_localrules.conf',
    '/etc/httpd/modsecurity.d/modsecurity.conf',
    # Apache (Debian)
    '/etc/apache2/mods-enabled/security2.conf',
    # Standalone modsecurity package
    '/etc/modsecurity/modsecurity.conf',
    # OpenLiteSpeed
    '/usr/local/lsws/conf/modsec.conf',
    '/usr/local/lsws/conf/modsecurity/modsec.conf',
)


_DIRECTIVE_RE = re.compile(
    r'^\s*SecRuleEngine\s+(\S+)',
    re.IGNORECASE | re.MULTILINE,
)


def _parse_engine(path):
    """Read a config file and return the LAST SecRuleEngine value or ''.
    Last-match wins because Apache config can declare it multiple times
    in nested includes; the last one in evaluation order is effective."""
    try:
        with open(path, 'r') as f:
            content = f.read()
    except (IOError, OSError):
        return ''
    matches = _DIRECTIVE_RE.findall(content)
    return matches[-1] if matches else ''


def _find_engine():
    """Walk candidate paths; return (value, source_file) for the first
    file that declares SecRuleEngine."""
    for path in CANDIDATE_PATHS:
        if not os.path.isfile(path):
            continue
        val = _parse_engine(path)
        if val:
            return (val, path)
    return ('', '')


class ModsecModeCheck(Check):
    check_id = 'modsec_mode'
    severity = Severity.LOW   # default; per-result override
    description = 'mod_security SecRuleEngine mode (On / DetectionOnly / Off)'

    def applies_to(self, profile):
        return bool(profile.get('has_modsec'))

    def run(self, profile, previous=None):
        engine, path = _find_engine()
        if not engine:
            return CheckResult.errored(
                detail=("has_modsec=true but no SecRuleEngine directive "
                        "found in any standard config path"),
                value={'reason': 'directive_not_found'},
            )

        engine_lower = engine.lower()
        value = {'engine': engine_lower, 'config_path': path}

        if engine_lower == 'on':
            return CheckResult.passing(
                detail="SecRuleEngine On (blocking)",
                value=value,
            )
        if engine_lower == 'detectiononly':
            return CheckResult.warning(
                detail=("SecRuleEngine DetectionOnly — logs violations "
                        "but doesn't block. Promote to On after FP review."),
                value=value,
                severity=Severity.LOW,
            )
        if engine_lower == 'off':
            return CheckResult.warning(
                detail="SecRuleEngine Off — module loaded but disabled",
                value=value,
                severity=Severity.MEDIUM,
            )

        return CheckResult.errored(
            detail="SecRuleEngine value {v!r} unrecognized".format(v=engine),
            value=value,
        )
