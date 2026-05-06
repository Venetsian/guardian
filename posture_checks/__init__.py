"""
WP-Guardian posture-audit + host-health check registry.

Each check is a small class derived from `posture_checks.base.Check`,
declaring its applicability against the host profile and producing a
`CheckResult` per run. Adding a new check means dropping a new file in
this directory and registering its class in `ALL_CHECKS`.
"""

from posture_checks.base import (
    Check,
    CheckResult,
    Severity,
    Status,
    Module,
)

# Phase 1 reference checks. New checks land here as they're written —
# the orchestrator iterates this list and applies each check's own
# `applies_to(profile)` gate.
from posture_checks.check_pwnkit import PwnKitCheck
from posture_checks.check_hidepid import HidePidCheck

ALL_CHECKS = [
    PwnKitCheck,
    HidePidCheck,
]

__all__ = [
    'Check',
    'CheckResult',
    'Severity',
    'Status',
    'Module',
    'ALL_CHECKS',
]
