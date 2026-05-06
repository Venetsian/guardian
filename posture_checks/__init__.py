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

# Registered checks. New checks land here as they're written — the
# orchestrator iterates this list and applies each check's own
# `applies_to(profile)` gate. Mix of posture (security) and health
# (system) modules; each check declares which one it belongs to.
from posture_checks.check_pwnkit import PwnKitCheck
from posture_checks.check_hidepid import HidePidCheck
from posture_checks.check_smart import SmartCheck
from posture_checks.check_copy_fail import CopyFailCheck

ALL_CHECKS = [
    CopyFailCheck,    # CVE-2026-31431 — high-priority current kernel CVE
    PwnKitCheck,      # CVE-2021-4034 — long-known polkit priv-esc
    HidePidCheck,     # /proc cross-tenant isolation
    SmartCheck,       # drive health with growth detection
]

__all__ = [
    'Check',
    'CheckResult',
    'Severity',
    'Status',
    'Module',
    'ALL_CHECKS',
]
