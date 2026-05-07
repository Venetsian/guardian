"""
Kernel livepatch posture — visibility into whether the host has a
runtime kernel patcher (KernelCare, kpatch, Ksplice) installed and
whether it's actually running.

Why this matters: kernel CVEs are the high-value priv-esc vector, and
the traditional "upgrade kernel + reboot" cycle is operationally
painful on multi-tenant boxes. Livepatch tools binary-patch the
running kernel without restart, closing the gap between disclosure
and reboot. This check makes the livepatch state visible:

  * provider in (kernelcare/kpatch/ksplice), active=True   → PASS
        Livepatch is running. Operator's subscription is doing its job.
  * provider in (...), active=False                         → MEDIUM (FAIL)
        A livepatch tool is INSTALLED but the service is not running.
        This is the dangerous state — operator may believe they're
        protected, but kernel patches are not being applied.
  * provider='none'                                          → PASS-with-note
        No livepatch tool installed. Operator relies on the reboot
        cycle for kernel patching. Common and fine for many setups
        (and explicitly the situation for third-party operators who
        deploy wp-guardian without a paid CL/KernelCare subscription).
        The note tells the operator what their options are.

The PASS-with-note path means this never alerts on operators who
deliberately don't run a livepatch tool — we surface the choice
rather than nag them about it.

Detection happens once at host-profile build time
(`extras.livepatch_provider` and `extras.livepatch_active`); this
check just reads and classifies. Applies: all Linux.
"""

import logging

from posture_checks.base import Check, CheckResult, Severity

logger = logging.getLogger('wp-guardian.posture.livepatch_state')


class LivepatchStateCheck(Check):
    check_id = 'livepatch_state'
    severity = Severity.MEDIUM
    description = ('Kernel livepatch provider state '
                   '(KernelCare / kpatch / Ksplice running)')

    def applies_to(self, profile):
        return bool(profile.get('is_linux', True))

    def run(self, profile, previous=None):
        extras = profile.get('extras') or {}
        provider = (extras.get('livepatch_provider') or 'none').lower()
        active = bool(extras.get('livepatch_active'))
        value = {'provider': provider, 'active': active}

        if provider == 'none':
            # No livepatch installed — pass with informational note.
            # Don't penalize third-party operators who haven't installed
            # a (potentially paid) livepatch service; just tell them
            # what their options are.
            return CheckResult.passing(
                detail=("no kernel livepatch provider detected — kernel "
                        "patches require a reboot. Options: KernelCare "
                        "(paid, comes with most CL subscriptions), "
                        "kpatch (free on RHEL/AlmaLinux 8+), or accept "
                        "the reboot cycle."),
                value=value,
            )

        if active:
            return CheckResult.passing(
                detail="{p} livepatch service active".format(p=provider),
                value=value,
            )

        # Installed but inactive — the dangerous state. Operator likely
        # thinks they're protected.
        return CheckResult.failing(
            detail=("{p} is INSTALLED but the service is NOT active — "
                    "kernel livepatches are not being applied. "
                    "Investigate: `systemctl status {p}` and the "
                    "provider's CLI tool.").format(p=provider),
            value=value,
            severity=Severity.MEDIUM,
        )
