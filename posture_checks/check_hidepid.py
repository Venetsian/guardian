"""
/proc hidepid mount option — multi-tenant process visibility hardening.

Without `hidepid=invisible` (or `hidepid=2` on older kernels), every user
on the box can read /proc entries belonging to every other user, leaking:
  * full command lines (often contain passwords / API keys passed as argv)
  * environment via /proc/<pid>/environ
  * open file paths via /proc/<pid>/fd/

On a multi-tenant box this is a meaningful cross-tenant info leak.

Severity:
  * MEDIUM by default (the leak is real but not RCE-grade).
  * Bumped to HIGH when the host is multi-tenant — the same misconfig is
    much more dangerous when there are unrelated tenants on the box.
  * On single-site hosts the check still runs; if hidepid isn't set, that's
    fine (no other users to hide from), so we report PASS with a note.

Detection: read /proc/mounts and look for the proc line. We don't shell
out to `mount` — /proc/mounts is the kernel-side truth and avoids the
PATH/env complications of subprocess.
"""

from posture_checks.base import Check, CheckResult, Severity, Status


def _read_proc_mount_options():
    """Return the option string for the /proc mount, or '' if not found."""
    try:
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.split()
                # /proc/mounts columns: src target fstype options ...
                if len(parts) >= 4 and parts[1] == '/proc' and parts[2] == 'proc':
                    return parts[3]
    except (IOError, OSError):
        pass
    return ''


def _hidepid_value(options):
    """Return the configured hidepid value ('', '0', '1', '2', 'invisible', etc.)."""
    if not options:
        return ''
    for opt in options.split(','):
        if opt.startswith('hidepid='):
            return opt.split('=', 1)[1].strip()
    return ''


def _is_hidden(value):
    """True if the hidepid value provides cross-user hiding."""
    return value in ('2', 'invisible')


class HidePidCheck(Check):
    check_id = 'proc_hidepid'
    severity = Severity.MEDIUM
    description = '/proc mounted with hidepid=invisible (cross-tenant /proc isolation)'

    def applies_to(self, profile):
        # Linux only. Single-site hosts still run it, but a 'no' result on
        # those is reported as PASS (with a note) rather than FAIL —
        # there's no other user to hide from.
        return bool(profile.get('is_linux', True))

    def run(self, profile):
        options = _read_proc_mount_options()
        if not options:
            return CheckResult.errored(
                detail="/proc not found in /proc/mounts (is this Linux?)",
                value={'options': '', 'hidepid': '', 'multi_tenant': profile.get('is_multi_tenant')},
            )

        value = _hidepid_value(options)
        hidden = _is_hidden(value)
        is_multi_tenant = bool(profile.get('is_multi_tenant'))

        result_value = {
            'options': options,
            'hidepid': value,
            'multi_tenant': is_multi_tenant,
        }

        if hidden:
            return CheckResult.passing(
                detail="/proc has hidepid={v}".format(v=value),
                value=result_value,
            )

        if not is_multi_tenant:
            # Single-site: nobody to hide from. Pass with an info note so the
            # operator can still see the current setting in --posture-status.
            return CheckResult.passing(
                detail=("/proc hidepid not set ({v}); fine on single-site hosts"
                        .format(v=value or 'default')),
                value=result_value,
            )

        # Multi-tenant + missing hidepid = real drift. Escalate severity.
        return CheckResult.failing(
            detail=("/proc hidepid not invisible (current: {v}); cross-tenant "
                    "/proc readable on a multi-tenant host"
                    .format(v=value or 'default')),
            value=result_value,
            severity=Severity.HIGH,
        )
