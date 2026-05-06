"""
CVE-2026-31431 ("Copy Fail") — Linux kernel local privilege escalation
in the algif_aead crypto userspace API module.

The vulnerability lives in the kernel's `algif_aead` initcall (built-in
on RHEL-family kernels via CONFIG_CRYPTO_USER_API_AEAD=y). Any
unprivileged local user can gain root via a small local exploit. The
common modprobe blacklist workaround does NOT work because the module
is compiled into the kernel image — only a kernel update or the GRUB
`initcall_blacklist=algif_aead_init` boot parameter mitigates.

CloudLinux published patched kernels on 2026-04-30 (per the
"CVE-2026-31431 (Copy Fail) — Mitigation and Patches" advisory).

Detection strategy:
  * Read current kernel via `uname -r`.
  * Compare against per-distro patched-version baseline.
  * Probe `/proc/cmdline` for the `initcall_blacklist=algif_aead_init`
    GRUB mitigation flag (handles both standalone and comma-list forms).

Severity ladder:
  * CRITICAL — kernel below patched AND no GRUB mitigation
                (root local priv-esc reachable; patch and reboot)
  * MEDIUM   — kernel below patched BUT GRUB mitigation active
                (mitigated for now, but still patch — operator might
                accidentally remove the GRUB arg later)
  * PASS     — kernel at or above patched version

Stored value includes the kernel string and the patched baseline so
transitions surface clean diffs. Mitigation flag is included too —
if someone removes the GRUB arg without patching, the check transitions
back to CRITICAL on next run.
"""

import logging
import os

from posture_checks.base import Check, CheckResult, Severity, Status
from posture_checks._utils import python_vercmp, distro_major, safe_run

logger = logging.getLogger('wp-guardian.posture.copy_fail')


# Minimum patched kernel version-release (no arch suffix) per distro.
# Kernel package version-release strings on EL look like:
#   5.14.0-611.49.2.el9_7
#   6.12.0-124.52.2.el10_1
#   4.18.0-553.121.1.el8_10
# `uname -r` returns these with a `.x86_64` (or other arch) suffix that
# we strip before comparing.
#
# Sources:
#   * CloudLinux blog "CVE-2026-31431 (Copy Fail) — Mitigation and Patches"
#     2026-04-30 — patched RPM strings for AlmaLinux/CL 9, 10, and CL 8.
#   * RHEL/AlmaLinux/Rocky 9 + 10 track the same upstream EL stream
#     (verified against AlmaLinux errata index).
_MIN_PATCHED_KERNEL = {
    # EL10 family (CL 10 / RHEL 10 / AlmaLinux 10 / Rocky 10)
    ('rhel', '10'):        '6.12.0-124.52.2.el10_1',
    ('almalinux', '10'):   '6.12.0-124.52.2.el10_1',
    ('rocky', '10'):       '6.12.0-124.52.2.el10_1',
    ('cloudlinux', '10'):  '6.12.0-124.52.2.el10_1',
    # EL9 family
    ('rhel', '9'):         '5.14.0-611.49.2.el9_7',
    ('almalinux', '9'):    '5.14.0-611.49.2.el9_7',
    ('rocky', '9'):        '5.14.0-611.49.2.el9_7',
    ('cloudlinux', '9'):   '5.14.0-611.49.2.el9_7',
    # CL 8 (RHEL 8 base + CL .lve suffix). Operator on plain RHEL/Alma 8
    # should consult Red Hat erratum directly; we only ship a CL 8 baseline.
    ('cloudlinux', '8'):   '4.18.0-553.121.1.el8_10',
    # CL 7 not affected per CL advisory — no baseline shipped, applies_to
    # gates it out below.
}

# GRUB initcall blacklist token that disables algif_aead_init at boot.
# We match it both as a standalone command-line argument and as a value
# inside a comma-separated `initcall_blacklist=` list.
_MITIGATION_INITCALL = 'algif_aead_init'

# Architecture suffixes that may appear in `uname -r` output. Stripped
# before version comparison so '5.14.0-611.49.2.el9_7.x86_64' compares
# cleanly against the baseline '5.14.0-611.49.2.el9_7'.
_ARCH_SUFFIXES = ('.x86_64', '.aarch64', '.s390x', '.ppc64le', '.i686', '.armv7hl')


def _current_kernel():
    """Return the running kernel version-release with arch stripped, or ''."""
    rc, out = safe_run(['uname', '-r'])
    if rc != 0:
        return ''
    s = (out or '').strip()
    for arch in _ARCH_SUFFIXES:
        if s.endswith(arch):
            return s[:-len(arch)]
    return s


def _read_cmdline():
    """Read /proc/cmdline. Returns the string or ''."""
    try:
        with open('/proc/cmdline', 'r') as f:
            return f.read().strip()
    except (IOError, OSError):
        return ''


def _mitigation_active(cmdline):
    """True if /proc/cmdline contains the algif_aead_init initcall blacklist.

    Matches both forms:
        initcall_blacklist=algif_aead_init
        initcall_blacklist=foo,algif_aead_init,bar
    """
    if not cmdline:
        return False
    for token in cmdline.split():
        if token.startswith('initcall_blacklist='):
            value = token.split('=', 1)[1]
            entries = [e.strip() for e in value.split(',')]
            if _MITIGATION_INITCALL in entries:
                return True
    return False


class CopyFailCheck(Check):
    check_id = 'kernel_copy_fail'
    severity = Severity.CRITICAL
    description = ('Linux kernel patched against CVE-2026-31431 '
                   '(Copy Fail / algif_aead local priv-esc)')

    def applies_to(self, profile):
        # Linux only.
        if not profile.get('is_linux', True):
            return False
        # Skip CL 7 (not affected per advisory) and any non-EL distro
        # for which we don't ship a baseline. Unknown distros surface as
        # WARN inside run() rather than silent SKIPPED so the operator
        # knows the check ran.
        distro = (profile.get('distro_id') or '').lower()
        major = distro_major(profile.get('distro_version'))
        if distro == 'cloudlinux' and major == '7':
            return False
        return True

    def run(self, profile, previous=None):
        distro = (profile.get('distro_id') or '').lower()
        major = distro_major(profile.get('distro_version'))
        baseline = _MIN_PATCHED_KERNEL.get((distro, major))

        kernel = _current_kernel()
        cmdline = _read_cmdline()
        mitigated = _mitigation_active(cmdline)

        if not baseline:
            # No baseline for this distro/major. Don't claim CRITICAL —
            # surface as WARN so the operator knows the check ran but
            # couldn't decide. Include the cmdline check anyway so the
            # value is informative.
            return CheckResult.warning(
                detail=("no Copy Fail (CVE-2026-31431) baseline known for "
                        "{d}/{m} — manual review against vendor advisory "
                        "needed; current kernel: {k}").format(
                    d=distro or '?', m=major or '?', k=kernel or '?'),
                value={
                    'distro': distro, 'major': major,
                    'kernel': kernel, 'patched_min': '',
                    'mitigation_active': mitigated,
                },
                severity=Severity.LOW,
            )

        if not kernel:
            return CheckResult.errored(
                detail="couldn't determine current kernel via `uname -r`",
                value={'distro': distro, 'major': major,
                       'patched_min': baseline,
                       'mitigation_active': mitigated},
            )

        cmp = python_vercmp(kernel, baseline)
        value = {
            'distro': distro,
            'major': major,
            'kernel': kernel,
            'patched_min': baseline,
            'mitigation_active': mitigated,
        }

        # Patched kernel — definitive PASS regardless of mitigation flag.
        if cmp >= 0:
            mit_note = ""
            if mitigated:
                mit_note = (" (initcall_blacklist=algif_aead_init also active "
                            "— belt-and-braces, can be removed)")
            return CheckResult.passing(
                detail="kernel {k} >= {p} (CVE-2026-31431 patched){m}".format(
                    k=kernel, p=baseline, m=mit_note),
                value=value,
            )

        # Vulnerable kernel — severity depends on whether GRUB mitigation
        # is in place.
        if mitigated:
            return CheckResult.warning(
                detail=("kernel {k} below patched {p} BUT "
                        "initcall_blacklist=algif_aead_init is in /proc/cmdline "
                        "— mitigated for now. Patch the kernel before next "
                        "reboot in case the GRUB arg is removed; run "
                        "`dnf upgrade kernel` and reboot to clear this.").format(
                    k=kernel, p=baseline),
                value=value,
                severity=Severity.MEDIUM,
            )

        return CheckResult.failing(
            detail=("kernel {k} is BELOW patched {p} on {d}{maj} — "
                    "CVE-2026-31431 (Copy Fail) exploitable. Fix: "
                    "`dnf upgrade kernel && reboot` (preferred), OR "
                    "`grubby --update-kernel=ALL "
                    "--args=\"initcall_blacklist=algif_aead_init\"` and "
                    "reboot to mitigate without patching.").format(
                k=kernel, p=baseline, d=distro, maj=major),
            value=value,
            severity=Severity.CRITICAL,
        )
