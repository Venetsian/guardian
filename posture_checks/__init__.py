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
from posture_checks.check_tmp_hygiene import TmpHygieneCheck
from posture_checks.check_sshd_config import SshdConfigCheck
from posture_checks.check_listening_ports import ListeningPortsCheck
from posture_checks.check_suid_baseline import SuidBaselineCheck
from posture_checks.check_tenant_home_perms import TenantHomePermsCheck
from posture_checks.check_public_html_perms import PublicHtmlPermsCheck
from posture_checks.check_cagefs_state import CageFSStateCheck
from posture_checks.check_mod_hostinglimits import ModHostinglimitsCheck
from posture_checks.check_apache_vhost_uid import ApacheVhostUidCheck
from posture_checks.check_disk_usage import DiskUsageCheck
from posture_checks.check_mta_queue import MtaQueueCheck
from posture_checks.check_worker_saturation import WorkerSaturationCheck
from posture_checks.check_db_health import DbHealthCheck
from posture_checks.check_modsec_volume import ModsecVolumeCheck

ALL_CHECKS = [
    CopyFailCheck,            # CVE-2026-31431 — high-priority current kernel CVE
    PwnKitCheck,              # CVE-2021-4034 — long-known polkit priv-esc
    HidePidCheck,             # /proc cross-tenant isolation
    SmartCheck,               # drive health with growth detection
    TmpHygieneCheck,          # /tmp bloat (passive LOW signal)
    SshdConfigCheck,          # sshd auth options
    ListeningPortsCheck,      # listening TCP/UDP inventory
    SuidBaselineCheck,        # new/modified SUID binaries
    TenantHomePermsCheck,     # /home/<tenant> 0711
    PublicHtmlPermsCheck,     # public_html 0750 + web-server group
    CageFSStateCheck,         # CL CageFS / LVE active
    ModHostinglimitsCheck,    # Apache+CL tenant LVE binding
    ApacheVhostUidCheck,      # tenant vhost UID assignment
    DiskUsageCheck,           # disk usage on key partitions
    MtaQueueCheck,            # postfix queue depth
    WorkerSaturationCheck,    # Apache BusyWorkers / MaxRequestWorkers
    DbHealthCheck,            # MariaDB/MySQL connection + slow + hit-rate
    ModsecVolumeCheck,        # mod_security audit log rotation health
]

__all__ = [
    'Check',
    'CheckResult',
    'Severity',
    'Status',
    'Module',
    'ALL_CHECKS',
]
