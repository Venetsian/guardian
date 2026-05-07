# Runbook — `dnf-automatic` for security-only auto-updates

**Applies to:** RHEL / AlmaLinux / Rocky / CloudLinux 8 + 9 + 10 (any
distro using `dnf`). For EL/CL 7 see the equivalent `yum-cron` setup.

**Goal:** Apply vendor security errata daily, automatically, for every
package that doesn't need a careful restart. Kernel, web server,
database, and mail server packages stay manual.

**Prerequisite:** WP-Guardian v1.7.0+ deployed; `security_updates`
posture check operating.

---

## 1. Pre-flight (read-only checks)

```bash
# Confirm we're on a DNF-based distro
which dnf

# Confirm dnf-automatic is available in repos
dnf info dnf-automatic | head -10

# See what security errata are pending RIGHT NOW
dnf updateinfo list security --quiet | head -20

# WP-Guardian's view of the same — should match in count
python3 /opt/wp-guardian/wp-guardian.py --posture-run | grep security_updates
```

If `security_updates` reports HIGH or CRITICAL, **install pending
errata manually first** (see step 4) before automating — you don't want
a half-decade of skipped patches landing in one cron run.

## 2. Install

```bash
sudo dnf install -y dnf-automatic
```

This installs the binary, three systemd timer units, and the default
config at `/etc/dnf/automatic.conf`.

## 3. Configure `/etc/dnf/automatic.conf`

Edit the file. Key options:

```ini
[commands]
# What to do — "security" pulls only security-tagged errata
upgrade_type = security

# Apply automatically (vs download-only)
download_updates = yes
apply_updates = yes

# Keep dnf history clean
random_sleep = 360

[emitters]
# Where to send the report — system_email is the default; can be
# stdio, motd, or email. WP-Guardian's `security_updates` check is
# the operator's primary signal anyway.
emit_via = stdio

[base]
# Inherit defaults from /etc/dnf/dnf.conf
debuglevel = 1
```

## 4. Configure exclude list in `/etc/dnf/dnf.conf`

Append to the `[main]` section:

```ini
exclude=kernel* kernel-core* kernel-modules* lshttpd lsws httpd* nginx* mariadb* mariadb-server* mysql* mysql-server* postfix* dovecot* lsphp*
```

**Why exclude these specifically:**

| Package | Why manual |
|---|---|
| `kernel*` | Needs reboot. KernelCare/kpatch livepatches in the meantime. |
| `lshttpd`, `lsws`, `httpd*`, `nginx*` | Needs careful restart with config validation; could break sites. |
| `mariadb*`, `mysql*` | Needs restart that drops connections; do during maintenance window. |
| `postfix*`, `dovecot*` | Mail in flight could be lost during a noisy restart. |
| `lsphp*` | Restart of PHP processes drops in-flight requests. |

Then either:
- Enable KernelCare/kpatch for the kernel half (Layer 1b — see
  [kernelcare-audit.md](kernelcare-audit.md)), or
- Schedule a monthly maintenance window for the manual half.

## 5. Pre-flight the configuration

```bash
# Dry-run: see what WOULD happen on next firing
sudo dnf-automatic --downloadupdates --installupdates --timer

# Or just inspect the cache
sudo dnf updateinfo list security --quiet
```

If the dry run looks reasonable (small number of packages, no
unexpected exclusions failing), proceed.

## 6. Enable the timer

```bash
sudo systemctl enable --now dnf-automatic.timer

# Verify
systemctl list-timers dnf-automatic.timer
```

The default schedule fires once a day with a randomized 0–360 second
jitter (the `random_sleep` we set above).

## 7. Monitor

```bash
# Last run state
systemctl status dnf-automatic.service

# Detailed log
journalctl -u dnf-automatic.service -n 100 --no-pager

# DNF transaction history (what was actually applied)
sudo dnf history list | head -10
sudo dnf history info last
```

After the first successful run, WP-Guardian's `security_updates`
posture check should drop to PASS (assuming you're not behind on
non-excluded packages). Subsequent runs catch you up daily.

## 8. Disable / rollback

If something needs to revert:

```bash
sudo systemctl disable --now dnf-automatic.timer
```

Pinning a single package back to an older version:

```bash
# Find the prior version
sudo dnf history list <pkg>
# Or roll back the most recent transaction
sudo dnf history rollback <transaction-id>
```

## Verification — expected WP-Guardian state after rollout

After the first daily firing on each box:

| Check | Expected on a healthy host |
|---|---|
| `security_updates` | PASS (or LOW if there's pending errata in your manual-restart bucket) |
| `livepatch_state` | PASS (KernelCare/kpatch active) — see [kernelcare-audit.md](kernelcare-audit.md) |
| `kernel_copy_fail` and other named-CVE checks | PASS |

## Per-host notes

Each box in the maiahost fleet has slightly different exclusion needs.
Adjust the `exclude=` list in `/etc/dnf/dnf.conf` per role:

- **Web hosts** (web.maiahost.com, wp.maiahost.com, srv.dotcom.services):
  exclude OLS / Apache / lsphp / mariadb / postfix / dovecot per the
  list above.
- **Mail host** (mail.maiahost.com): same plus extra care around
  `dovecot*`, `postfix*`, `opendkim*`, `opendmarc*`, `roundcubemail*`.
- **Pure DB hosts** (none currently): exclude only `mariadb*`,
  `mysql*`.

---

## Why we don't auto-apply everything

The "apply security errata daily" model is a leaky abstraction:

1. The distro security team tags errata as `security`, but a
   "Moderate" CVE in a deeply-linked library can still cascade
   restart requirements that aren't obvious.
2. Some CVEs in shipped-but-disabled features get tagged anyway; the
   restart is unneeded but the package list churns.
3. Major version bumps occasionally arrive in security tracks
   (e.g. polkit going 0.117 → 121 was a security update on EL10).

So we let the long tail auto-update (the volume is high, the per-
update risk is low, the time-saved is huge), and we keep manual
control over the small set of packages whose restart impacts user-
facing services. The exclude list is the contract between automation
and operator judgement.
