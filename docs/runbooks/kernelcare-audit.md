# Runbook — KernelCare / kpatch / Ksplice audit

**Goal:** Confirm that every host running WP-Guardian has a kernel
livepatch service installed, subscribed (where applicable), and
actually applying patches to the running kernel.

**Why this matters:** Kernel CVEs are the highest-impact priv-esc
vector on a multi-tenant box. The traditional "upgrade kernel +
reboot" cycle takes weeks of operator effort across a fleet; a kernel
livepatch tool patches the running kernel binary in seconds, no
restart. Pairing `dnf-automatic` for userland with KernelCare/kpatch
for kernel closes Layer 1 of the layered defense (see
[../../SECURITY.md](../../SECURITY.md)).

**Prerequisite:** WP-Guardian v1.7.2+ deployed; `livepatch_state`
posture check operating.

---

## Provider options

| Provider | Cost | Distros | Service unit |
|---|---|---|---|
| **KernelCare** | Paid (typically bundled with CL subscription; standalone licence available) | EL family + Debian/Ubuntu | `kcare.service` (oneshot) + `kcare.timer` |
| **kpatch** | Free | RHEL 8+ / AlmaLinux 8+ / Rocky 8+ (upstream) | `kpatch.service` |
| **Ksplice** | Bundled with Oracle Linux Premier | Oracle Linux | `uptrack.service` |

For the **maiahost fleet** (CL + AlmaLinux 9 mix), KernelCare comes
with the CL subscription on most plans; the AlmaLinux-only hosts can
use kpatch for free.

For **third-party operators** of WP-Guardian: pick whichever is
cheapest given your distro and budget. The `livepatch_state` check
auto-detects whichever is installed and reports PASS regardless of
provider; if none is installed it returns PASS-with-note (not a
finding) so you're not nagged.

---

## 1. Check current state per host

Run this on each host:

```bash
# WP-Guardian's view of the livepatch posture
sudo python3 /opt/wp-guardian/wp-guardian.py --posture-run | grep -E 'livepatch_state|kernel_copy_fail|pwnkit'

# What it's reading from
sudo python3 /opt/wp-guardian/wp-guardian.py --posture-profile | grep -E 'livepatch|kernel|distro'

# Authoritative tool state
which kcarectl && kcarectl --info 2>&1 | head -10
which kpatch   && kpatch list 2>&1 | head -10
which uptrack-show && uptrack-show 2>&1 | head -10
ls /sys/kernel/livepatch/ 2>/dev/null
```

Expected outputs map to one of three states:

### State A — provider installed AND patching the kernel

Looks like (KernelCare example):
```
livepatch_state: pass    info  livepatch service active (kernelcare)
kernel_copy_fail: pass   info  kernel ... (CVE-2026-31431 patched)
```
And `kcarectl --info` shows `kpatch-state: patch is applied`.

**Action: nothing.** Done.

### State B — provider installed BUT no patch loaded

`livepatch_state` reports MEDIUM (FAIL) "kernelcare/kpatch installed
but the service is not active — kernel livepatches are not being
applied".

**Action: investigate.** Common causes:

```bash
# Is the timer running?
systemctl status kcare.timer    # KernelCare
systemctl status kpatch         # kpatch

# What does the service log say?
journalctl -u kcare.service -n 50 --no-pager
journalctl -u kpatch.service -n 50 --no-pager

# Subscription state (KernelCare-specific)
kcarectl --license-info

# Is there a network reach problem to the patch server?
kcarectl --update-debug 2>&1 | head -20
```

Most often: lapsed subscription, broken DNS, or operator forgot to
enable the timer after install. Fix the underlying cause; re-run
`--posture-run` to verify the finding clears.

### State C — no provider installed

`livepatch_state` reports PASS with a note about options. Not a
finding, but if you WANT livepatch coverage:

#### Install KernelCare (paid)

On a CL host with subscription:
```bash
# Most likely already installed; verify
rpm -q kernelcare

# If missing
sudo dnf install kernelcare
sudo systemctl enable --now kcare.timer
```

On a non-CL host with standalone KernelCare licence:
```bash
curl -s -L https://kernelcare.com/installer | sudo bash
sudo /usr/bin/kcarectl --register <activation-key>
sudo systemctl enable --now kcare.timer
```

#### Install kpatch (free, RHEL/Alma 8+)

```bash
sudo dnf install kpatch kpatch-dnf

# Subscribe to the patches for your kernel stream
sudo dnf kpatch auto

# Activate
sudo systemctl enable --now kpatch
```

After install, re-run `--posture-run` to verify state transitions to A.

---

## 2. Verify a specific CVE patch is applied

WP-Guardian's `kernel_copy_fail` check tells you whether the CVE is
mitigated overall, but if you specifically want to confirm a named CVE
is on the running kernel:

### KernelCare

```bash
sudo kcarectl --patch-info | grep -i CVE-2026-31431
```

Output looks like:
```
CVE-2026-31431  (Copy Fail / algif_aead local priv-esc)  applied: 2026-04-30
```

Or use `--info` for a summary:
```bash
sudo kcarectl --info
```

### kpatch

```bash
sudo kpatch list
```

Maps loaded patch modules to their kernel-version. Look up the kpatch
release notes for the CVE to confirm coverage.

### Ksplice

```bash
sudo uptrack-show
sudo uptrack-show --available     # what's available but not yet applied
```

---

## 3. Force a patch update

Most providers run on a daily timer. If you want to push an update
right now (after reading a CVE advisory, say):

```bash
# KernelCare
sudo kcarectl --update

# kpatch
sudo dnf upgrade kpatch-patch-*
sudo kpatch load <patch-module>     # if not auto-loaded

# Ksplice
sudo uptrack-upgrade -y
```

Then re-run `--posture-run` to confirm the finding clears.

---

## 4. Subscription audit (KernelCare specifically)

For paid KernelCare:

```bash
# License state
sudo kcarectl --license-info

# Server identification (for support / portal lookup)
sudo kcarectl --uname
sudo kcarectl --kernel-id
```

Cross-check the CloudLinux / KernelCare portal to confirm:
1. Subscription is active (not lapsed).
2. The host is registered.
3. The kernel stream you're on is in the patched-kernels list.

---

## 5. Roll out across the fleet

For each host:

```bash
# 1. SSH in
ssh root@<host>

# 2. Read current state (steps 1 above)

# 3. If State B: fix per the troubleshooting

# 4. If State C: install per provider instructions

# 5. Verify via WP-Guardian
sudo python3 /opt/wp-guardian/wp-guardian.py --posture-run | grep livepatch_state
sudo python3 /opt/wp-guardian/wp-guardian.py --posture-status

# 6. Document any non-default state in fleet inventory
```

For maiahost fleet, document per-host state in your runbook tracker
or commit a `fleet-state.md` somewhere private.

---

## What `livepatch_state` won't tell you

The check verifies the *service* is running and a patch is loaded. It
does NOT verify:

- That the loaded patch covers a *specific* CVE you care about. Use
  `kcarectl --patch-info` / `kpatch list` for that, paired with the
  named-CVE checks (`kernel_copy_fail`, `pwnkit`).
- That your subscription has billing-life remaining. Use
  `kcarectl --license-info` for that.
- That the patch is current. Most providers update daily; if you
  want a freshness check, parse `kcarectl --info` for the
  `kpatch-build-time:` field and compare against `now()`. Could be a
  follow-up posture check if drift becomes an issue.
