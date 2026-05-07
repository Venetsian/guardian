# Security Policy

## Reporting a vulnerability

If you discover a security issue in WP-Guardian itself (the daemon, the
firewall backends, the detectors, the database layer, or the install
scripts), please report it privately rather than opening a public
GitHub issue.

Open a private security advisory on GitHub:
<https://github.com/Venetsian/guardian/security/advisories/new>

You can expect:
- Acknowledgement within 7 days
- An initial assessment within 14 days
- Coordinated disclosure: we'll work with you on a timeline that gives
  operators time to upgrade before the issue becomes public.

## Threat model

WP-Guardian is designed for **multi-tenant shared web hosting** —
typically a single physical or virtual host running dozens of
unrelated WordPress / Joomla / Drupal / Magento sites for different
end customers. The threat model assumes:

- The host is internet-facing and continuously under low-grade
  scanning + brute-force pressure.
- Tenants are mutually-untrusted: a compromise of one site (XSS,
  webshell, plugin RCE, leaked FTP credentials) must not become a
  compromise of others.
- The operator is technical but not 24/7. Detection and response
  must be automatable; alerts go to Telegram or email.
- The kernel and userland are kept reasonably current but on a
  budget — a paid kernel-livepatch subscription (KernelCare, kpatch
  pro) is common but not universal.

WP-Guardian focuses on **observable activity in logs** (web, mail,
SSH) and **observable host state** (perms, kernel CVE status, listening
ports). It deliberately does NOT do active scanning, in-memory
forensics, or kernel-module-based intrusion detection — those are
better served by other tools (Imunify360, AIDE, Falco, etc.).

## Layered defense — how the pieces fit together

WP-Guardian implements its piece of a five-layer defense:

### Layer 1 — Patch faster (highest leverage)

The single biggest reduction in real-world exposure on a shared-host
box. Two pieces:

- **`dnf-automatic`** for security-only auto-updates. Daily apply of
  vendor errata for non-restart-sensitive packages (sudo, openssl,
  glibc, libxml2, polkit, etc.); kernel/web-server/database packages
  excluded so the operator stays in control of restart timing.
  See [docs/runbooks/dnf-automatic.md](docs/runbooks/dnf-automatic.md).
- **Kernel livepatch** (KernelCare, kpatch, Ksplice). Binary patches
  the running kernel for CVEs without reboot. Most CL subscriptions
  include KernelCare; kpatch is free on RHEL 8+ / AlmaLinux 8+.
  See [docs/runbooks/kernelcare-audit.md](docs/runbooks/kernelcare-audit.md).

WP-Guardian's `security_updates` and `livepatch_state` checks surface
the state of both daily.

### Layer 2 — Self-updating CVE detection in posture-audit

Hand-coded per-CVE checks (`pwnkit`, `kernel_copy_fail`) don't scale
to the AI-accelerated CVE disclosure rate. The `security_updates`
check consults the distro security team's curated errata feed
(`dnf updateinfo list security` on EL family, `apt list --upgradable`
filtered for `*-security` on Debian/Ubuntu) and surfaces pending
errata by severity class. Named-CVE checks stay in place as overrides
for high-priority bugs where distro tagging is too quiet.

### Layer 3 — Defense-in-depth so a successful exploit has limited blast radius

- **CageFS / LVE** (CloudLinux) — per-tenant kernel-level filesystem
  jails. `cagefs_state` check verifies it's active.
- **`mod_hostinglimits` / OLS extprocessor** — per-vhost UID
  enforcement, so a compromised PHP process can only see its own
  tenant's files.
- **Tenant home perms 0711, public_html 0750** — cross-tenant
  isolation at the filesystem layer. Verified by `tenant_home_perms`
  and `public_html_perms` checks.
- **`/proc hidepid=invisible`** — prevents one tenant from reading
  another's process command lines (which often contain credentials
  passed as argv).
- **SELinux Enforcing** — confines exploit fallout regardless of
  application-layer flaws.
- **mod_security blocking mode** — Apache/OLS WAF actually blocking
  attacks rather than just logging them.

### Layer 4 — Behavioral / integrity detection

Catches what Layers 1–3 miss:

- **`DistributedAuthDetector`** — same mailbox / SSH user authenticating
  from many countries / ASNs / IPs in a short window indicates a
  successful credential compromise; auto-blocks source IPs and
  optionally disables the mailbox.
- **POST-flood detector** (v1.5+) — generic admin-page brute force
  with behavioral confirmation (no CSS, no Referer, uniform
  Content-Length).
- **(Future)** outbound SMTP volume monitoring; AIDE file integrity
  monitoring on `/usr/bin`, `/usr/sbin`, `/etc`.

### Layer 5 — Out-of-band human review

WP-Guardian doesn't replace the operator subscribing to:

- Vendor advisories: CloudLinux blog/email; AlmaLinux / RHEL errata
  RSS; Debian / Ubuntu security announce mailing lists.
- General disclosure: <oss-security@lists.openwall.com> — low
  traffic, very high signal.
- Hosting peer network for early intel before public disclosure.

## What WP-Guardian does NOT protect against

- Application-layer vulnerabilities in the hosted CMSes (those are
  the WAF's / WordFence's job; WP-Guardian observes the resulting
  brute-force / scanning patterns and blocks the attackers, but
  doesn't patch the underlying RCE).
- Insider threats from the operator account.
- Compromise of upstream package repositories (supply-chain attacks
  on the distro itself).
- DDoS at the network layer (use a CDN / scrubbing service).
- Kernel zero-days with no patch + no mitigation available
  (Layer 5 review is the only answer here).

## Hardening recommendations for new deployments

1. Run as `root` via systemd (the default `install.sh` does this).
2. Use a perimeter firewall in front of the host and set
   `[posture] behind_perimeter_firewall = true` so the listening-port
   and sshd-config checks tune their severity correctly.
3. Configure Telegram alerts; the `[telegram.rules]` per-rule routing
   lets you mute noisy rules without losing the high-signal ones.
4. Enable `dnf-automatic` per the runbook above; keep kernel updates
   manual.
5. Verify your KernelCare/kpatch subscription is active via
   `wp-guardian.py --posture-run` and look at the `livepatch_state`
   check.
6. Set `[tmp_cleanup] mode = dry_run` for the first ~14 days, review
   the digests, then promote to `live`.
7. Subscribe to the upstream advisories listed in Layer 5 above.

## Versioning and security backports

WP-Guardian uses semantic versioning. Security fixes ship as patch
releases and are documented in [CHANGELOG.md](CHANGELOG.md). Operators
on the `main` branch can apply via `git pull && sudo bash update.sh`.
There is no separate `security` branch — `main` is the only supported
deployment target.
