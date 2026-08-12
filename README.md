# WP-Guardian

Real-time security monitoring and automated threat response for WordPress hosting servers.

WP-Guardian monitors web, SMTP, IMAP/POP3, and SSH logs, automatically blocks attackers via your firewall, and sends alerts via Telegram. It features a three-tier escalation system (24h, 30d, permanent) and automatic CIDR /24 subnet aggregation for coordinated attacks.

## Features

- **Multi-service monitoring** — web access logs (OpenLiteSpeed, Apache combined, nginx; auto-detected per line), mail (Postfix + Dovecot), Roundcube webmail, SSH
- **Pluggable firewall backends** — CSF, firewalld, nftables, MikroTik, pfSense/OPNsense
- **CMS auto-detect (v1.5+)** — fingerprints each vhost on startup (WordPress / Joomla / Drupal / Magento / PrestaShop / OpenCart / phpMyAdmin) and uses that to dispatch CMS-specific rules; per-vhost overrides via optional `vhosts.conf`
- **POST-flood detector (v1.5+)** — generic catch-all for admin/auth POST flooding. Watchlist-only (registered admin paths + universal `/login`, `/signin`, `/phpmyadmin/`, etc.) plus a two-stage gate (rate threshold + behavioral confirmation: zero CSS / off-host Referer / uniform Content-Length) so it doesn't false-positive on offices behind shared NAT. Off by default, opt-in per server.
- **SSH root brute-force rule (v1.5+)** — `ssh_root` rule fires on the first `Failed password for root` attempt by default. Port-agnostic (works on sshd port 22, 69, or anything else).
- **Smart detection pipeline** — structural tripwires, known webshells, login isolation (CSS-based bot detection), brute force thresholds, PHP scanning detection, author enumeration, 404 storms
- **Posture audit + host-health module (v1.5+, expanded v1.6 + v1.7)** — daily read-only scan for security and operational drift. **22 checks shipped through v1.7.1**: kernel CVEs (`kernel_copy_fail` / `pwnkit`) — livepatch-aware (KernelCare / kpatch / Ksplice) so they don't false-alarm CRITICAL on hosts where binary patches are applied at runtime; generic distro security errata (`security_updates`, the long-tail successor to hand-coded per-CVE checks); kernel livepatch posture (`livepatch_state`); generic Linux (`/proc hidepid`, sshd config, listening ports, SUID drift, /tmp hygiene); defense-in-depth visibility (SELinux state, mod_security mode); multi-tenant + CloudLinux (tenant home perms 0711, public_html 0750, CageFS/LVE state, mod_hostinglimits, Apache vhost UID mapping); host-health (SMART with growth detection, disk usage, MTA queue, Apache worker saturation, DB connection/slow/buffer-pool, mod_security audit-log volume). Each check declares its applicability against an auto-detected host profile so a free single-site VPS only runs the generic Linux checks while a multi-tenant CL+Apache box gets the full set. Telegram alerts fire on transitions whose severity meets `[posture] alert_severity_min` (default `high`); recoveries silent by default.
- **Active /tmp cleanup module (v1.6+)** — opt-in daily janitor for stale, root-owned, world-readable, allowlisted files in /tmp. Three modes: `off` (default), `dry_run` (scan + log + Telegram digest), `live` (delete + log to `posture_events`). Strict criteria (realpath under /tmp, owner uid 0, mode o+r, age ≥ 7d, allowlist match, lsof-clean). Recommended rollout: enable as `dry_run` for ~14 days, review the digests, promote to `live`.
- **Credential compromise detection (v1.4+)** — `DistributedAuthDetector` catches the classic distributed credential-abuse botnet pattern (same mailbox authenticating from many countries/ASNs/IPs in a short window), automatically blocks source IPs, and disables the mailbox in the mail backend. Mailbox management works with any stack storing accounts in MySQL/MariaDB (CyberPanel, Postfixadmin, Mailcow, iRedMail, or a custom schema you name yourself) via a least-privilege, column-scoped DB user — see [INSTALL.md](INSTALL.md) Step 9. It's optional: without it Guardian still blocks and alerts
- **Abuse corroboration (v1.7.12+)** — geography selects candidates, abuse evidence authorises enforcement. Guardian looks for signs the account is actually being *misused* — a credential-stuffing failure burst, a sieve filter planted over ManageSieve, a forwarding row injected into the mail database — and uses them to promote a rule that geography alone leaves muted. The checks are deliberately **reconnaissance-phase**: a real takeover reads mail and plants persistence for days before it starts sending, so corroborating only on outbound spam would stay silent through the whole window where intervention is cheap. Every check fails toward "no signal" — an exception or a missing grant can never authorise disabling a client's mailbox
- **Outbound corroboration (v1.7.15+)** — the payload-phase counterpart to the above: Guardian records what a mailbox actually *sent* and corroborates on volume far above the account's own normal rate, or one message addressed to an implausible number of recipients. Postfix's queue ID is the join key and the join is mandatory — `qmgr` logs inbound and outbound mail identically, so counting it alone would measure how much mail *arrives* for an account and call it sending. Only a queue ID first seen on an authenticated `smtpd` line is counted, which also picks up PHP-originated mail relayed from a compromised website. The volume check compares each account against itself and is therefore **deliberately inert for its first two weeks** — on an empty table every account looks anomalous — but `backfill_maillog.py --outbound-only` replays your existing rotated logs and arms it on day one. Recipient fan-out needs no baseline at all. `--outbound-stats` shows what has accrued
- **Mail schema auto-detection (v1.7.12+)** — `--detect-mail-schema` reads what Postfix and Dovecot already declare about themselves (`postconf` map files, `password_query`, `mail_location`) and tells you the `[mail_backend]` settings and the exact `GRANT` they imply. No database credentials needed, so it runs before Guardian's own DB user exists, and it works across Postfixadmin / Mailcow / iRedMail / CyberPanel / custom schemas because the query text differs but the place you find it doesn't. It refuses to guess — a `JOIN`, an `ldap:` map or a chained map reports "could not determine" rather than a confident wrong table name
- **Compromise enforcement is per-rule and provisional (v1.7.11+)** — the three trigger rules are not equally trustworthy, so each carries its own `action_<rule>`. The ASN rule ships as `alert_only`: a multi-homed user with two fixed lines and a phone routinely reaches 4–5 ASNs inside one country, which is indistinguishable from credential abuse and produced two production false positives. And any mailbox disable is **reversed automatically after 4h** unless an operator confirms it with `/confirm <event_id>` — bounding a detection error to hours instead of "however long until someone notices an alert that landed at 02:00". Reversal is safe because the source IPs stay firewall-blocked on their own tier schedule
- **GeoIP enrichment (v1.4+)** — every auth event and block is tagged with country, city, ASN, and ASN organization via MaxMind GeoLite2
- **Three-tier escalation** — 24h block, 30d block, permanent ban with automatic tier advancement. An hourly reaper (v1.7.9+) actually enforces those durations: tier-1/tier-2 blocks are released when they expire and the tier is reset so repeat offenders still escalate, while tier 3 stays permanent. Clearing a false positive with `--unblock` resets the escalation ladder rather than arming the next rung
- **Cloud mail relay protection (v1.7.9+)** — IPs in a trusted ASN (Microsoft 365, Google Workspace, iCloud) are never firewall-dropped for mail rules or compromise handling. New Outlook syncs IMAP through Microsoft's cloud, so blocking a relay cuts off the legitimate client and stops no attacker — and per-IP whitelisting doesn't hold because those relays rotate. Scoped to mail services, so an Azure VM in the same ASN scanning `wp-login.php` is still blocked
- **No self-inflicted lockouts (v1.7.9+)** — when Guardian disables a mailbox after a compromise event, the owner's mail client turns into a failed-auth generator on every retry. Those failures no longer feed the brute-force ladder, provided the IP is a known client of that account
- **CIDR /24 aggregation** — auto-blocks entire subnets when coordinated scanning is detected
- **Authenticated user protection** — any successful login (WordPress, IMAP, POP3, SMTP, SSH) grants the IP a 24h grace period across all detectors, so a mail client with a wrong outgoing password can't get its working IMAP connection cut off
- **Telegram alerts** — real-time notifications for every block, with per-rule routing (v1.4.1+): mute noisy rules like `php_scan` / `general_404` / `author_enum`, digest others hourly, keep auth and compromise rules loud. Tune live via `/verbosity <rule> <level>` from chat — `compromise`, `cidr`, and `block_failed` are always-immediate and cannot be muted by accident
- **Telegram commands** — manage blocks, whitelists, and compromise events remotely via Telegram chat (`/status`, `/block`, `/unblock`, `/whitelist`, `/history`, `/authmap`, `/suspects`, `/disable`, `/enable`, `/compromises`, `/resolve`, `/confirm`)
- **Per-account auth map (v1.4+)** — `--auth-map`, `--auth-suspects`, `--hunt-compromises` for investigating account activity and surfacing pre-existing compromises
- **Automated tripwire discovery** — learns attack patterns from your access logs
- **Auto log discovery** — finds and monitors new access logs automatically
- **Update & rollback** — `git pull` + one command to update, with automatic backups

## Quick Start

Clone directly to `/opt/wp-guardian` so that future updates work with `git pull`:

```bash
sudo git clone https://github.com/Venetsian/guardian.git /opt/wp-guardian
cd /opt/wp-guardian
sudo bash install.sh
```

The interactive installer will walk you through choosing a firewall backend, setting up Telegram alerts, whitelisting your IPs, and discovering your access logs.

For detailed step-by-step instructions, see [INSTALL.md](INSTALL.md).

For the broader security strategy WP-Guardian fits into (threat model,
layered defense, hardening recommendations), see [SECURITY.md](SECURITY.md).

Operational runbooks for completing the layered defense (security-only
auto-updates, kernel livepatch audit) live in
[docs/runbooks/](docs/runbooks/).

## How It Works

```
Internet
    |
[Firewall]  <-- WP-Guardian blocks here
    |
[Your Server]
    |
[Access Logs] --> [WP-Guardian Daemon] --> [Detect] --> [Block] --> [Alert]
[Mail Logs]  -/                                |
[SSH Logs]  -/                                 v
                                         [SQLite DB]
                                     (history, tiers, stats)
```

The daemon runs three log tailers (web, mail, SSH) in background threads, each streaming new log lines to their detector. When a threat is detected, the blocker checks the whitelist, determines the escalation tier, executes the block via the configured firewall backend, records it in the database, and sends a Telegram alert.

## Commands

```bash
# Run / manage
python3 wp-guardian.py                           # Run daemon
python3 wp-guardian.py --dry-run                 # Watch only, don't block
systemctl start|stop|restart|status wp-guardian  # Service control

# Version & status
python3 wp-guardian.py --version                 # App version
python3 wp-guardian.py --db-version              # Schema version
python3 wp-guardian.py --status                  # Overview
python3 wp-guardian.py --history 1.2.3.4         # IP history
python3 wp-guardian.py --test-backend            # Test firewall connectivity

# Whitelist
python3 wp-guardian.py --whitelist-list
python3 wp-guardian.py --whitelist-add 1.2.3.4
python3 wp-guardian.py --whitelist-remove 1.2.3.4

# Tripwires
python3 wp-guardian.py --analyze-tripwires                   # Discover NEW candidates (manual review)
python3 wp-guardian.py --list-tripwires                      # Show top tripwires by hits
python3 wp-guardian.py --list-tripwires admin                # Search tripwires by pattern
python3 wp-guardian.py --remove-tripwire /path.php           # Remove a single tripwire
python3 wp-guardian.py --import-tripwires FILE               # Full import from file
python3 wp-guardian.py --import-tripwires-incremental FILE   # Add new only
python3 wp-guardian.py --flush tripwires                     # Clear all

# Logs
python3 wp-guardian.py --discover-logs           # Find access logs
python3 wp-guardian.py --discover-logs-save       # Find and save

# Telegram
python3 wp-guardian.py --telegram-setup          # Interactive setup wizard
python3 wp-guardian.py --telegram-test           # Send test message

# Posture audit (v1.5+)
python3 wp-guardian.py --posture-profile         # Show detected host profile
python3 wp-guardian.py --posture-profile --refresh  # Re-detect now
python3 wp-guardian.py --posture-run             # Run all applicable checks now
python3 wp-guardian.py --posture-status          # Current state of every check
python3 wp-guardian.py --posture-events          # Recent transitions

# Block / unblock
python3 wp-guardian.py --block 1.2.3.4               # block an IP permanently
python3 wp-guardian.py --block 1.2.3.4 --duration 24h  # block for 24h (tier 1)
python3 wp-guardian.py --block 1.2.3.0/24            # block a whole /24 (permanent)
python3 wp-guardian.py --block 1.2.3.0/24 --duration 30d
python3 wp-guardian.py --unblock 1.2.3.4            # remove block + reset escalation

# Block expiry (v1.7.9+) — normally automatic on the hourly loop
python3 wp-guardian.py --reap-blocks --dry-run       # preview what's overdue
python3 wp-guardian.py --reap-blocks                 # drain one batch now
python3 wp-guardian.py --reap-blocks --reap-limit 2000

# Provisional compromise disables (v1.7.11+) — also automatic on the hourly loop
python3 wp-guardian.py --reap-mailboxes --dry-run    # preview what's due for restore
python3 wp-guardian.py --reap-mailboxes             # restore them now

# Outbound corroboration (v1.7.15+)
python3 wp-guardian.py --outbound-stats              # is the volume baseline armed yet?
python3 wp-guardian.py --outbound-stats --days 30    # busiest senders, fan-out sizes
# Arm the baseline immediately from rotated logs instead of waiting 14 days
python3 tools/backfill_maillog.py --outbound-only --also-rotated --days 30 --dry-run
python3 tools/backfill_maillog.py --outbound-only --also-rotated --days 30

# Update
cd /opt/wp-guardian && git pull && sudo bash update.sh
sudo bash update.sh --rollback                   # Rollback last update
bash update.sh --status                          # Show versions

# If git pull fails with "local changes would be overwritten"
cd /opt/wp-guardian && git checkout -- . && git pull && sudo bash update.sh
```

## Telegram Commands

When `commands_enabled = true` in your `[telegram]` config, WP-Guardian polls for incoming Telegram messages and responds to commands. No webhooks or open ports needed — it uses Telegram's `getUpdates` long-polling.

**Security:** Only messages from the configured `chat_id` are processed. All other messages are silently ignored.

```
/status                      — block counts, IPs tracked, auth sessions, tripwires
/block <ip|cidr> [duration]  — manually block (default: permanent; e.g. 24h, 30d)
/unblock <ip>                — remove block and reset tier
/whitelist <ip>              — add permanently
/whitelist <ip> <duration>   — add temporarily (24h, 7d, 30d)
/whitelist remove <ip>       — remove from whitelist
/whitelist list              — show all entries
/history <ip>                — full IP history with recent blocks
/tripwires [search]          — list/search active tripwires
/remove <path>               — remove a tripwire path
/verbosity                   — show rule → level routing table
/verbosity <rule> <level>    — set immediate/digest/silent for a rule
/verbosity clear <rule>      — remove one override
/verbosity reset             — wipe all overrides

/sites [cms]                 — (v1.5+) detected vhosts, optional CMS filter
/site <name>                 — (v1.5+) full registry entry for one site
/cmsrefresh                  — (v1.5+) rebuild the CMS registry now
/logs                        — (v1.5+) log files being tailed + web-server type
/serverinfo                  — (v1.5+) version, firewall, feature flags

/help                        — list commands
```

Enable in `wp-guardian.conf`:

```ini
[telegram]
commands_enabled = true
commands_poll_timeout = 30    # long-poll timeout in seconds
```

## Detection Pipeline

Each web access log line goes through these checks in order (first match wins):

1. Auto-detect log format (OLS / Apache combined / nginx) and parse IP, method, path, status, referer, user-agent
2. **POST-flood watchlist** (v1.5+) — two-stage gate on registered admin paths; runs in parallel before WP-specific rules
3. Track CSS loads (browser fingerprint for login isolation)
4. Record successful WordPress logins (trusted for 24h)
5. Skip safe paths (`/wp-admin/`, `/wp-includes/`)
6. PHP in `/wp-content/uploads/` — instant block
7. Known webshells (alfa.php, c99.php, etc.) — instant block
8. Suspicious PHP patterns (random filenames) — block after 3 hits (authenticated IPs exempt since v1.7.10; tunable via `suspicious_threshold` / `suspicious_statuses` / `legit_php_paths`)
9. Tripwire paths from log analysis — instant block on 404/401/403
10. Login isolation — wp-login.php without CSS = bot — block after 3 hits
11. wp-login.php brute force — block after 10 failed POSTs
12. xmlrpc.php abuse — block after 5 hits
13. Author enumeration — block after 8 hits
14. PHP 404 scanning — block after 20 hits
15. General 404 storm — block after 50 hits

For SSH (`/var/log/secure`):
- `Invalid user` → instant block (`ssh_invalid`)
- `Failed password for root` → block after `ssh_root_fail_threshold` (default 1) (v1.5+, `ssh_root`)
- `Failed password` for any other user → block after `ssh_fail_threshold` (default 3) (`ssh_fail`)

## Posture Audit (v1.5+)

A separate read-only subsystem that runs daily and watches for **drift** rather than active attacks. Each check declares its applicability against an auto-detected host profile, so the catalog scales with the box: a single-site VPS only runs the generic Linux checks; a multi-tenant CloudLinux+Apache box gets the full set.

### Host profile

On first run (and every `profile_refresh_seconds`, default daily) guardian probes the host and stores a profile:

| Flag | Meaning |
|------|---------|
| `is_linux`, `distro_id`, `distro_version` | OS / distro family |
| `is_cloudlinux` | CloudLinux 8/9/10 detected (kmodlve loaded or distro ID match) |
| `is_multi_tenant` | At least 2 `/home/*` entries with `public_html` / `web` / `logs` subdirs |
| `is_single_site` | The opposite — at most one tenant-shaped /home entry |
| `web_server` | Detected from `systemctl is-active`: `ols`, `apache`, `nginx`, or `none` |
| `db_server`, `mta` | `mariadb`/`mysql`/`none`, `postfix`/`none` |
| `has_modsec` | mod_security config present |
| `behind_perimeter_firewall` | Operator-declared (config-driven; affects severity of port-binding checks) |
| `extras.is_virtualized` | `systemd-detect-virt` reports a hypervisor (kvm/qemu/vmware/xen/lxc); SMART check skips when true |

Override `is_multi_tenant` and `behind_perimeter_firewall` in `[posture]` if auto-detect is wrong for your setup.

### Storage

Two SQLite tables, both pruned automatically:

- `posture_state` — one row per `(host, module, check_id)`, upserted every run with current `status` (`pass` / `fail` / `warn` / `error` / `skipped`), `severity`, JSON `current_value`, `last_run_at`, `last_change_at`.
- `posture_events` — append-only log of transitions (status or value change) with a 30-day TTL. Inserted only when a check actually changes — quiet steady-state, full forensic trail when something drifts.

### Telegram alerts

Fire only on transitions whose severity meets `[posture] alert_severity_min` (default `high`). On the very first run after install, only `critical` transitions alert — bootstrap dampening prevents a fresh deploy from flooding your chat with the initial state of every check. After the second run, the configured floor takes over.

### Adding a new check

Drop a new file in `posture_checks/`:

```python
from posture_checks.base import Check, CheckResult, Severity, Status

class MyCheck(Check):
    check_id = 'my_thing'
    severity = Severity.HIGH
    description = 'short human description'

    def applies_to(self, profile):
        # Return True only on hosts where this check makes sense.
        return profile.get('is_cloudlinux') and profile.get('is_multi_tenant')

    def run(self, profile):
        if all_good():
            return CheckResult.passing(detail='looks fine')
        return CheckResult.failing(
            detail='something drifted: ...',
            value={'measured': 123},
        )
```

Register it in `posture_checks/__init__.py` (`ALL_CHECKS = [...]`). The orchestrator handles persistence, transition diffing, and alerting — checks just declare applicability and produce a `CheckResult`.

## Firewall Backends

WP-Guardian supports pluggable firewall backends. Choose one in `wp-guardian.conf`:

```ini
[firewall]
backend = csf       # or: firewalld, nftables, mikrotik, pfsense, opnsense
flush_conntrack = true   # firewalld/nftables: tear down live connections on block
```

| Backend | Blocks At | Best For |
|---------|-----------|----------|
| CSF | Server (iptables) | Standalone servers with CSF installed |
| firewalld | Server (rich rules) | RHEL/AlmaLinux, CyberPanel 2.4+ |
| nftables | Server (nft sets) | Modern Linux, minimal setups |
| MikroTik | Network edge (router) | Dedicated networks with MikroTik hardware |
| pfSense / OPNsense | Network edge (appliance) | Networks with pfSense/OPNsense firewalls |

See [backends/README.md](backends/README.md) for creating custom backends.

> **firewalld/nftables — install `conntrack` (recommended).** Stateful firewalls
> accept already-established connections before the block rule runs, so without
> conntrack a block only stops *new* connections — an attacker on HTTP keep-alive
> keeps flooding until the connection closes. With `[firewall] flush_conntrack =
> true` (default), Guardian runs `conntrack -D -s <ip>` after each block so live
> connections drop in under a second. Install the CLI:
> `dnf install -y conntrack-tools` (RHEL/AlmaLinux) or `apt install -y conntrack`
> (Debian/Ubuntu). Missing it is a safe no-op; Guardian warns at startup.

## v1.5 Configuration

The full reference is in [`wp-guardian.conf.example`](wp-guardian.conf.example). The options most operators will touch:

### CMS auto-detect

```ini
[cms_detection]
enabled = true
refresh_interval = 21600          # 6h — how often to re-fingerprint vhosts
vhosts_overrides = /opt/wp-guardian/vhosts.conf
```

The registry walks `logfiles.txt`, derives site names from `/home/<site>/logs/...`, and fingerprints each docroot. To check what was detected: `/sites` from Telegram, or `--status` includes a tally.

### Per-vhost overrides — `vhosts.conf`

Drop this file next to `wp-guardian.conf` to override auto-detect or declare a renamed admin path. Empty / missing = pure auto-detect.

```ini
[example.com]
cms = joomla
admin_paths = /sekret-admin/index.php, /administrator/index.php

[shop.com]
cms = wordpress
post_flood_threshold = 50         # raise threshold for high-traffic vhost
```

Force an immediate rebuild after editing: `/cmsrefresh` from Telegram, or restart the daemon.

### POST-flood detector

Off by default. Enable on servers running non-WordPress CMSes:

```ini
[post_flood]
enabled = true
threshold = 30                    # POSTs per IP per URL within window
window = 300                      # 5 min
behavioral_required = true        # require at least one bot signal — keep this ON
behavioral_referer_pct = 80
behavioral_content_length_pct = 80
universal_paths =                 # comma-separated; extends built-in defaults
```

Built-in always-watched paths: `/phpmyadmin/`, `/cpanel`, `/login`, `/signin`, `/admin/login`, `/admin/index.php`. Per-CMS paths come from the CMS detector skeletons (Joomla → `/administrator/index.php`, Drupal → `/user/login`).

Default verbosity is `digest` — alerts batch hourly so you can observe the FP profile before promoting. After 1–2 weeks of clean data:

```
/verbosity post_flood immediate
```

### SSH root brute force

```ini
[thresholds]
ssh_fail_threshold = 3            # regular users
ssh_root_fail_threshold = 1       # v1.5+ — root attempts (1 = instant block)
                                  # set to 0 to disable the dedicated root rule
```

If you legitimately SSH as root from automation, whitelist its IP first or set `ssh_root_fail_threshold = 0`.

### Suspicious PHP scanning (v1.7.10+)

The `suspicious` rule matches **any** lowercase `.php` filename of 6+ letters, so your own application endpoints can trip it. Since v1.7.10 an IP that has authenticated on any service within `wp_trust_duration` is exempt, the same as every other tripwire rule — but three knobs are available for the pre-login case:

```ini
[thresholds]
suspicious_threshold = 3               # pattern hits within time_window before blocking
suspicious_statuses = 404, 401, 403    # which statuses count as scanning evidence

[whitelist]
legit_php_paths = /billing.php, /account.php
```

Built-in exemptions: `/api.php`, `/ajax.php`, `/public.php`, `/cron.php`, `/rss.php`, `/feed.php`, `/client.php`, `/index.php`. `legit_php_paths` adds to that set, it does not replace it.

**On `suspicious_statuses`:** 404 is the classic enumeration signature, but deny-heavy installs (Apache/nginx `deny`, ModSecurity, CyberPanel) answer scans with **403** instead — on one Apache host in our fleet 403 outnumbers 404 on these paths by roughly 100:1, so the default counts all three. Narrow it to `404` only if this server fronts a customer portal whose PHP endpoints return application-level 403s to logged-in users.

### Remote troubleshooting

All of the above is observable from Telegram once `commands_enabled = true`:

- `/serverinfo` — version, firewall, feature flags at a glance
- `/sites` — what CMS each vhost was detected as
- `/site <name>` — full registry entry for one vhost
- `/logs` — log files being tailed and inferred web-server type
- `/cmsrefresh` — rebuild the CMS registry without restarting

## File Structure

```
/opt/wp-guardian/
├── wp-guardian.py          # Main daemon + CLI (~1200 lines after v1.5 refactor)
├── wp-guardian.conf        # Configuration (chmod 600!)
├── vhosts.conf             # Optional per-vhost CMS / admin-path overrides (v1.5+)
├── VERSION                 # Application version
├── update.sh               # Update with backup/rollback
├── whitelist.conf          # Never-block IPs
├── tripwires.txt           # Attack paths from log analysis
├── logfiles.txt            # Monitored access log paths
├── detectors/              # v1.5+ — one detector per file
│   ├── base.py             # HitTracker (shared sliding-window counter)
│   ├── log_formats.py      # OLS / Apache / nginx access-log parser
│   ├── web.py              # WordPress-focused web detector
│   ├── mail.py             # Postfix + Dovecot detector
│   ├── ssh.py              # sshd detector (incl. v1.5 ssh_root rule)
│   ├── roundcube.py        # Roundcube errors.log detector
│   ├── distributed_auth.py # Cross-protocol compromise detector
│   ├── post_flood.py       # Two-stage POST-flood detector (v1.5+)
│   ├── cms_base.py         # Per-CMS detector base class (v1.5+)
│   ├── joomla.py           # Joomla skeleton (v1.5; auth-failure detect lands in v1.6+)
│   └── drupal.py           # Drupal skeleton  (same status)
├── modules/
│   ├── database.py         # SQLite data layer
│   ├── config.py           # Config loader
│   ├── whitelist.py        # Three-source whitelist manager
│   ├── blocker.py          # Block decision engine
│   ├── geoip.py            # MaxMind GeoLite2 lookup
│   ├── compromise.py       # CompromiseAction (block IPs + disable mailbox)
│   ├── corroboration.py    # Abuse evidence that authorises enforcement (v1.7.12+)
│   ├── outbound.py         # Queue-ID correlation for sent mail (v1.7.15+)
│   ├── mail_schema.py      # Postfix/Dovecot schema auto-detection (v1.7.12+)
│   ├── digest.py           # Hourly Telegram digest buffer
│   ├── verbosity.py        # Per-rule alert routing
│   ├── cms_registry.py     # Auto-detected vhost → CMS map (v1.5+)
│   ├── host_profile.py     # Posture-audit host profile detector (v1.5+)
│   ├── posture.py          # Posture-audit orchestrator (v1.5+)
│   ├── tmp_cleanup.py      # Active /tmp janitor (v1.6+, opt-in)
│   ├── mail_backend.py     # MariaDB mailbox-disable integration
│   ├── conntrack.py        # Flush live connections on block (v1.7.7+)
│   └── migrator.py         # Database migration runner
├── posture_checks/         # v1.5+ — one posture/health check per file
│   ├── base.py             # Check ABC, CheckResult, Severity/Status enums
│   ├── _utils.py           # Shared helpers: vercmp, distro_major, safe_run
│   ├── check_copy_fail.py  # CVE-2026-31431 kernel priv-esc (algif_aead)
│   ├── check_pwnkit.py     # CVE-2021-4034 polkit version (PwnKit)
│   ├── check_hidepid.py    # /proc hidepid=invisible
│   ├── check_smart.py      # SMART drive health + growth detection
│   ├── check_tmp_hygiene.py            # /tmp bloat (v1.6+)
│   ├── check_sshd_config.py            # sshd auth options (v1.6+)
│   ├── check_listening_ports.py        # listening TCP/UDP inventory (v1.6+)
│   ├── check_suid_baseline.py          # SUID/SGID drift (v1.6+)
│   ├── check_tenant_home_perms.py      # /home/<tenant> 0711 (v1.6+)
│   ├── check_public_html_perms.py      # public_html 0750 (v1.6+)
│   ├── check_cagefs_state.py           # CL CageFS/LVE active (v1.6+)
│   ├── check_mod_hostinglimits.py      # Apache+CL mod_hostinglimits (v1.6+)
│   ├── check_apache_vhost_uid.py       # tenant vhost PHP uid: Apache directive / per-user FPM / suEXEC (v1.6+, FPM-aware v1.7.6)
│   ├── check_disk_usage.py             # disk usage on key partitions (v1.6+)
│   ├── check_mta_queue.py              # postfix queue depth (v1.6+)
│   ├── check_worker_saturation.py      # Apache BusyWorkers / Max (v1.6+)
│   ├── check_db_health.py              # DB conn / slow / hit rate (v1.6+)
│   ├── check_modsec_volume.py          # mod_security audit volume (v1.6+)
│   ├── check_security_updates.py       # distro security errata feed (v1.7+)
│   ├── check_selinux.py                # SELinux runtime state (v1.7+)
│   ├── check_modsec_mode.py            # mod_security SecRuleEngine mode (v1.7+)
│   └── check_livepatch_state.py        # KernelCare/kpatch/Ksplice (v1.7.1+)
├── backends/
│   ├── base.py             # Firewall backend interface (ABC)
│   ├── factory.py          # Backend registry + instantiation
│   ├── csf.py              # CSF backend
│   ├── firewalld.py        # firewalld backend (conntrack flush v1.7.7+)
│   ├── nftables.py         # nftables backend (conntrack flush v1.7.7+)
│   ├── mikrotik.py         # MikroTik backend
│   ├── pfsense.py          # pfSense / OPNsense backend
│   └── README.md           # Backend developer guide
├── actions/
│   ├── telegram.py         # Telegram alerts
│   └── telegram_commands.py # Telegram command handler
├── tools/
│   ├── telegram_setup.py        # Interactive Telegram setup
│   ├── log-analyzer.sh          # Tripwire discovery
│   ├── backfill_maillog.py      # Seed auth_sessions from maillog history
│   ├── backfill_ip_history.py   # Geo-enrich ip_history rows (v1.4.2+ repair)
│   └── config-upgrade.py        # Detect & merge new config options on upgrade
├── tests/                   # stdlib unittest, no test deps
│   ├── test_web_suspicious.py    # Regression tests for the suspicious rule (v1.7.10+)
│   ├── test_compromise_action.py # Per-rule enforcement + provisional disables (v1.7.11+)
│   ├── test_corroboration.py     # Fail-safe direction per abuse check (v1.7.12+)
│   ├── test_mail_schema.py       # Schema detection refusals (v1.7.12+)
│   └── test_outbound.py          # Queue-ID join + outbound signals (v1.7.15+)
├── migrations/
│   └── *.sql               # Database migrations (009_block_cleared_at, 010_compromise_confirmed_at, 011_outbound_activity)
├── state/
│   └── guardian.db          # SQLite database
└── logs/
    ├── guardian.log         # Main activity log
    └── blocked.log          # Block actions log
```

## Requirements

- Python 3.6+ (tested with 3.6.8)
- SQLite3 (built into Python)
- `requests` Python module (for Telegram alerts)
- Root access
- One supported firewall (CSF, firewalld, nftables, MikroTik, or pfSense/OPNsense)

## License

MIT License. See [LICENSE](LICENSE).

## Contributing

Contributions welcome! Areas where help is especially appreciated:

- Geographic anomaly detection (schema exists, implementation needed)
- AbuseIPDB integration
- Additional log format parsers (Apache, Nginx direct)
- Testing on different Linux distributions
- New firewall backends
