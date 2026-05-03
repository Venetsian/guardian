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
- **Posture audit + host-health module (v1.5+)** — daily read-only scan for security and operational drift (PwnKit/polkit version, `/proc hidepid`, **SMART drive health with growth detection** — alerts on new reallocated/pending/uncorrectable sectors and SSD endurance thresholds, telling you when to plan or expedite drive replacement). More checks added incrementally — SUID drift, sshd config, listening ports, tenant home perms, mod_hostinglimits / mod_lsapi UID switching, CageFS state, disk usage, worker saturation, DB health, modsec volume, MTA queue. Each check declares its applicability against an auto-detected host profile so a free single-site VPS only runs the generic Linux checks while a multi-tenant CL+Apache box gets the full set. Telegram alerts fire on transitions whose severity meets `[posture] alert_severity_min` (default `high`).
- **Credential compromise detection (v1.4+)** — `DistributedAuthDetector` catches the classic distributed credential-abuse botnet pattern (same mailbox authenticating from many countries/ASNs/IPs in a short window), automatically blocks source IPs, and disables the mailbox in the mail backend
- **GeoIP enrichment (v1.4+)** — every auth event and block is tagged with country, city, ASN, and ASN organization via MaxMind GeoLite2
- **Three-tier escalation** — 24h block, 30d block, permanent ban with automatic tier advancement
- **CIDR /24 aggregation** — auto-blocks entire subnets when coordinated scanning is detected
- **Authenticated user protection** — any successful login (WordPress, IMAP, POP3, SMTP, SSH) grants the IP a 24h grace period across all detectors, so a mail client with a wrong outgoing password can't get its working IMAP connection cut off
- **Telegram alerts** — real-time notifications for every block, with per-rule routing (v1.4.1+): mute noisy rules like `php_scan` / `general_404` / `author_enum`, digest others hourly, keep auth and compromise rules loud. Tune live via `/verbosity <rule> <level>` from chat — `compromise`, `cidr`, and `block_failed` are always-immediate and cannot be muted by accident
- **Telegram commands** — manage blocks, whitelists, and compromise events remotely via Telegram chat (`/status`, `/unblock`, `/whitelist`, `/history`, `/authmap`, `/suspects`, `/disable`, `/enable`, `/compromises`, `/resolve`)
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

# Unblock
python3 wp-guardian.py --unblock 1.2.3.4

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
8. Suspicious PHP patterns (random filenames) — block after 3 hits
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
```

| Backend | Blocks At | Best For |
|---------|-----------|----------|
| CSF | Server (iptables) | Standalone servers with CSF installed |
| firewalld | Server (rich rules) | RHEL/AlmaLinux, CyberPanel 2.4+ |
| nftables | Server (nft sets) | Modern Linux, minimal setups |
| MikroTik | Network edge (router) | Dedicated networks with MikroTik hardware |
| pfSense / OPNsense | Network edge (appliance) | Networks with pfSense/OPNsense firewalls |

See [backends/README.md](backends/README.md) for creating custom backends.

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
│   ├── digest.py           # Hourly Telegram digest buffer
│   ├── verbosity.py        # Per-rule alert routing
│   ├── cms_registry.py     # Auto-detected vhost → CMS map (v1.5+)
│   ├── host_profile.py     # Posture-audit host profile detector (v1.5+)
│   ├── posture.py          # Posture-audit orchestrator (v1.5+)
│   ├── mail_backend.py     # MariaDB mailbox-disable integration
│   └── migrator.py         # Database migration runner
├── posture_checks/         # v1.5+ — one posture/health check per file
│   ├── base.py             # Check ABC, CheckResult, Severity/Status enums
│   ├── check_pwnkit.py     # PwnKit / CVE-2021-4034 polkit version
│   ├── check_hidepid.py    # /proc hidepid=invisible
│   └── check_smart.py      # SMART drive health + growth detection
├── backends/
│   ├── base.py             # Firewall backend interface (ABC)
│   ├── factory.py          # Backend registry + instantiation
│   ├── csf.py              # CSF backend
│   ├── firewalld.py        # firewalld backend
│   ├── nftables.py         # nftables backend
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
├── migrations/
│   └── *.sql               # Database migrations (v1.5: 007_cms_sites.sql, 008_posture_audit.sql)
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
