# WP-Guardian Changelog

## v1.2.0 — Whitelist Protection Improvements (2026-02-27)

### Whitelist Defense-in-Depth

Five improvements to how whitelisted IPs are handled throughout the detection pipeline. Previously, the owner got blocked despite being in `whitelist.conf` due to an inline comment parsing bug (fixed in config.py). Investigation revealed additional defensive gaps.

**1. Early whitelist bypass in detectors**
- All three detectors (Web, Mail, SSH) now check the whitelist immediately after IP extraction
- Whitelisted IPs skip all hit counters, tripwire checks, login isolation tracking, and threshold rules
- Successful WordPress logins are still recorded for geo audit even when whitelisted
- Prevents counter pollution from legitimate traffic

**2. Whitelist file auto-reload**
- `whitelist.conf` changes are now picked up automatically every 60 seconds (no daemon restart needed)
- Uses `os.path.getmtime()` to detect changes, `reload_file()` uses atomic reference swaps (GIL-safe)

**3. CIDR /24 aggregation whitelist check**
- `_check_cidr_aggregation()` now checks `whitelist.conf`, file CIDRs, and DB whitelist entries before blocking a /24 subnet
- Previously only the MikroTik `friendly` list was checked — a whitelisted IP could be caught by a subnet block

**4. MikroTik friendly list periodic refresh**
- The `friendly` address list is now refreshed every 5 minutes (was loaded once at startup)
- Added `refresh_friendly_list()` to the `FirewallBackend` base class (no-op default) with MikroTik implementation

**5. Improved whitelist skip logging**
- `blocker.block()` now logs whitelist skips at INFO level with full context: `WHITELIST SKIP ip=... service=... reason=... site=...`
- Acts as defense-in-depth audit trail

### Files Changed

- **Modified** `wp-guardian.py` — pass whitelist to all 3 detectors, early bypass logic, whitelist file auto-reload in main loop, friendly list periodic refresh in main loop
- **Modified** `modules/whitelist.py` — added `reload_file()` and `contains_whitelisted_ip()` methods
- **Modified** `modules/blocker.py` — CIDR whitelist safety check, improved whitelist skip logging
- **Modified** `backends/base.py` — added `refresh_friendly_list()` stub
- **Modified** `backends/mikrotik.py` — implemented `refresh_friendly_list()`

---

## v1.1.0 — Telegram Interactive Commands (2026-02-25)

### New Feature: Telegram Command Handler

WP-Guardian can now receive commands via Telegram, not just send alerts. A new polling thread uses the Telegram `getUpdates` API with long-polling — no webhooks, no open ports.

**Available commands:**

- `/status` — current block counts by tier, IPs tracked, auth sessions, tripwires
- `/unblock <ip>` — remove block and reset tier to 0
- `/whitelist <ip>` — add IP to whitelist permanently
- `/whitelist <ip> <duration>` — add temporarily (e.g., `24h`, `7d`, `30d`)
- `/whitelist remove <ip>` — remove from whitelist
- `/whitelist list` — show all entries with expiry info
- `/history <ip>` — full IP history with recent block log
- `/help` — list available commands

**Security:** Only messages from the configured `chat_id` are processed. All other messages are silently ignored.

**Configuration:**

```ini
[telegram]
commands_enabled = true
commands_poll_timeout = 30
```

### Files Changed

- **Added** `actions/telegram_commands.py` — `TelegramCommander` class
- **Modified** `wp-guardian.py` — wired command handler into daemon lifecycle (init, start, shutdown)
- **Modified** `wp-guardian.conf` — added `commands_enabled` and `commands_poll_timeout` options

---

## v1.0.0 — Initial Public Release (2026-02-24)

### Core Features

- Real-time monitoring of web access logs (OpenLiteSpeed format), mail logs (Postfix/Dovecot), and SSH logs
- Three-tier escalation blocking: 24h (first offense) → 30d (repeat) → permanent (persistent)
- Login isolation detection — catches bots by behavioral signal (no CSS = not a browser), blocks after just 3 requests
- Tripwire-based detection from automated log analysis with incremental import
- Webshell and scanner pattern detection (alfa.php, c99.php, r57.php, etc.)
- Brute force detection for wp-login.php, xmlrpc.php, SMTP, IMAP/POP3, SSH
- CIDR /24 aggregation — auto-blocks entire subnets when 5+ IPs are individually blocked
- Domain tracking in alerts — Telegram notifications include which site was targeted
- Three-source whitelist (file + database + firewall-native friendly list)
- Authenticated IP bypass — WordPress logins grant 24h trusted status
- SQLite database with WAL mode and automated migration framework

### Pluggable Firewall Backends

- **CSF** — ConfigServer Firewall with tier-based temp/permanent blocks
- **firewalld** — Default on RHEL/AlmaLinux and CyberPanel 2.4+ (rich rules)
- **nftables** — Direct nftables with named sets and auto-expiry timeouts
- **MikroTik** — Network edge blocking via SSH with address list TTLs
- **pfSense / OPNsense** — Network edge blocking via REST API and aliases
- Extensible backend system — add new firewalls by implementing the `FirewallBackend` ABC

### Tools & Operations

- Interactive installer with firewall selection, Telegram setup, log discovery
- Telegram setup wizard with chat_id auto-discovery via bot polling
- Log discovery sub-command to find and register access logs
- Automated log analysis with incremental tripwire import (never flushes old entries)
- Update script with backup, migration, verification, and rollback
- Database migration framework with numbered SQL scripts
- Comprehensive CLI for status, whitelist management, tripwire import, flushing, and more
