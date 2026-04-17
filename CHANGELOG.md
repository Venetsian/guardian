# WP-Guardian Changelog

## v1.4.1 — Mail false-positive fix + fine-grained Telegram routing (2026-04-17)

Fixes legitimate mail users getting blocked when their mail client has the
wrong SMTP password saved. Symptoms: IMAP works fine, but the client retries
SMTP auth 5+ times in seconds, hits the brute-force threshold, and firewalld
blocks the whole IP — killing the working IMAP connection too.

### Changes

- **`is_ip_authenticated()` is now service-agnostic.** A successful login on
  ANY protocol (WordPress, IMAP, POP3, SMTP, SSH) marks the IP as a known
  user. Takeover of those credentials is still caught by
  `DistributedAuthDetector` (same username from multiple countries/ASNs).
- **`MailDetector` and `RoundcubeDetector` now honor the trust grace period.**
  If an IP has authenticated successfully within `mail_trust_duration`, it is
  exempt from SMTP / IMAP / POP3 / Roundcube auth-failure thresholds — the
  detector logs a warning instead of blocking. Mirrors the WordPress pattern
  that's been live since v1.0.
- **Raised default mail thresholds** (5 → 10) to better match real mail-client
  retry behavior.

### Config

- New `[auth_tracking] mail_trust_duration = 24` (hours). Picked up
  automatically by `tools/config-upgrade.py` on upgrade.
- `smtp_auth_fail_threshold`, `imap_auth_fail_threshold`,
  `roundcube_fail_threshold` defaults raised to 10.

### Username-aware alerts

- `Blocker.block()` now accepts `username=''`. When present, it's rendered as
  an `Account:` line in the Telegram block alert (`alert_block`), and logged
  to `blocked.log` as `user=<name>`. `MailDetector` / `RoundcubeDetector` /
  `CompromiseAction` all pass it through.
- **New `Blocker.alert_trusted_skip()`** — heads-up Telegram alert (MEDIUM)
  when a trusted IP hits a mail / roundcube threshold and the block is
  skipped. Message: "IP had a successful login recently, so it's NOT being
  blocked despite failing IMAP auth 10 times in 300s. Account: kathy@… —
  likely a misconfigured mail client. Consider calling the user."
- **Deduped**: one trusted-skip alert per (IP, service) per 24h, so a client
  stuck in a retry loop doesn't spam the operator.

### Per-rule Telegram routing (`[telegram.rules]` + `/verbosity`)

Replaces the coarse-grained `alert_mode = verbose | digest | quiet` with
per-rule routing. Every block call now carries a short `rule` id
(`wp_login`, `php_scan`, `general_404`, `smtp_fail`, `imap_fail`,
`ssh_fail`, `ssh_invalid`, `roundcube`, `tripwire`, `instant`, `structural`,
`suspicious`, `login_isolation`, `xmlrpc`, `author_enum`, `trusted_skip`,
`compromise`, `cidr`, `block_failed`). A new `VerbosityRouter` resolves each
rule to **immediate**, **digest**, or **silent**.

- **New hardcoded defaults** — `php_scan`, `general_404`, `author_enum` =
  `silent` out of the box (the noisy web traffic that was spamming
  Telegram). Everything else defaults to `immediate`. The block still
  executes in all cases — `silent` only suppresses the Telegram message.
- **Always-immediate rules** (cannot be muted): `compromise`, `cidr`,
  `block_failed`, and any tier-3 block (regardless of its rule).
- **`[telegram.rules]` config section** — per-rule overrides in the config
  file, picked up on startup.
- **`/verbosity` Telegram command** — live tuning without a restart:
  - `/verbosity` — show full rule → level table with source annotations
  - `/verbosity <rule> <level>` — set an override (immediate / digest / silent)
  - `/verbosity clear <rule>` — remove one override
  - `/verbosity reset` — wipe all runtime overrides
- **Runtime overrides persist** to `state/telegram_verbosity.json`
  (atomic write via `.tmp` + rename) and survive restarts without
  touching `wp-guardian.conf` (no configparser rewrite = no lost comments).

Legacy `alert_mode` is still honored as a fallback for rules that aren't
covered by defaults or `[telegram.rules]` — existing v1.4 operators see
no regression.

### Username-aware alerts

- `Blocker.block()` now accepts `username=''`. When present, it's rendered as
  an `Account:` line in the Telegram block alert (`alert_block`), and logged
  to `blocked.log` as `user=<name>`. `MailDetector` / `RoundcubeDetector` /
  `CompromiseAction` all pass it through.
- **New `Blocker.alert_trusted_skip()`** — heads-up Telegram alert (MEDIUM)
  when a trusted IP hits a mail / roundcube threshold and the block is
  skipped. Message: "IP had a successful login recently, so it's NOT being
  blocked despite failing IMAP auth 10 times in 300s. Account: kathy@… —
  likely a misconfigured mail client. Consider calling the user."
- **Deduped**: one trusted-skip alert per (IP, service) per 24h, so a client
  stuck in a retry loop doesn't spam the operator.

### Update script version tracking

- **Fixed**: `git pull && sudo bash update.sh` used to report
  `Current version: 1.4.1 → New version: 1.4.1` because both were reading
  the same `VERSION` file — `git pull` had already overwritten it.
- New `state/installed_version` stamp file written on successful install /
  update / rollback. This is the authoritative "what version is actually
  deployed" for the next update.sh run.
- Fallback: if the stamp file is missing (fresh install without yet running
  update, or manual install), the script reads the pre-pull VERSION from
  `git show ORIG_HEAD:VERSION` — the reference git automatically sets to
  the prior branch tip on every `git pull` / merge / rebase.
- Final fallback: plain `VERSION` file. Current behavior; only engaged if
  neither stamp nor ORIG_HEAD are available (external-source updates).
- `--status` now shows both resolved `Current version` and the raw
  `VERSION file` for diagnostics.
- `install.sh` also writes the stamp so the first update-after-install
  works correctly.

### Files changed

- `modules/database.py` — `is_ip_authenticated()` drops the `service = 'wordpress'` filter
- `modules/blocker.py` — `username` + `rule` kwargs, `alert_trusted_skip()`,
  dedup state, router integration
- `modules/verbosity.py` — NEW. `VerbosityRouter`, `[telegram.rules]` parsing,
  JSON-backed runtime overrides, always-immediate rule set
- `modules/digest.py` — `queue()` trusts the router (no longer re-checks `is_immediate`)
- `modules/compromise.py` — passes `username` + `rule='compromise'` through to `blocker.block()`
- `actions/telegram.py` — `alert_block()` renders `Account:` line
- `actions/telegram_commands.py` — `/verbosity` command + help update
- `wp-guardian.py` — `MailDetector` / `RoundcubeDetector` extract username
  and consult the trust check; all detector `blocker.block()` calls carry a `rule`
- `wp-guardian.conf.example`, `wp-guardian.conf` — new `[telegram.rules]` section +
  `mail_trust_duration` + raised mail defaults
- `update.sh` — `get_installed_version()` resolver (stamp / ORIG_HEAD / VERSION
  fallback), `write_installed_version()`, stamping after update/rollback
- `install.sh` — stamps `state/installed_version` on fresh install
- `VERSION` — bumped to 1.4.1

## v1.4.0 — Mail Hardening Release (2026-04-15)

Headline feature: **DistributedAuthDetector** catches the classic distributed
credential-abuse botnet pattern (same account, many countries/ASNs/IPs in a
short window) and automatically disables the mailbox + blocks attacker IPs.

### Major features

- **DistributedAuthDetector** — fires on every successful auth when the same
  username crosses a distinct-countries / distinct-ASNs / distinct-IPs
  threshold over a sliding window. Triggers the configured compromise action.
- **GeoIP enrichment** — auth events and blocks now carry country, city,
  ASN, and ASN organization (MaxMind GeoLite2-City + GeoLite2-ASN, LRU-cached).
- **RoundcubeDetector** — tails Roundcube `errors.log` and threshold-blocks
  failed webmail logins.
- **CompromiseAction** — orchestrates the response: records a compromise
  event, blocks all attacker IPs from the window, disables the mailbox via
  MailBackend, sends an immediate Telegram alert (never digested).
- **MailBackend / MariaDB integration** — new `[mail_backend]` section lets
  Guardian disable/enable mailboxes in a Postfixadmin/Mailcow-style
  `virtual_users` table via a least-privilege SQL user.
- **Per-account auth map** — `--auth-map`, `--auth-suspects`,
  `--hunt-compromises` plus matching Telegram commands.
- **Telegram alert modes** — `verbose` (v1.3 behavior, default), `digest`
  (tier-1/2 blocks aggregated into hourly summaries), `quiet` (only
  high-priority events immediate). Compromise / tier-3 / CIDR /24 /
  BLOCK FAILED are always immediate regardless of mode.
- **Profile config** — `[profile] mode = steady | migration`. Migration mode
  loosens brute-force thresholds for post-cutover periods while keeping
  country/ASN compromise rules tight.
- **Compromise hunt CLI** — `--hunt-compromises` replays detector logic
  against historical data; `--auto-act` optionally applies the configured
  compromise action.
- **Mailbox management CLI + Telegram** — `--disable-mailbox`,
  `--enable-mailbox`, `--list-compromise-events`, `--resolve-compromise`,
  and `/disable`, `/enable`, `/compromises`, `/resolve`.
- **Backfill tool** — `tools/backfill_maillog.py` imports recent maillog
  history (current + rotated .gz) into `auth_sessions` so detectors and
  `--auth-map` have data on day one.
- **Internal DB dialect layer** — `_SQLDialect` abstraction marks the
  SQLite-specific surface as foundation for a v1.5 pluggable MySQL backend.

### New CLI commands

- `--auth-map <user>`, `--auth-suspects`, `--hunt-compromises [--auto-act]`
- `--disable-mailbox <user>`, `--enable-mailbox <user>`, `--reason "..."`
- `--list-compromise-events [--open-only]`, `--resolve-compromise <id> [--note]`
- `--days N`, `--min-ips N` modifiers

### New Telegram commands

- `/authmap <user> [days]`, `/suspects [days] [minips]`
- `/disable <user> [reason]`, `/enable <user>`
- `/compromises [open]`, `/resolve <event_id> [note]`

### New config

- `[profile]` — `mode` (steady|migration)
- `[compromise_detection]` — `enabled`, `window_seconds`,
  `threshold_distinct_countries`, `threshold_distinct_asns`,
  `threshold_distinct_ips`, `action`, `suppression_seconds`, `exclude_usernames`
- `[mail_backend]` — `type`, `host`, `port`, `database`, `user`, `password`,
  `table`, `email_column`, `enabled_column`
- `[geoip]` — `city_database_path`, `asn_database_path`, `cache_size`,
  `on_missing_db` (replaces v1.3 `database_path`)
- `[telegram]` — `alert_mode`, `digest_interval`, `digest_max_events`
- `[thresholds]` — `roundcube_fail_threshold`
- `[log_paths]` — `roundcube_log`

### New database schema (migrations 002–005)

- `auth_sessions.geoip_asn`, `auth_sessions.geoip_asn_org`
- `ip_history.geoip_asn`, `ip_history.geoip_asn_org`
- Indexes: `idx_auth_username_ts`, `idx_auth_country_ts`
- `compromise_events` table + indexes
- `mailbox_actions` audit log
- `alert_digest_buffer` for digest-mode Telegram alerts
- `CURRENT_SCHEMA_VERSION` bumped from 1 to 5

### New dependencies (optional)

- `geoip2>=4.7.0` — required only when `[geoip] enabled = true`
- `PyMySQL>=1.0.0` — required only when `[mail_backend] type != none`

Both lazy-imported. Existing v1.3 deployments upgrading via `git pull`
see zero behavioral change until they opt in.

### Files added

- `modules/geoip.py`, `modules/mail_backend.py`, `modules/compromise.py`,
  `modules/digest.py`
- `migrations/002_geoip_asn_columns.sql`,
  `migrations/003_compromise_events_table.sql`,
  `migrations/004_mailbox_actions_table.sql`,
  `migrations/005_alert_digest_buffer.sql`
- `tools/backfill_maillog.py`

### Files changed

- `wp-guardian.py` — new detectors, Guardian wiring, CLI handlers, profile
- `modules/database.py` — schema, `_SQLDialect`, v1.4 query methods
- `modules/migrator.py` — `CURRENT_SCHEMA_VERSION = 5`
- `modules/blocker.py` — digest buffer routing
- `actions/telegram.py` — `alert_compromise()`
- `actions/telegram_commands.py` — six new v1.4 commands
- `wp-guardian.conf`, `wp-guardian.conf.example` — new sections
- `requirements.txt` — geoip2, PyMySQL
- `install.sh` — GeoIP, compromise detection, mail backend, profile, alert mode prompts
- `VERSION` — 1.4.0

---

## v1.3.0 — Tripwire Management (2026-02-28)

### Tripwire Removal & Manual Review

Replaced automatic tripwire importing with a manual-review workflow to prevent false positives. Added dynamic tripwire removal via CLI and Telegram.

**1. Replaced `--auto-analyze` with `--analyze-tripwires`**
- Old behavior: ran log analyzer and auto-imported results without review
- New behavior: runs log analyzer, filters against existing tripwires, shows only NEW candidates
- Saves new candidates to `state/new-tripwires.txt` for review before manual import
- Removed periodic auto-analysis from the daemon main loop
- Removed `auto_analyze` and `interval` config options from `[log_analysis]`

**2. Dynamic tripwire removal**
- New CLI: `--remove-tripwire /path.php` — removes from database, `tripwires.txt`, and memory
- New CLI: `--list-tripwires [pattern]` — search/list tripwires by pattern with hit counts
- New database methods: `remove_tripwire()`, `search_tripwires()`, `count_tripwires()`

**3. Telegram commands for tripwire management**
- `/tripwires` — shows total count + top 10 by hits
- `/tripwires <search>` — searches paths containing the term (max 30 results)
- `/remove <path>` — removes a tripwire from database, file, and memory
- TelegramCommander now receives shared tripwires set for live memory updates

**Files changed:** `wp-guardian.py`, `modules/database.py`, `actions/telegram_commands.py`, `wp-guardian.conf`, `wp-guardian.conf.example`, `install.sh`, `README.md`, `INSTALL.md`, `CLAUDE.md`, `CHANGELOG.md`, `VERSION`

---

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
