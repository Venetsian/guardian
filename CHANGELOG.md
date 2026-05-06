# WP-Guardian Changelog

## v1.5.0 — Multi-CMS scaffolding & POST-flood detector (2026-05-03)

> **Updated 2026-05-06 (task #122)**: posture-audit + host-health module
> foundation added. Foundation + two reference checks (PwnKit, /proc
> hidepid). Additional checks land incrementally in subsequent v1.5
> updates: SUID drift, sshd config, listening ports, tenant home perms,
> mod_hostinglimits / mod_lsapi UID switching, CageFS state, SMART, disk
> usage, worker saturation, DB health, modsec volume, MTA queue, and
> active /tmp cleanup with dry-run rollout.

### Posture audit + host-health module (added 2026-05-06)

Extensible subsystem for daily security-drift and host-health checks.
Each check declares its applicability against an auto-detected host
profile, so a free single-site VPS only runs the generic Linux checks
while a multi-tenant CL+Apache box gets the full set. Checks share a
two-table schema (`posture_state` upserted on every run, `posture_events`
append-only with a 30-day TTL) and Telegram alerts fire on transitions
whose severity meets `[posture] alert_severity_min`.

### Schema (migration 008)

- `host_profile` — single-row-per-host facts driving check applicability
  (is_cloudlinux, web_server, db_server, mta, has_modsec,
  is_multi_tenant, behind_perimeter_firewall, distro_id/version, plus
  free-form `extras_json` for future fields).
- `posture_state` — `(host, module, check_id)` PK, upserted every run
  with `status`, `severity`, `current_value` JSON, `detail`, `last_run_at`,
  `last_change_at`.
- `posture_events` — append-only transitions log with
  `from_status/to_status`, `from_value/to_value`, `severity`, `alerted`,
  pruned daily after `events_retention_days` (default 30).

### New modules

- `modules/host_profile.py` — `HostProfileDetector` probes the host
  defensively (every probe wrapped, falls back to safe defaults). Caches
  to `host_profile`; refreshes after `profile_refresh_seconds` (default
  daily). Allows config overrides for `behind_perimeter_firewall` and
  `is_multi_tenant`.
- `modules/posture.py` — `PostureAuditor` orchestrator: load profile,
  iterate registered checks, persist state, diff for transitions, append
  to `posture_events`, fire Telegram alerts above the severity floor.
  First-run grace dampens alerts to CRITICAL only on bootstrap so a
  fresh install doesn't flood chat.

### Check API

- `posture_checks/base.py` — `Check` ABC plus `CheckResult`, `Severity`,
  `Status`, `Module` enums. `applies_to(profile) -> bool` and
  `run(profile) -> CheckResult`. Checks may override severity per result
  via `severity_override`.
- `posture_checks/__init__.py` registers checks in `ALL_CHECKS` — adding
  a new check is a one-line registry edit.

### Reference checks

- `pwnkit` (CRITICAL) — polkit/pkexec patched against CVE-2021-4034.
  Per-distro patched-version table for RHEL/AlmaLinux/Rocky/CloudLinux
  8 + 9 and Debian/Ubuntu 11/12 + 20.04/22.04/24.04. Falls back to
  WARN+LOW on unrecognized distros so we never raise a false CRITICAL.
- `proc_hidepid` (MEDIUM, escalates HIGH on multi-tenant) — `/proc`
  mounted with `hidepid=invisible`. Reads `/proc/mounts` directly.
  Reports PASS-with-note on single-site hosts since there's nobody to
  hide from.

### Telegram

- `actions/telegram.py` gains `alert_posture_drift(check_id, module,
  severity, host, status, detail, description)` — formatted message
  with severity emoji and module label, mapped to send-priority.

### Daemon + CLI

- `Guardian.__init__` constructs `HostProfileDetector` + `PostureAuditor`
  after the digest buffer. The daemon's main loop calls
  `posture_auditor.run_if_due()` every tick; the orchestrator no-ops
  unless `interval_seconds` has elapsed since the last run.
- New CLI flags:
  - `--posture-profile [--refresh]` — print the detected host profile
  - `--posture-run [--refresh]` — run all checks now and print results
  - `--posture-status` — show current state of every check
  - `--posture-events` — show recent transitions with timestamps

### Config

- New `[posture]` section in `wp-guardian.conf.example` with
  `enabled`, `interval_seconds`, `alert_severity_min`,
  `events_retention_days`, `profile_refresh_seconds`, plus optional
  overrides for `behind_perimeter_firewall` and `is_multi_tenant`.

### Original v1.5.0 release notes (2026-05-03)

This is an **extensibility release**. Every detector class moved out of
the 2200-line `wp-guardian.py` into a `detectors/` package, the access-log
parser is now format-aware (OpenLiteSpeed, Apache combined, nginx), and a
new CMS registry auto-detects what's running on each vhost so future
CMS-specific detectors can plug in without touching shared code.

The headline new feature is a generic POST-flood detector with a
two-stage gate (rate + behavioral confirmation) designed to catch
admin-page brute force on any CMS while staying safe behind office NAT.
It ships **off by default** — opt in via `[post_flood] enabled = true`.

Joomla and Drupal arrive as scaffolding (path registration; auth-failure
detection deferred to v1.6+ when the new web servers actually need it).

### Detector refactor — no behavior change for existing rules

- New `detectors/` package with one file per detector:
  `base.py` (HitTracker), `web.py`, `mail.py`, `ssh.py`, `roundcube.py`,
  `distributed_auth.py`, `post_flood.py`, `cms_base.py`, `joomla.py`,
  `drupal.py`, `log_formats.py`.
- `wp-guardian.py` shrinks from ~2200 to ~1200 lines and just imports
  from `detectors`. Existing rules behave identically — verified by
  unit-level smoke tests of each parser path.

### `detectors/log_formats.py` — log-format dispatcher

- `parse_line()` auto-detects OLS (outer quotes) vs Apache combined /
  nginx default. Returns a normalized dict with `ip`, `method`, `path`,
  `clean_path`, `status`, `size`, `referer`, `user_agent`, `format`.
- `WebDetector.process_line` now calls `parse_line()` first; the legacy
  three-regex parser is retired. Behavior preserved for the fields the
  WordPress pipeline already used.
- Fixes a latent bug in the v1.4 parser that stripped the trailing UA
  quote from Apache combined lines (harmless before because the pipeline
  never read that field; it would now have broken POST-flood's
  off-host-Referer check).

### `modules/cms_registry.py` — CMSRegistry

- Auto-detects WordPress / Joomla / Drupal / Magento / PrestaShop /
  OpenCart / phpMyAdmin per vhost by fingerprinting the docroot.
- Refreshes every 6h (configurable), persists to the new `cms_sites`
  table.
- New `vhosts.conf` (optional) — operator can pin a site's CMS or
  declare a renamed admin path (e.g. `admin_paths = /sekret-admin/index.php`).
- WordPress auto-detect on a Joomla site is a non-issue: bots that
  attack `/wp-login.php` on a Joomla vhost get a 404 from Joomla and
  fall through to the universal 404-storm rule.

### `detectors/post_flood.py` — POST-flood detector

Watchlist-driven. Only paths registered by the CMS module (or
`vhosts.conf`) are watched. WordPress's `wp-login.php` is intentionally
excluded — the dedicated `wp_login` rule already covers it.

Two-stage gate:
- **Stage 1 (rate):** N POSTs to one watched URL from one IP within the
  configured window. Default: 30 / 5 min.
- **Stage 2 (behavioral, default ON):** at least one of —
  - **A** zero CSS loads from this IP (real browsers fetch CSS for the
    page hosting the form). Reuses the existing `login_isolation` table.
  - **C** ≥80% off-host Referer across recent POSTs.
  - **D** ≥80% identical Content-Length across recent POSTs.

Trusted-IP exemption runs before stage 1: if the IP authenticated on
any service in the trust window, the detector logs a heads-up via
`alert_trusted_skip` and never blocks. (This subsumes the originally
planned signal B — "zero successful auth" — which was redundant with
the trust check.)

New rule id: `post_flood`. Default verbosity: `digest` (FP profile
not yet proven; promote to `immediate` after 2+ weeks of clean data).

### SSH tune-up

- New rule id `ssh_root` — fires when `Failed password for root from
  <IP>` lines exceed `ssh_root_fail_threshold` (default: half of
  `ssh_fail_threshold`, floor at 1 → instant block on first attempt).
- Verified port-agnostic. The listening sshd port (22 / 69 / anything)
  doesn't appear in the auth log message — only the client's source
  port — so the existing `from (\d+\.\d+\.\d+\.\d+)` regex works on
  any server config.

### Database

- Migration `007_cms_sites.sql` adds the `cms_sites` table.
- `CURRENT_SCHEMA_VERSION` → 7.
- `db.cms_sites_upsert / cms_sites_get / cms_sites_all` helpers.

### Config additions

```ini
[cms_detection]
enabled = true
refresh_interval = 21600          # 6h
vhosts_overrides = /opt/wp-guardian/vhosts.conf

[post_flood]
enabled = false                   # opt-in
threshold = 30
window = 300
behavioral_required = true
behavioral_referer_pct = 80
behavioral_content_length_pct = 80
universal_paths =                 # comma-separated, extends defaults

[thresholds]
ssh_root_fail_threshold = 1       # NEW (default = max(1, ssh_fail_threshold // 2))
```

All new options default-off or default-safe; existing v1.4 deployments
upgrade with zero behavior change until they opt in.

### Files changed

- **New** `detectors/__init__.py`, `detectors/base.py`, `detectors/web.py`,
  `detectors/mail.py`, `detectors/ssh.py`, `detectors/roundcube.py`,
  `detectors/distributed_auth.py`, `detectors/log_formats.py`,
  `detectors/post_flood.py`, `detectors/cms_base.py`,
  `detectors/joomla.py`, `detectors/drupal.py`.
- **New** `modules/cms_registry.py`, `migrations/007_cms_sites.sql`.
- `wp-guardian.py` — detector classes removed; imports from
  `detectors`; `Guardian.__init__` instantiates `CMSRegistry` and
  `PostFloodDetector` and threads them into `WebDetector`; main loop
  refreshes the registry on the configured interval.
- `modules/database.py` — `cms_sites` in `_create_tables`; new helpers
  `cms_sites_upsert`, `cms_sites_get`, `cms_sites_all`.
- `modules/migrator.py` — `CURRENT_SCHEMA_VERSION = 7`.
- `modules/verbosity.py` — registers `ssh_root` (immediate) and
  `post_flood` (digest) defaults.
- `wp-guardian.conf.example` & `wp-guardian.conf` — new sections.
- `install.sh` — interactive prompts for POST-flood opt-in.
- `README.md` — features list, file tree, detection-pipeline section.
- `CLAUDE.md` — Detector architecture section, CMS registry, POST-flood
  rule, `ssh_root` rule, updated detection-logic ordering.
- `VERSION` → `1.5.0`.

### Upgrade notes

- `git pull && bash update.sh` runs migration 007 idempotently. No
  behavior change unless you opt into POST-flood.
- If you rename your Joomla admin path or use a non-standard docroot
  layout, drop a stub in `vhosts.conf` so the registry knows about it.

---

## v1.4.3 — Trusted-ASN exemption for compromise detection (2026-04-30)

Stops `DistributedAuthDetector` from false-firing on legitimate users of
Microsoft 365 / Google Workspace / iCloud Mail. These services relay one
user's outbound mail through DCs in many countries within minutes, which
previously looked identical to a credential-abuse botnet and would (with
`action = full`) auto-disable the user's mailbox.

### Real-world example that triggered this fix

One user in 1h: Sky GB (AS5607), Sky GB (AS31655), EE GB (AS206067), and
Microsoft 365 relays from IE / SE / NL (all AS8075). With the default
`threshold_distinct_countries = 3` that's 4 countries → fires. The user is
in one country; Microsoft is the source of the geographic spread.

### Changes

- **New `[compromise_detection] trusted_asns`** — comma-separated list of
  ASNs whose rows are excluded from the country and ASN counts. The IP
  count is **not** filtered, so volumetric abuse via a trusted ASN still
  trips `threshold_distinct_ips`.
- **Default value: `8075, 15169, 714`** — Microsoft, Google, Apple. These
  are the providers that relay through DCs in many countries by design.
  Defaults applied automatically on upgrade via
  `tools/config-upgrade.py` (the option is auto-discovered from
  `wp-guardian.conf.example`).
- **`db.distinct_auth_counts()` now accepts `trusted_asns=`** — used by
  `DistributedAuthDetector.on_successful_auth` on every successful auth.
  Backwards-compatible: callers that don't pass it get the v1.4.2 behavior.

### Files changed

- `wp-guardian.py` — `DistributedAuthDetector.__init__` parses
  `trusted_asns` into a set of ints, passes it to `distinct_auth_counts`.
- `modules/database.py` — `distinct_auth_counts(..., trusted_asns=None)`
  emits filtered SQL when the set is non-empty (NOT IN clause on
  `geoip_asn` for the country and ASN expressions).
- `wp-guardian.conf.example` — adds `[compromise_detection] trusted_asns`
  with the default list and a comment explaining why.
- `wp-guardian.conf` — same option mirrored into the live config.
- `VERSION` → `1.4.3`.
- `CLAUDE.md` — DistributedAuthDetector section notes the trusted-ASN filter.

### What if I want stricter behavior?

Set `trusted_asns =` (empty) to count every ASN. You'll get false positives
on Microsoft 365 / Google / iCloud users but no compromise scenario will
slip past the country/ASN rules.

### What if a compromise IS using Microsoft 365 as the relay?

The IP-count rule still applies — `threshold_distinct_ips = 20` by default.
A volumetric attack via a trusted ASN trips that rule even though country
and ASN counts are zero. For low-volume attacks via your own tenant's
relay, compromise detection by source dispersal is the wrong layer; outbound
volume / unusual-recipient monitoring (v1.5 work) catches that.

## v1.4.2 — Geo enrichment of blocks (2026-04-30)

Bug fix: every row in `ip_history` shipped since v1.4.0 had `geoip_country=''`
and `geoip_asn=0`, even on hosts with GeoIP fully configured and the auth
side working. Telegram block alerts also went out without a country / city
line, and `--history` / daily-summary country breakdowns were empty.

### Root cause

`Guardian.__init__` constructed `Blocker` on line 875 and `GeoIPResolver` on
line 880 — the resolver didn't exist yet when the blocker was wired up.
`Blocker.__init__` had no `geoip` parameter either, so even reordering
wouldn't have helped without a signature change. Net effect: `Blocker.block()`
called `db.track_ip(ip, service, country, city)` with the kwargs from each
detector's `block()` call — and no detector passes country/city. They all
silently became empty strings.

`auth_sessions` was unaffected because the successful-auth path goes through
`MailDetector._geo(ip)` → `db.record_auth(geo=geo)`, which the v1.4 wiring
got right.

### Fix

- `modules/blocker.py` — `Blocker.__init__` now accepts `geoip=None` and
  stores it. At the top of `block()` (after the whitelist check) it calls
  `self.geoip.lookup(ip)` once and threads the result into
  `db.track_ip(geo=geo)` and the Telegram alert / digest payload.
- `wp-guardian.py` — `GeoIPResolver` is now constructed before `Blocker`,
  and the resolver is passed in via the new kwarg.
- Backwards-compatible: detector call sites still pass `country=''` /
  `city=''` (none of them ever set these), the lookup fills them in. No
  detector signatures change.

### Files changed

- `modules/blocker.py` — `__init__` accepts `geoip=`; `block()` does the
  lookup and passes geo to `db.track_ip` and through to alert/digest paths.
- `wp-guardian.py` — GeoIPResolver init moved above Blocker init; Blocker
  constructed with `geoip=self.geoip`.
- `VERSION` → `1.4.2`.
- `CLAUDE.md` — Blocking Architecture section notes the geo-enrichment step.

### Backfill (one-shot)

Existing rows stay blank until they're re-touched. New tool to repair them
in place:

```bash
# Dry run first — counts only, no writes
python3 /opt/wp-guardian/tools/backfill_ip_history.py --dry-run

# Apply
python3 /opt/wp-guardian/tools/backfill_ip_history.py
```

Defaults to scanning only rows where `geoip_country = ''` AND `geoip_asn = 0`
(the v1.4.0–v1.4.1 victims). Pass `--all` to re-resolve every row, e.g.
after a GeoLite2 database refresh. `--limit N` caps the run for testing.
Idempotent: re-runs pick up only rows still missing data.

**Note:** `auth_sessions` was unaffected by the bug — the auth path looks
geo up itself — so this tool only touches `ip_history`. Compromise
detection (which reads `auth_sessions`) is independent of this fix.

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

### Dependency preflight in update.sh

- The old "Missing Python dependencies for enabled features" was a soft
  warning at Step 6 (after backup, file copy, migrations), easy to miss in
  the output. A missing `geoip2` module doesn't crash the daemon — it fails
  safe to `None`, leaving `DistributedAuthDetector`'s country/ASN rules
  silently inert. Same for missing PyMySQL with mail_backend enabled.
- **Now a hard preflight** before any backup or file copy:
  - Red banner listing each missing package, the config flag that requires
    it, and what silently breaks (e.g. *"geoip2 → country/ASN detection
    silently disabled; DistributedAuthDetector rules will never fire"*).
  - Offers to run `pip3 install -r requirements.txt --break-system-packages`
    interactively (default yes). Re-verifies after install.
  - If the operator declines install, asks one more time: *"Continue update
    with FEATURES DISABLED?"* — defaults to no.
  - Non-interactive runs (no TTY on stdin) abort automatically so an
    automated caller can't skip past the check.
  - No state has been modified at the point of abort.
- Checks: `pymysql` (for `[mail_backend] type != none`), `geoip2` (for
  `[geoip] enabled = true`), `requests` (for `[telegram] enabled = true`).

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
