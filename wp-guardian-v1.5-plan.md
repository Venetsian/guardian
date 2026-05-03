# WP-Guardian v1.5 — Multi-CMS Scaffolding Plan

**Status:** approved 2026-05-03, implementation starting.
**Theme:** refactor for extensibility + scaffolding for non-WP CMS detection. WordPress remains the only fully-implemented CMS detector. Joomla/Drupal/POST-flood ship as opt-in skeletons that land in v1.6+ when needed on the web servers.

---

## 1. Version & branding

- Bump `VERSION`: `1.4.3` → `1.5.0`
- This is the "extensibility release" — refactor + skeleton, not "+4 detectors"
- Branch strategy: work on `feature/v1.5` until done, then merge to `main`. `mail.maiahost.com` stays on tagged `v1.4.3` until v1.5 has soaked on a test box.

---

## 2. New file structure

Move detectors out of the 2200-line `wp-guardian.py`:

```
/opt/wp-guardian/
├── wp-guardian.py              # Now ~1200 lines: CLI + Guardian class + LogTailer
├── detectors/
│   ├── __init__.py
│   ├── base.py                 # Detector ABC + shared helpers (HitTracker, parse helpers)
│   ├── log_formats.py          # Format autodetect: ols / apache_combined / nginx_combined / lsws
│   ├── web_pipeline.py         # Orchestrates per-line: format-detect → site lookup → CMS dispatch → universal rules
│   ├── universal.py            # CMS-agnostic web rules: structural, instant patterns, suspicious patterns, 404 storms, login isolation
│   ├── wordpress.py            # WP-specific (wp-login.php, xmlrpc.php, ?author=, /wp-content/uploads/, /wp-admin/)
│   ├── joomla.py               # Skeleton: declares /administrator/index.php to POST-flood watchlist; no body inspection yet
│   ├── drupal.py               # Skeleton: declares /user/login; no body inspection yet
│   ├── post_flood.py           # Watchlist + two-stage gate
│   ├── mail.py                 # Moved from wp-guardian.py (no logic change)
│   ├── ssh.py                  # Moved + tune-up: root-attempt rule, port-agnostic re-verify
│   ├── roundcube.py            # Moved (no logic change)
│   └── distributed_auth.py     # Moved (no logic change)
├── modules/
│   ├── cms_registry.py         # NEW: builds & holds the {site → cms → admin_paths} map at startup
│   └── (existing modules unchanged: blocker, database, config, whitelist, geoip, etc.)
└── (everything else unchanged)
```

**Why this shape:** matches existing `backends/` plugin pattern, uses the same factory style, no surprises.

---

## 3. CMSRegistry (the in-memory map)

`modules/cms_registry.py` — built once at startup, refreshed on a 6h interval:

```python
class CMSRegistry:
    # site → {'cms': 'wordpress', 'docroot': '/home/foo/public_html',
    #         'admin_paths': ['/wp-login.php'], 'overrides': {...}}

    def detect(self, docroot):
        if exists(f'{docroot}/wp-config.php'): return 'wordpress'
        if exists(f'{docroot}/configuration.php') and isdir(f'{docroot}/administrator'): return 'joomla'
        if exists(f'{docroot}/core/lib/Drupal.php'): return 'drupal'
        # ... etc
        return 'unknown'

    def get(self, site) -> dict   # used by web_pipeline per line
```

**Site → docroot resolution:** walk the access log paths in `logfiles.txt`, derive site from path (`/home/SITE/logs/...`), then probe the conventional docroot locations: `/home/SITE/public_html`, `/home/SITE/www`, OLS vhost path. Fingerprint each.

**Per-vhost overrides:** new optional file `vhosts.conf` (INI):
```ini
[example.com]
cms = joomla
admin_paths = /sekret-admin/index.php, /administrator/index.php
post_flood_threshold = 50
```

Operator only writes entries when auto-detect is wrong or they want to override. Empty file = pure auto-detect.

**Bot-on-wrong-CMS:** non-issue — WP attacks against a Joomla site fall through to universal rules (structural, 404 storms, instant patterns) and get caught.

---

## 4. POST-flood module

- **Watchlist-only.** Only paths registered by a CMS module (or `vhosts.conf`) are watched. Default registrations:
  - WordPress: skipped — already covered by dedicated `wp_login` rule
  - Joomla skeleton: `/administrator/index.php`
  - Drupal skeleton: `/user/login`
  - Universal (always-on): `/phpmyadmin/`, `/cpanel`, `/login`, `/signin`
- **Two-stage gate.**
  - Stage 1: 30 POSTs to a watched URL from one IP in 5 min
  - Stage 2: at least ONE behavioral signal:
    - zero CSS/JS loads from IP in 1h (reuses `login_isolation_record_css`)
    - zero successful auth in 24h (reuses `is_ip_authenticated`)
    - ≥80% off-host Referer
    - ≥80% identical Content-Length
- **Tier-1 only** at first (24h block). No auto-escalation until 2 weeks of clean data.
- New rule id: `post_flood`. Default verbosity: `digest`.

---

## 5. SSH tune-up

- Re-verify port-agnostic regex with port-69 sample lines
- New signal: `Failed password for root` → halve the threshold (root attempts are higher signal). New rule id: `ssh_root`.
- Document in CLAUDE.md: pubkey-only servers will see fewer hits; operator should drop `ssh_fail_threshold` to 2 if they're paranoid.

---

## 6. Database migration

`migrations/006_cms_registry.sql` — minimal:

```sql
CREATE TABLE IF NOT EXISTS cms_sites (
    site TEXT PRIMARY KEY,
    cms TEXT NOT NULL,
    docroot TEXT,
    admin_paths TEXT,        -- JSON list
    detected_at INTEGER NOT NULL,
    overridden INTEGER DEFAULT 0
);
```

Bump `CURRENT_SCHEMA_VERSION` to 6. Idempotent (`IF NOT EXISTS`). No backfill — registry rebuilds on next startup.

POST-flood needs no schema change — uses in-memory `HitTracker`.

---

## 7. Config additions

`wp-guardian.conf.example` gains:

```ini
[cms_detection]
enabled = true
refresh_interval = 21600          # 6h
vhosts_overrides = /opt/wp-guardian/vhosts.conf

[post_flood]
enabled = false                   # opt-in initially
threshold = 30
window = 300
behavioral_required = true        # set false to disable stage 2 (NOT recommended)
behavioral_referer_pct = 80
behavioral_content_length_pct = 80

[thresholds]
# new:
ssh_root_fail_threshold = 1       # root attempts halve the regular threshold floor
```

All new options default-OFF or default-safe. Existing v1.4 deployments upgrade with zero behavior change until they opt in.

---

## 8. Implementation order (each step independently mergeable)

1. **Refactor only — no behavior change.** Move detectors to `detectors/`. Run existing test traffic, confirm identical output. Tag `v1.5.0-rc1`.
2. **Log-format dispatcher.** Add `log_formats.py`, wire into web pipeline. OLS still default; Apache combined / nginx detection added.
3. **CMSRegistry.** Build, populate, expose via Guardian. WordPress detector reads from registry instead of inlined. No behavior change for WP-only servers.
4. **POST-flood module.** Add disabled. Wire watchlist registration. Manually enable in dry-run, observe.
5. **Joomla + Drupal skeletons.** Just register paths to POST-flood; no body inspection. Real impl deferred.
6. **SSH tune-up.** Add `ssh_root` rule, re-verify port handling.
7. **Docs + version + changelog + install.sh prompts.** All seven New Feature Checklist items.

Each step ships green. If we halt at step 4, v1.5 still ships value (refactor + log formats + registry).

---

## 9. Documentation deliverables (the 7-item checklist)

| File | Change |
|---|---|
| `CHANGELOG.md` | Full v1.5.0 entry: refactor, CMSRegistry, POST-flood, log formats, SSH `ssh_root` |
| `README.md` | Update detection-pipeline section, add CMS auto-detect feature, update file tree |
| `wp-guardian.conf.example` | Add `[cms_detection]`, `[post_flood]`, `ssh_root_fail_threshold` |
| `wp-guardian.conf` | Mirror the new options |
| `install.sh` | Wizard prompts for POST-flood enable + threshold; CMS detect on by default |
| `CLAUDE.md` | New "Detector architecture" section, update "Detection Logic" pipeline order, add `cms_registry`/`post_flood`/`ssh_root` rule docs |
| `VERSION` | `1.5.0` |

---

## 10. Rollout

1. Develop on `feature/v1.5` branch
2. Test box first: spin up a copy on a non-production VM, replay last week's logs, verify zero new false-positives vs. v1.4.3
3. Merge to `main`, tag `v1.5.0`
4. Pull on `mail.maiahost.com` first (no web traffic = lowest risk; tests refactor + log discovery)
5. Observe 48h; if clean, deploy to `wp.maiahost.com` (will exercise log-format dispatcher and CMSRegistry properly)
6. Observe 1 week
7. Deploy to `web.maiahost.com`. POST-flood enabled in `dry_run` for first week.

---

## Calendar estimate

- Refactor (step 1): ~1 day
- Log-format dispatcher (step 2): ~half day
- CMSRegistry (step 3): ~1 day
- POST-flood (step 4): ~1.5 days
- Joomla/Drupal skeletons (step 5): ~half day
- SSH tune-up (step 6): ~half day
- Docs + install.sh (step 7): ~half day
- **~5 dev days + 1.5 weeks observation windows = ~3 calendar weeks** to all 3 servers.
