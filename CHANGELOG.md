# WP-Guardian Changelog

## v1.7.16 — the 404 storm is a ratio, not a count (2026-09-03)

`general_404` blocked a developer off his own client's site several times a
day. The rule counted 404s and 403s per IP and blocked at 50 in 300s, with no
notion of who was asking or why.

### What a single-page app does to that counter

A Next.js App Router client prefetches one payload per route it might navigate
to. The moment a deploy makes the build on disk disagree with the route
manifest inside an already-loaded browser tab, every one of those prefetches
misses at once:

```
GET /shipper/signup/__next.shipper.signup.txt?_rsc=1nnv4 HTTP/2" 404
    Referer: https://dev.example.com/     UA: Chrome/152 Edg/152
```

Measured on one host, in the worst single minute:

| | misses | of which framework payloads | successes |
|---|---|---|---|
| developer mid-rebuild | 134 | 129 | 100 |
| second developer IP | 74 | 68 | 156 |

134 misses in sixty seconds against a threshold of 50 per 300s. Six blocks
over four months, one escalated to a 30-day tier 2. The client was a current
browser sending a same-origin Referer that had already pulled 766 successful
responses from that vhost. The same burst hits any *visitor* who happens to be
browsing during a deploy.

### Framework payloads are counted separately

New `modules/spa_assets.py` classifies a request as a build tool's own
navigation payload: the `_rsc` and `_data` query parameters, the `/_next/`,
`/_nuxt/`, `/_astro/`, `/_app/`, `/page-data/`, `/@vite/`, `/@id/`, `/@fs/`
prefixes, and the generated filenames `__next.*.txt`, `__data.json`,
`_payload.json`, `app-data.json` and `*.map`. Those are charged against a new
`framework_404_threshold` (default 400) instead of `general_404_threshold`.

A budget, not an exemption, and deliberately not a bypass token:

- a `.php` path is **never** classified as a payload, and every high-value web
  rule — structural, instant, suspicious, tripwire, php_scan — is `.php`-scoped,
  so none of them is reachable this way;
- the query markers only count on a route-shaped path, so `/backup.zip?_rsc=1`,
  `/.env?_rsc=1` and `/.git/config?_rsc=1` remain ordinary enumeration;
- the ratio guard below still applies to whatever is left.

### A storm is a ratio, not a count

`general_404_min_fail_ratio` (default 0.9) requires misses to make up at least
that share of everything the IP was served in the window before a block. A
browser rendering a site pulls real content alongside its misses; a scanner
enumerating one pulls almost nothing that exists. `general_404_hard_limit`
(default 500) is the ceiling — past that many misses the ratio stops mattering,
so padding a scan with real requests only delays a block.

Replaying four months of production logs through the new code:

| | worst general bucket | worst payload bucket | worst miss ratio |
|---|---|---|---|
| developer A | 19 | 129 | 0.60 |
| developer B | 6 | 68 | 0.59 |
| scanner A | 389 | 0 | 1.00 |
| scanner B | 154 | 0 | 1.00 |
| scanner C | 271 | 0 | 0.98 |

Classification alone puts the developers 2.6x under the threshold; the ratio
guard is the second line. No scanner produced a single framework-bucket hit.
All three were still blocked.

### Also

- `general_404_threshold = 0` now disables the rule, as `[thresholds]` has
  always documented. It previously meant "block on the first miss".
- **In-memory trackers are now actually swept.** The 5-minute
  "clean up in-memory trackers" tick in the main loop had an empty body, so
  none of the eleven `HitTracker`s across the five detectors was ever pruned:
  `add()` trims an IP's timestamp list but never drops the key, so every IP
  the daemon had ever seen kept a dict entry for the life of the process. New
  `detectors.base.cleanup_trackers()` sweeps each tailer's detector, and
  `PostFloodDetector.cleanup()` (which already existed and was likewise never
  called) is invoked alongside it. This mattered enough to fix now because
  `hits_success` records every 2xx/3xx response, so the web trackers grow with
  ordinary visitors rather than only with attack traffic.

### Config

```ini
[thresholds]
framework_404_threshold = 400
general_404_min_fail_ratio = 0.9
general_404_hard_limit = 500

[whitelist]
framework_payload_paths =          # extra build-tool prefixes, rarely needed
```

Existing installs keep the old behaviour until these are added — see
`wp-guardian.conf.example`. A `sed` to retune in place:

```bash
sed -i '/^general_404_threshold/a framework_404_threshold = 400
general_404_min_fail_ratio = 0.9
general_404_hard_limit = 500' /opt/wp-guardian/wp-guardian.conf
```

### Files

- `modules/spa_assets.py` (new) — framework payload classification
- `detectors/web.py` — payload bucket, success tracking, `_is_scanning_ratio()`
- `detectors/base.py`, `wp-guardian.py` — tracker sweep
- `tests/test_web_404_storm.py` (new) — 15 tests: both measured incidents,
  detection regressions, and the evasion cases
- `wp-guardian.conf.example`, `README.md`, `VERSION`


## v1.7.15 — outbound volume and recipient fan-out corroboration (2026-08-12)

Future Work #3, and the payload-phase half of the abuse corroboration that
shipped in v1.7.12. Guardian had **no outbound visibility at all** before this:
`MailDetector` parsed four line shapes, all of them authentication, and
discarded Postfix delivery lines entirely.

Two new corroboration checks, alongside the three reconnaissance-phase ones:

| Check | Asks | Needs history |
|---|---|---|
| `outbound_volume` | is the account sending far above its own normal rate | yes — see below |
| `outbound_fanout` | did one message go to an implausible number of recipients | no |

They feed the same machinery as the existing signals: evidence **promotes** a
rule that geography alone leaves muted (`action_asns = alert_only` →
`corroborated_action`), and a promotion still only ever moves enforcement up.

### The queue ID is the join key, and the join is mandatory

Postfix logs two lines that matter, seconds apart and interleaved with
everything else:

```
postfix/smtps/smtpd[65793]: 0F5B86C403F7: client=host[198.51.100.20],
    sasl_method=PLAIN, sasl_username=erin@example.com
postfix/qmgr[4031830]: 0F5B86C403F7: from=<...>, size=80933, nrcpt=1 (queue active)
```

Only the first says who sent it. Only the second says how big it was and how
many recipients it had. And **qmgr logs inbound and outbound mail
identically** — on the reference host most sampled qmgr lines were inbound
bounces and spam. Counting qmgr alone would measure how much mail the server
*receives* for an account and report it as sending, so a queue ID is ours going
out only if it was first seen on an authenticated smtpd line.

`modules/outbound.OutboundTracker` holds a short-lived queue-ID map
(`outbound_queue_ttl`, default 300s) with a hard size cap, and rides the
existing maillog tailer — no fourth tailer, no second read of the same file.

This also catches PHP-originated mail: `web.maiahost.com` relays through the
mail host with a `sasl_username`, so a compromised *website* is visible through
exactly the same path.

### The volume check is inert for about two weeks after you upgrade

Deliberate, and the most important operational note in this release. The
baseline compares an account against **its own** history, because mailboxes
differ by orders of magnitude — a booking address that sends 400 a day and a
director's address that sends four are both normal, and no single number
describes them. On a fresh table there is nothing to compare against and every
account looks anomalous.

So the check stays silent until the table holds `outbound_min_observation_days`
(default 14) of history, measured **across all accounts** rather than the one
being examined. That global measure is what lets Guardian tell "this mailbox is
genuinely silent" from "Guardian was installed on Tuesday" — without it, the
strongest signal in the whole feature (a silent account suddenly sending
hundreds) would be unusable.

`--outbound-stats` shows how much has accrued and whether the check is armed.

**Unless you backfill.** `tools/backfill_maillog.py --outbound-only
--also-rotated --days 30` replays existing rotated maillogs into the new table
and arms the baseline immediately. A host with a month of logs on disk already
has the history; there is no reason to wait two weeks to rediscover it. The
replay runs through the real `OutboundTracker` — a backfilled row is produced
by exactly the code path that produces a live one — and `outbound_exists()`
makes re-runs idempotent.

**Recipient fan-out needs no baseline**, which is why it ships alongside rather
than later: it is armed the moment you upgrade and covers the window in which
the volume baseline is still accruing on a host with no logs worth replaying.

### Calibration against a real host

The fan-out default ships at **250, not the 50 originally chosen**, after
replaying 4.5 weeks of production maillog — 5,413 outbound messages, 63
senders. The distribution is starkly bimodal: **everything is ≤ 9 recipients
except a single message at 133**, a flooring retailer's Outlook-sent newsletter
to its own customer list.

A threshold of 50 would have fired on it, and on the worst possible account:
that mailbox is simultaneously the host's only bulk sender *and* its most
geographically scattered one (90 IPs, 11 ASNs, 4 countries, already the subject
of a false-positive compromise event). Those two risks are not independent —
they are concentrated on one paying client.

Two weeks of the same logs showed a maximum of 6 and would have justified
*lowering* the threshold instead. The lesson is the one the ASN rule already
taught in v1.7.11: a threshold calibrated on a short window sits on the noise
floor.

Note that the volume check is structurally immune to that newsletter — it
counts **messages**, and a newsletter is one message however many recipients it
carries. Fan-out is the fragile half of the pair, and the one to disable
(`outbound_fanout_threshold = 0`) if your users send bulk mail from their own
mailboxes.

### Design decisions worth knowing

- **Rolling query, not a stored per-account rate.** The baseline is computed on
  demand from the same table. A materialised rate would need its own recompute
  job and its own staleness semantics — a second place to be wrong — for a
  query that runs only when a compromise event fires (six times in this
  detector's lifetime).
- **The baseline excludes the recent window.** Otherwise a burst inflates the
  bar it is being measured against, and the check quietly stops working at
  exactly the volumes that matter most.
- **The baseline denominator is the account's own span**, not the window
  length. A mailbox created three days ago inside a thirty-day window would
  otherwise have its rate divided by ten — understating the baseline, and
  erring in the direction that manufactures evidence.
- **The absolute floor is load-bearing.** `outbound_volume_floor` (100 messages
  in the window) must be cleared as well as the multiplier. A multiplier
  against a near-zero baseline is a division by almost nothing and would fire
  on a mailbox going from one message a week to three.
- **Every new check fails toward NO SIGNAL**, like the existing three: no
  database, a raising query, an empty table, a young install — all resolve to
  silence. `tests/test_outbound.py` asserts each direction individually.

### Config

New in `[compromise_detection]`:

| Key | Default | Note |
|---|---|---|
| `outbound_monitoring` | `true` | false stops recording entirely |
| `outbound_window_hours` | `6` | wider than the detector's 1h — the burst and the geographic anomaly need not be simultaneous |
| `outbound_baseline_days` | `30` | |
| `outbound_min_observation_days` | `14` | the inert period |
| `outbound_volume_floor` | `100` | messages in the window |
| `outbound_volume_multiplier` | `10` | times the account's own rate |
| `outbound_fanout_threshold` | `250` | recipients on one message; `0` disables |
| `outbound_queue_ttl` | `300` | seconds a submission waits for its qmgr line |
| `outbound_max_pending` | `10000` | cap on unmatched submissions held in memory |

New in `[database]`: `outbound_retention_days = 30`. Shorter than the 90 days
`auth_sessions` keeps, because this table grows per *message* rather than per
login and its only consumer looks back 30 days. Guardian logs a startup warning
if you set it below `outbound_baseline_days`.

**No existing default was retuned, so no `sed` is needed** — `config-upgrade`
adds all of the above as missing keys.

`outbound_fanout_threshold` is still the one most likely to need tuning for
your users. Check before trusting it:

```bash
python3 wp-guardian.py --outbound-stats --days 30
```

### Schema

Migration `011_outbound_activity.sql` — new `outbound_activity` table, one row
per authenticated outbound message. Schema version 10 → 11. The table is also
in `_create_tables()`, which is what fresh installs get (they stamp the version
without replaying migrations).

### CLI

```
python3 wp-guardian.py --outbound-stats [--days N]
```

Shows how much history has accrued, whether the volume baseline is armed, the
configured trip points, and the busiest senders.

```
python3 tools/backfill_maillog.py --outbound-only --also-rotated --days 30
```

Arms the volume baseline from rotated logs. Add `--dry-run` first. Use
`--outbound` instead of `--outbound-only` to backfill auth history in the same
pass. Both are idempotent, so a re-run over overlapping logs is safe.

### Files changed

`modules/outbound.py` (new), `migrations/011_outbound_activity.sql` (new),
`tests/test_outbound.py` (new), `modules/corroboration.py`,
`modules/database.py`, `modules/migrator.py`, `detectors/mail.py`,
`tools/backfill_maillog.py`, `wp-guardian.py`, `wp-guardian.conf`,
`wp-guardian.conf.example`, `install.sh`, `README.md`, `CLAUDE.md`,
`CHANGELOG.md`, `VERSION`

---

## v1.7.14 — a clean restart no longer reports as a crash (2026-08-12)

Long-standing bug, surfaced by upgrading four hosts in a row. On
`wp.maiahost.com` a routine `systemctl restart` logged:

```
sqlite3.ProgrammingError: Cannot operate on a closed database
  File "wp-guardian.py", line 606, in start
    stats = self.db.get_stats()
systemd[1]: wp-guardian.service: Failed with result 'exit-code'.
```

A signal can arrive anywhere inside a main-loop iteration. `shutdown()` closes
the SQLite connection, but the loop had already passed its `while self.running`
check and carried on into the periodic tasks — against a closed database.

The daily-summary block was the only periodic task not wrapped in
`try/except`; both reapers already were. So it was the one place the race
became a fatal exception, exiting 1 and making a clean stop look like a crash.

The service always came back, so nothing was lost. The cost was diagnostic:
every routine restart left `Failed with result 'exit-code'` in the journal,
which is exactly the string you grep for when hunting a real failure. It cost
real time during this upgrade before being identified as benign.

Two fixes: re-check `self.running` at the top of each iteration so the race
window is one iteration rather than one full periodic pass, and wrap the daily
summary like its neighbours.

No config or schema changes.

### Files changed

`wp-guardian.py`, `VERSION`

---

## v1.7.13 — `--detect-mail-schema` output is paste-safe (2026-08-12)

Bugfix for v1.7.12. `--detect-mail-schema` printed its suggested settings
indented by two spaces, for looks:

```
Add to [mail_backend] in wp-guardian.conf:

  alias_table = virtual_aliases
  alias_source_column = source
```

That block is meant to be copy-pasted into an INI file, and **in INI syntax a
leading space makes a line a continuation of the key above it.** Pasting it
folded eight settings into the value of whichever key landed first, and the
next daemon start died with `DuplicateOptionError` against a key that already
existed further down the section. Observed on a production mail host: Guardian
crash-looped in `activating` until the config was repaired.

Two fixes:

1. **The block prints flush-left, between copy markers,** with an explicit
   warning not to add indentation.
2. **`load_config()` no longer dies with a raw traceback.** A malformed config
   now names the duplicated option and its section, points at indentation as
   the usual cause, and exits with a one-line message instead of a stack trace
   through `configparser` internals. A security daemon that won't start should
   say why in terms of the file the operator edited.

No config or schema changes.

### Files changed

`wp-guardian.py`, `modules/config.py`, `VERSION`

---

## v1.7.12 — abuse corroboration, and mail schema auto-detection (2026-08-12)

v1.7.11 made compromise detection stop acting on geography alone. It did that
bluntly — by muting the ASN rule. This release makes the rule useful again by
giving Guardian a way to tell a travelling client from a takeover.

**Geography selects candidates; abuse evidence authorises enforcement.**

### The dwell-window problem

The obvious corroboration signal is outbound spam. It is also the wrong one to
build first. A real takeover does not start sending immediately: credentials
are harvested, the attacker logs in, reads mail, hunts for financial threads,
plants persistence — and monetises days or weeks later. A model that only knew
about outbound volume would stay silent through the entire window in which
intervention is cheap, and speak up only once the damage was underway.

So the checks that ship here are the **reconnaissance-phase** artefacts:

| Signal | Why it fires early |
|---|---|
| `auth-failure burst` | credential stuffing leaves a pile of failures immediately before the success that matters |
| `sieve injection` | ManageSieve accepts the stolen IMAP password — no panel access needed, so it is the cheapest persistence available |
| `alias injection` | the same persistence step performed through a panel, as a forwarding row in the mail database |

Outbound volume and recipient fan-out are stronger proof and still land later —
they are just not sufficient on their own, and not first.

### 1. Corroboration promotes, it does not only veto

A muted rule is recovered when there is real evidence:

```ini
action_asns = alert_only     # 5 ASNs alone: a travelling client
corroborated_action = full   # 5 ASNs + a sieve rule planted yesterday: a takeover
```

Promotion only ever moves enforcement **up**, and a broken or unavailable check
resolves to "no signal" — an exception must never authorise taking a client's
mailbox offline. Every check fails in that direction by construction, and the
test suite asserts it for each one.

The inverse gate, `require_corroboration`, refuses to disable a mailbox
*without* evidence even when the rule says `full`. It is **off by default**: it
would weaken `countries`, the one rule that has ever been right, and six or
more countries in an hour is close to impossible legitimately.

The Telegram alert now answers the operator's actual first question — *is this
real, or is someone travelling again* — by listing the corroborating signals,
or stating plainly that there are none.

### 2. Mail schema auto-detection

The corroboration checks need to know your alias table, its columns, and where
Dovecot keeps maildirs. None of that is standardised, and this is an
open-source tool — hard-coding our own layout would have made the feature
useless to everyone else.

Both daemons already state their schema in plain text, so Guardian reads it:

```
postconf -h virtual_alias_maps
  -> mysql:/etc/postfix/mysql-virtual-aliases.cf
     query = SELECT destination FROM virtual_aliases WHERE source='%s' AND enabled=1

dovecot: password_query = SELECT email as user, password FROM virtual_users WHERE email='%u' AND enabled=1
         mail_location  = maildir:/var/vmail/%d/%n
```

That yields the alias table and columns, the mailbox table and its enabled
column, the database and host, and the maildir root. **No database credentials
required** — which matters, because detection has to run before Guardian's
least-privilege user exists.

It is stack-agnostic because the query *text* differs between stacks but the
place you find it does not:

```
postfix+dovecot MySQL   SELECT destination FROM virtual_aliases WHERE source='%s'
postfixadmin / mailcow  SELECT goto        FROM alias           WHERE address='%s'
iRedMail                SELECT forwarding  FROM forwardings     WHERE address=%s
```

```bash
python3 wp-guardian.py --detect-mail-schema
```

Prints each setting with the file it came from, verifies against a live
`DESCRIBE` when credentials happen to be available, and emits the exact `GRANT`
with real names filled in. It changes nothing — you copy across what you agree
with. `install.sh` runs the same detection and offers the result as defaults.

Detection never guesses. A query with a `JOIN` or `UNION`, a non-MySQL map
(`hash:`, `ldap:`), chained maps, or a `SELECT 1` existence probe all produce
"could not determine, here is the raw query" rather than a confident wrong
answer.

### Config options

| Key | Section | Default |
|---|---|---|
| `corroboration_enabled` | `[compromise_detection]` | `true` |
| `corroborated_action` | `[compromise_detection]` | `full` |
| `corroboration_lookback_hours` | `[compromise_detection]` | `168` |
| `corroboration_failure_threshold` | `[compromise_detection]` | `20` |
| `corroboration_failure_window` | `[compromise_detection]` | `3600` |
| `require_corroboration` | `[compromise_detection]` | `false` |
| `alias_table` | `[mail_backend]` | *(empty — check disabled)* |
| `alias_source_column` | `[mail_backend]` | *(empty)* |
| `alias_destination_column` | `[mail_backend]` | *(empty)* |
| `alias_created_column` | `[mail_backend]` | *(empty)* |
| `maildir_template` | `[mail_backend]` | *(empty — check disabled)* |

The forwarding check needs one extra, **read-only** grant. Guardian must never
be able to alter mail routing:

```sql
GRANT SELECT (source, destination, created_at)
  ON <db>.<alias_table> TO 'wp_guardian'@'localhost';
```

`INSTALL.md` gained a **Step 9: Mail Backend** covering all of this — the
section did not exist before, despite the mail backend having had privilege
requirements since v1.4.

### Notes

`maildir_template` uses `{domain}` / `{user}` / `{email}`, deliberately **not**
Dovecot's `%d` / `%n`. Python's `ConfigParser` runs `BasicInterpolation`, so a
literal `%` anywhere in `wp-guardian.conf` raises at load time and the daemon
never starts. Detection translates Dovecot's form for you.

The per-username failure counter is in memory rather than a table. The window
is an hour, write volume during an attack is enormous, and losing the counter
to a restart costs one corroborating signal — which fails toward "don't
disable". It also counts only failures from non-whitelisted sources, so an
operator's own whitelisted box looping on a stale password cannot manufacture
the evidence for someone else's punishment.

### Files changed

`modules/mail_schema.py` (new), `modules/corroboration.py` (new),
`modules/compromise.py`, `modules/mail_backend.py`, `detectors/mail.py`,
`detectors/roundcube.py`, `actions/telegram.py`, `wp-guardian.py`,
`tests/test_mail_schema.py` (new), `tests/test_corroboration.py` (new),
`tests/test_compromise_action.py`, `wp-guardian.conf`,
`wp-guardian.conf.example`, `install.sh`, `INSTALL.md`, `README.md`,
`CLAUDE.md`, `VERSION`

---

## v1.7.11 — compromise detection stops disabling travelling clients (2026-08-11)

On 2026-08-09 at 23:44 UTC, `DistributedAuthDetector` auto-disabled
`bob@example.net` and firewall-blocked five of the account holder's
own IP addresses. He was travelling in the US. The "many ASNs" the detector
saw were his phone roaming between AT&T carrier pools plus two rural ILECs and
Charter — five networks, one country. Confirmed directly with the client.

The mailbox stayed off for **16 hours and 4 minutes**, until an operator
noticed the next afternoon. The client-visible outage was ten minutes only
because his device happened not to poll overnight. That gap was luck.

### The pattern in the event history

| # | Date | Account | Rule | Countries | ASNs | IPs | Outcome |
|---|---|---|---|---|---|---|---|
| 1 | 2026-04-15 | alice@example.com | countries | **28** | **39** | **62** | real compromise |
| 2 | 2026-04-29 | erin@example.com | countries | 3 | 3 | 4 | operator-reversed |
| 3 | 2026-04-29 | erin@example.com | countries | 3 | 3 | 4 | operator-reversed |
| 4 | 2026-06-22 | frank@example.net | countries | 3 | 3 | 3 | reversed in 10 min |
| 5 | 2026-07-31 | carol@example.org | asns | 1 | 5 | 6 | false positive |
| 6 | 2026-08-09 | bob@example.net | asns | 1 | 5 | 5 | false positive (confirmed) |

Configured thresholds were 3 countries / 5 ASNs. **Every false positive landed
on its threshold exactly, never one above. The only true positive cleared it by
roughly an order of magnitude.** A wide empty region separates the two
populations and the thresholds were pinned to the bottom of it.

The account in event 6 was not even behaving unusually: it authenticated from
66 distinct IPs over the retained month and hit 3–5 distinct ASNs *every single
day*. Jul-15, Aug-03 and Aug-07 also reached five and did not fire. Aug-09
fired only because five happened to fall inside the same rolling 3600-second
window. The trigger was a windowing artifact over baseline behaviour.

### 1. Thresholds recalibrated — 6 countries / 10 ASNs

`threshold_distinct_countries` 3 → 6, `threshold_distinct_asns` 5 → 10. Both
the config default and the code fallback, so an install that never edits its
config still gets the change.

Validated against the table: event 1 still triggers with a wide margin, events
2–6 fall silent and produce no event at all.

### 2. Per-rule enforcement — `action_<rule>`

`action = full` applied identically to a 62-IP, 28-country trigger and to a
1-country, 5-IP one. Enforcement now resolves per trigger rule:

```ini
action = full            # global fallback, unchanged
action_countries = full
action_asns = alert_only # ← the rule that has never once been right
action_ips = full
```

`alert_only` records the event and alerts, but blocks nothing and disables
nothing. **This governs IP blocking too** — in event 6 five of the client's own
addresses were firewall-dropped alongside his mailbox, and that stops as well.

`asns` defaults to `alert_only` **in code**, not only in the shipped config, so
an existing install gets the protection on `git pull` + restart. An explicit
`action_asns = full` still wins. `alert` is accepted as an alias for
`alert_only`, and an unrecognised value fails safe to `alert_only` rather than
toward disabling a paying customer's mailbox.

### 3. Provisional disables — the outage is now bounded

Thresholds move the noise floor; they don't stop a sufficiently unusual
legitimate user from being disabled on geography alone. Detection will be wrong
again. What changed is what being wrong costs.

A compromise disable is now **provisional**: absent operator confirmation it is
reversed after `auto_reenable_hours` (default **4**). The hourly sweep calls
`CompromiseAction.reap_auto_disabled_mailboxes()`, restores the mailbox, and
fires a HIGH Telegram alert. The event stays OPEN and unreviewed.

This is safe because reversal does not restore the attacker's access: the
source IPs remain firewall-blocked on the normal tier schedule (24h minimum),
reaped separately by `Blocker.reap_expired_blocks`. Anyone benefiting would
need entirely fresh infrastructure.

`/confirm <event_id>` pins a disable permanently — before the window elapses,
or after, in which case it re-disables the mailbox. That is the expected path
when the operator wakes to an auto-restore alert and decides the detection was
right. `auto_reenable_hours = 0` restores the old "disabled until a human
notices" behaviour.

The reaper skips mailboxes an operator already re-enabled by hand, and leaves
an event unstamped when the mail backend call fails so the next sweep retries —
a backend outage must not silently strand a disabled mailbox.

### Config options

| Key | Section | Default |
|---|---|---|
| `threshold_distinct_countries` | `[compromise_detection]` | `6` *(was 3)* |
| `threshold_distinct_asns` | `[compromise_detection]` | `10` *(was 5)* |
| `action_countries` | `[compromise_detection]` | inherits `action` |
| `action_asns` | `[compromise_detection]` | `alert_only` |
| `action_ips` | `[compromise_detection]` | inherits `action` |
| `auto_reenable_hours` | `[compromise_detection]` | `4` |
| `auto_reenable_batch_limit` | `[compromise_detection]` | `50` |

### Commands

- `/confirm <event_id> [note]` — the compromise was real; pin the disable
- `--reap-mailboxes [--dry-run]` — run the provisional-disable sweep manually

`/compromises` now shows `confirmed` / `auto-restored` alongside open/resolved.

### Migration 010

Adds `confirmed_at`, `confirmed_by`, `auto_reversed_at` to `compromise_events`.
`confirmed_at` is deliberately distinct from `resolved_at`: *resolved* closes an
incident, *confirmed* asserts the compromise was genuine and enforcement must
stand. `auto_reversed_at` records that the reaper acted, leaving
`mailbox_disabled` intact as the forensic record of what the event did.

### Not done here

The report backing this release also proposed requiring a corroborating abuse
signal (outbound volume, recipient fan-out, rspamd verdicts, preceding
auth-failure burst) before any auto-disable. That is the right long-term fix —
geography should select candidates, abuse should authorise enforcement — but it
is **not** a small patch, because Guardian has no outbound-mail visibility at
all today: `MailDetector` parses four line shapes (SMTP/Dovecot auth
success/failure) and ignores Postfix delivery lines entirely, nothing reads
rspamd, and failed auths live in an in-memory `HitTracker` keyed by IP rather
than username. It is the "Outbound SMTP volume monitoring" item from the future
work list, scoped separately.

Also noted while verifying: `account_baselines` is **never written**.
`update_baseline()` and `is_known_location()` have zero call sites, so the
per-account country/city baseline has been dead code since v1.3.

### Files changed

`modules/compromise.py`, `modules/database.py`, `modules/migrator.py`,
`detectors/distributed_auth.py`, `actions/telegram.py`,
`actions/telegram_commands.py`, `wp-guardian.py`,
`migrations/010_compromise_confirmed_at.sql`,
`tests/test_compromise_action.py`, `wp-guardian.conf`,
`wp-guardian.conf.example`, `install.sh`, `README.md`, `CLAUDE.md`, `VERSION`

---

## v1.7.10 — the `suspicious` rule stops blocking logged-in customers (2026-08-04)

Two paying customers were blocked at the firewall in two days on
`mail.maiahost.com`, both while holding live, heavily-authenticated sessions.
Neither was doing anything unusual — they were clicking around a customer
portal.

### The bug

`detectors/web.py` runs six tripwire branches in order. Five of them consult
`is_ip_authenticated()` before blocking. The threshold-based `suspicious`
branch — the one whose own source comment reads *"suspicious but could be a
mistake"* — was the only one that did not. It was therefore **stricter than
the branch for known webshells**, which is documented as "no legitimate use
ever".

That inversion mattered because of what the rule matches. The pattern
`^/[a-z]{6,}\.php$` matches essentially any lowercase application endpoint of
six or more letters: `/client.php`, `/account.php`, `/billing.php`,
`/profile.php`, `/support.php`. The mitigating allowlist was a hardcoded
six-entry set that an operator could not extend without editing code — and had
already been patched reactively, which is why `/public.php` was exempt and
`/client.php` was not. `/index.php` survived only by the accident of being five
characters, missing both length regexes.

Three permission-denied responses within 300 seconds was all it took:

```
13:08:24  POST /client.php  200
13:08:29  POST /client.php  403   <- hit 1
13:08:34  POST /client.php  403   <- hit 2
13:08:40  POST /client.php  200
13:08:46  POST /client.php  403   <- hit 3 -> BLOCKED
```

Twenty-two seconds, with 200s interleaved proving the session was live
throughout. Those 403s were the application's own `AuthorizationException` —
a logged-in user touching a feature outside their permissions. The IP had 203
successful authentications in the preceding 24 hours.

Present since `fae423c` (2026-05-03), so roughly three months in the fleet.

### 1. Authenticated IPs are exempt (the fix that matters)

The `suspicious` branch now consults `is_ip_authenticated()` and logs a warning
instead of blocking, identical to the five branches around it. Requires no
configuration and no per-install knowledge of which endpoints an app exposes.
Verified against both incidents: neither IP would have been blocked.

This widens what a recently-authenticated IP may do before tripping *this*
rule. That tradeoff is already accepted for webshell and tripwire hits, which
are strictly higher-signal, and the `instant` / `structural` branches still run
*before* this one — so a known webshell blocks an authenticated IP as before.
Real credential theft remains covered by `DistributedAuthDetector`, which
watches the same username across countries/ASNs regardless of trust state.

### 2. `suspicious_statuses` — which statuses count as scanning evidence

New `[thresholds] suspicious_statuses`, **default `404, 401, 403` — unchanged
behavior.**

The bug report that prompted this release recommended defaulting to `404`
alone, reasoning that 404 means "no such resource" (enumeration) while 401/403
mean the app made a deliberate auth decision. On `mail.maiahost.com` that is
exactly right: of 9 total 403s on matching paths, 6 were the two false
positives and the other 3 were single hits from three different scanner IPs on
three different days — never enough to reach a threshold of 3. 401 had never
occurred at all.

It does not generalize, and the report flagged that risk itself. Measuring the
rest of the fleet before choosing the default:

| Host | 404 | 403 | 401 |
|---|---|---|---|
| mail (nginx, portal) | 4,223 | 9 | 0 |
| web (Apache) | 212 | **22,631** | 0 |
| srv.dotcom.services (OLS, 147 vhosts) | 348,054 | 28,297 | 8,706 |

Deny-heavy installs answer scans with 403, not 404. On the Apache host 403
outnumbers 404 on these paths by roughly 100:1, and the top offenders are
unambiguous — `/phpinfo.php`, `/x.php`, `/config.php`, `/1.php`,
`/classwithtostring.php`. A 404-only default would have removed **almost every
detection on that host**, and roughly 10% on `srv`. So the default preserves
current behavior and the knob exists for portal-style hosts to narrow it.

### 3. `legit_php_paths` — a per-install allowlist

New `[whitelist] legit_php_paths`, comma-separated, added to (never replacing)
the built-in set. `/client.php` and `/index.php` join the built-ins —
`/index.php` explicitly, so it no longer depends on a filename-length accident.

### 4. `suspicious_threshold` is configurable

Was hardcoded to 3 while every neighbouring threshold was configurable. Default
unchanged.

### Fleet blast radius

Across all four hosts: **12,223** `suspicious` blocks total, **2** false
positives — both on mail, both already released. The rule is doing real work;
it just had no floor under it. The audit query is in `docs/` and reproduced in
the report: join `block_log` against `auth_sessions` in the 24h before each
block.

### Files changed

- `detectors/web.py` — auth guard, `suspicious_statuses`, `suspicious_threshold`, allowlist
- `modules/config.py` — `parse_csv_set()`; `parse_service_list()` now delegates to it
- `wp-guardian.conf`, `wp-guardian.conf.example` — three new keys
- `install.sh` — setup questions for the endpoint allowlist and status list
- `tests/test_web_suspicious.py` — **new**, 11 regression tests

No database migration. All three config keys are additive with behavior-
preserving fallbacks, so existing `wp-guardian.conf` files need no edits.

## v1.7.9 — false positives are no longer permanent (2026-08-03)

Four bugs that compounded into a multi-day mail outage for a client on
Microsoft 365. Each one was survivable alone; together they turned a single
heuristic trip into a permanent ban that no automatic process could undo.

### 1. Trusted ASNs were exempt from detection but not from enforcement

`DistributedAuthDetector` excludes `trusted_asns` (Microsoft, Google, Apple)
from the country and ASN counts, because cloud mail providers relay one
legitimate user through DCs in many countries. But every enforcement path
ignored that list:

- `recent_auth_ips()` was a bare `SELECT DISTINCT ip` with no ASN filter, and
  `CompromiseAction` fed its output straight to `_block_ips()`.
- The SMTP / IMAP / POP3 / Roundcube brute-force rules never consulted it at all.

So Microsoft's ASN was too trusted to count as *evidence*, then got
firewall-dropped as the *attacker*. Since new Outlook syncs IMAP through
Microsoft's cloud rather than from the PC, that silently killed the client's
mail — presenting as "Waiting for your email provider" forever.

**Fixed** in two layers:

- `Blocker.block()` refuses to block an IP in a trusted ASN for the services
  in the new `trusted_asn_services` list (default `smtp, imap, pop3, roundcube`),
  plus any `rule='compromise'` block. Scoped by service on purpose — AS8075 is
  Office 365 *and* Azure, and an Azure VM scanning `wp-login.php` is still a
  legitimate block. Manual operator blocks (`force_tier`) override the guard.
- `CompromiseAction` partitions the window's IPs by ASN before blocking. The
  compromise event still records **every** IP in `sample_ips` for forensics;
  only untrusted ones are eligible for the firewall.

Per-IP whitelisting was never a fix here — Microsoft rotates these relays
(`40.97.x`, `40.104.x`, `52.96.x`). The ASN is the durable key. When GeoIP is
down or has no answer, the guard falls back to `db.last_known_asn()`, so a
relay that has authenticated here before stays protected.

### 2. Guardian's own remediation manufactured the next punishment

When a mailbox is auto-disabled after a compromise event, Dovecot's
`password_query` filters on `AND enabled = 1` — so the owner's own mail client
becomes a failed-auth generator on every retry. `mail_trust_duration` did not
cover this: trust requires a *successful* auth, and a disabled mailbox can
never produce one. After 24h the trust lapsed and the victim's own IP was
blocked, then escalated.

**Fixed:** the mail and Roundcube detectors now suppress blocking when both
hold — Guardian currently has that mailbox disabled, *and* the failing IP has
successfully authenticated as that username before. Both conditions are
required: without the second, knowing the name of a disabled mailbox would buy
an attacker unlimited free attempts. Fires a `HIGH` Telegram heads-up so the
account doesn't stay silently out of service.

Coverage note: Dovecot logs `user=<...>` on failure reliably, so IMAP/POP3 is
fully covered. Postfix rarely logs `sasl_username` on failure, so SMTP is
best-effort.

### 3. Unblocking a false positive armed the next escalation

`unblock()` reset `ip_history.current_tier` but left `block_log` untouched —
and `determine_tier()` escalates off `block_log`. So rescuing a client made
things *worse*: unblock → client retries → re-blocked at tier 2 → unblock →
tier 3 permanent. Observed live as a 1 → 2 → 3 climb in four minutes, which is
an operator at a keyboard, not a bot.

**Fixed:** migration 009 adds `block_log.cleared_at`. `unblock()` marks the
IP's history cleared and `get_recent_block()` ignores cleared rows, so a manual
unblock resets the ladder. Blocks retired by the reaper are **not** marked
cleared — those should still escalate on return, which is the point of the
three-tier design.

### 4. Block durations were never enforced

`tier1_duration = 24h` was written to `block_log`, the log line and the Telegram
alert, but nothing ever expired it. There was no reaper and no systemd timer,
and `Blocker.unblock()` was reachable only from the CLI and Telegram handlers.
The `firewalld` backend even documents *"the daemon's cleanup loop calls
unblock() when an entry expires"* — that call never existed.

The failure mode differed by backend:

| Backend | Actual behavior before v1.7.9 |
|---|---|
| firewalld | ipsets carry no TTL → **every block was permanent** |
| mikrotik / nftables / csf | firewall expired the entry on its own TTL, but `current_tier` stayed set → `block()` short-circuited on "already blocked" and **a returning attacker was never re-pushed** |

**Fixed:** `Blocker.reap_expired_blocks()` runs on the hourly cleanup tick.
Expiry is derived from `ip_history.tier_changed_at` against the configured tier
durations — no schema change and no backfill, since `tier_changed_at` has always
been written by `record_block()`. `unblock()` is idempotent, so one sweep fixes
both failure modes. Tier 3 is never expired. If a firewall call fails the tier is
left set and the next sweep retries, so a backend outage can't silently drop
blocks from the database.

**The firewall call is skipped where it would be a no-op.** Backends declare a
new `expires_own_entries` capability (default `False`):

| Backend | Flag | Reaper does |
|---|---|---|
| mikrotik, nftables, csf | `True` | tier reset only — the entry already expired on the firewall's own TTL |
| firewalld, pfsense | `False` | `unblock()` then tier reset — nothing else removes these |

On MikroTik that turns a 500-IP sweep from 1,500 SSH round-trips into pure
SQLite. The tier reset is the half that matters everywhere: without it,
`block()` short-circuits on "already blocked" and the returning attacker is
never re-pushed, even though RouterOS dropped the entry hours ago. Default
`False` is the safe direction — a wrong `True` would leave entries blocked at
the firewall that the database no longer tracks.

Batched at `reap_batch_limit` (default 500/hour), which now only really binds
on firewalld and pfSense; on the self-expiring backends a sweep issues no
firewall calls at all.

### New

**CLI:** `--reap-blocks`, optionally with `--dry-run` and `--reap-limit N`
```
python3 wp-guardian.py --reap-blocks --dry-run     # preview the backlog
python3 wp-guardian.py --reap-blocks               # drain one batch now
python3 wp-guardian.py --reap-blocks --reap-limit 2000
```

**Config** — `[escalation]`
```ini
reap_enabled = true       # hourly block-expiry sweep
reap_batch_limit = 500    # max expiries per sweep
```

**Config** — `[compromise_detection]`
```ini
trusted_asn_services = smtp, imap, pop3, roundcube
```

### Upgrade notes

- **Run `--reap-blocks --dry-run` first.** On a long-running install the first
  sweep will retire a large backlog of blocks that expired months ago. That is
  correct — they should never have outlived their duration — but it is a real
  change in posture, so look at the number before letting the daemon do it.
- Migration 009 is additive (`ALTER TABLE ... ADD COLUMN`) and idempotent.
- Raising `threshold_distinct_asns` above the default `5` is worth considering
  if you have users who roam between carriers; five distinct non-trusted ASNs
  in an hour is reachable by a legitimate travelling user with a phone and a
  laptop.

### Files changed

- `modules/blocker.py` — trusted-ASN enforcement guard, `reap_expired_blocks()`,
  `unblock()` clears escalation history, `alert_guardian_disabled_skip()`
- `backends/base.py` — `expires_own_entries` capability flag (default `False`)
- `backends/mikrotik.py`, `backends/nftables.py`, `backends/csf.py` — declare `True`
- `backends/pfsense.py` — declare `False`; `backends/README.md` — document the flag
- `modules/compromise.py` — partition attacker IPs by trusted ASN
- `modules/database.py` — `cleared_at` column, `clear_block_history()`,
  `get_expired_blocks()`, `count_expired_blocks()`, `expire_block_tier()`,
  `recent_auth_ips_with_asn()`, `is_mailbox_disabled_by_guardian()`,
  `has_auth_history()`, `last_known_asn()`, `get_recent_block()` filter
- `modules/config.py` — `parse_asn_list()`, `parse_service_list()`
- `modules/migrator.py` — `CURRENT_SCHEMA_VERSION` 8 → 9
- `migrations/009_block_cleared_at.sql` — new
- `detectors/base.py` — `is_guardian_disabled_client()`
- `detectors/mail.py`, `detectors/roundcube.py` — disabled-mailbox suppression
- `detectors/distributed_auth.py` — use the shared ASN parser
- `wp-guardian.py` — reaper in the hourly loop, `--reap-blocks` / `--reap-limit`
- `install.sh`, `wp-guardian.conf`, `wp-guardian.conf.example`, `README.md`,
  `CLAUDE.md`, `VERSION`

## v1.7.8 — manual block command (`/block` + `--block`) (2026-06-17)

Adds an operator-initiated block to complement the existing `--unblock` / `/unblock`.
Until now, blocking was only ever triggered automatically by the detectors —
there was no way to say "block this IP/range right now" without editing a config
or waiting for the bot to trip a threshold.

### What's new

**Telegram:** `/block <ip|cidr> [duration]`
```
/block 192.0.2.50            # permanent (default)
/block 192.0.2.50 24h        # 24 hours
/block 192.0.2.0/24          # block the whole /24, permanent
/block 192.0.2.0/24 30d      # 30 days
```

**CLI:** `--block` (mirror of `--unblock`)
```
python3 wp-guardian.py --block 192.0.2.50
python3 wp-guardian.py --block 192.0.2.50 --duration 24h
python3 wp-guardian.py --block 192.0.2.0/24 --duration 30d
```

### Semantics

- **Default duration is permanent (tier 3).** A manual block is a deliberate
  decision, so it sticks until you `/unblock` it. Pass a duration to make it
  temporary.
- **Duration → tier (single IPs).** The per-IP TTL is owned by the firewall
  backend via the escalation tiers, so a duration maps to the nearest tier that
  *covers* it: `≤ tier1_duration` → tier 1, `≤ tier2_duration` → tier 2, else
  tier 3 (permanent). The reply always states the effective tier/duration, so a
  `7d` request that lands on the 30d tier is shown as such — no hidden mismatch.
  `perm`/`permanent`/`forever` → tier 3.
- **CIDR durations pass straight through** to the backend (`block_cidr`), so an
  arbitrary `7d` on a range is honored exactly. Works on every backend (all five
  set `supports_cidr = True`).
- **Safety guards.** A manual block refuses to touch a whitelisted IP, a CIDR
  that overlaps any whitelisted/friendly address, or a range wider than `/16`
  (collateral-damage guard). `WhitelistManager.overlaps_cidr()` is the new
  arbitrary-prefix whitelist check behind this.
- **Re-asserts stale blocks.** If the IP is already marked blocked, the manual
  block clears the firewall entry first and re-pushes at the requested tier —
  which also re-applies a block whose firewall TTL has expired while the DB still
  reads "blocked" (the stale-tier case).
- **No extra Telegram noise.** Manual blocks are logged to `blocked.log` /
  `guardian.log` but do not emit a separate Telegram alert — the `/block` reply
  (or CLI output) is the confirmation, exactly like `/unblock`.

### Files changed

- `modules/blocker.py` — `block_manual()` + `_block_ip_manual` / `_block_cidr_manual`
  helpers; `block()` gains `force_tier=` and `notify=` kwargs (both backward-compatible).
- `modules/whitelist.py` — new `overlaps_cidr()` (arbitrary-prefix overlap check).
- `actions/telegram_commands.py` — `/block` command + `/help` entry.
- `wp-guardian.py` — `--block` / `--duration` CLI args + handler.
- `README.md`, `CLAUDE.md`, `VERSION` — docs + version bump.

No new config options; the feature reuses the existing `[escalation]` tier durations.

## v1.7.7 — blocks tear down already-established connections (conntrack flush) (2026-06-07)

A distributed XML-RPC flood (POST `/xmlrpc.php` across ~150 WordPress sites) on
`wp.maiahost.com` exposed an enforcement gap in the **firewalld** backend:
detection and blocking fired correctly, but blocked IPs kept hammering the
server for *minutes* after being blocked. One offender (`192.0.2.35`) logged
**48,000+ requests after** its block timestamp.

### Root cause

firewalld's `filter_INPUT` chain starts with `ct state {established, related}
accept`. Our drop rule (rich rule → `filter_IN_public_deny`) lives **downstream
of that accept, inside the same base chain**, where `accept` is terminal. So
once an attacker has an established TCP connection — and HTTP keep-alive means
every subsequent POST rides the *same* connection — the early accept matches
first and the drop is never reached. Adding an IP to the set therefore only
stopped *new* connections; existing floods ran until they closed on their own.

This is **firewalld-specific**. The direct `nftables` backend installs its drop
in its *own* base chain, and in nftables a `drop` verdict is terminal across all
base chains on a hook (an earlier chain's `accept` can't save the packet), so it
already dropped established connections.

### What changed

New `[firewall] flush_conntrack = true` (default on). After adding an IP/CIDR to
the drop set, the firewalld and nftables backends run `conntrack -D -s <ip>` to
destroy its live connection-tracking entries. The next packet on each keep-alive
connection is then re-evaluated as `ct state new`, bypasses the established-accept,
and hits the drop — block becomes effective in under a second. (This is the same
technique fail2ban uses on ban, and it holds even with
`nf_conntrack_tcp_loose=1`: the packet that re-creates the entry is seen as
`new`, gets dropped, and never confirms.)

The block log now reports how many live connections were torn down, e.g.
`firewalld BLOCKED 192.0.2.35 tier=1 reason=... (tore down 312 live conns)`.

### Dependency: the `conntrack` CLI

The flush requires the `conntrack` binary (package `conntrack-tools` on
RHEL/AlmaLinux/CyberPanel, `conntrack` on Debian/Ubuntu). If it is missing the
flush is a **safe no-op** — new-connection blocking is unaffected — and Guardian
warns loudly:

* at **startup** (firewalld backend logs a WARNING in `guardian.log`),
* during **`install.sh`** (offers to install it when you pick firewalld/nftables),
* during **`update.sh`** preflight (offers to install it if the live config uses
  firewalld/nftables and `conntrack` is absent — non-fatal, never aborts).

**New: table-driven OS-package preflight.** `update.sh` previously validated only
Python/pip dependencies (`requirements.txt`), which is why a missing
`conntrack-tools` was never flagged on past updates — it's an OS package, not a
pip module. v1.7.7 adds a second preflight, right after the pip one, driven by a
`SYSTEM_DEPS` table (the single source of truth): each entry declares the binary,
its package name per manager (`dnf`/`yum`/`apt`), whether it's fatal, the config
condition under which it applies, and the consequence if missing. conntrack is
the first entry; adding a future OS-package dependency is a one-line table edit.

**Action for existing firewalld/nftables hosts:** install conntrack-tools to arm
the fix —

```bash
dnf install -y conntrack-tools     # RHEL / AlmaLinux / CyberPanel
sudo systemctl restart wp-guardian
```

### Why not reorder the firewall rules

The other obvious fix — putting our drop *before* the established-accept — can't
be done cleanly in firewalld: the accept is in firewalld's built-in base chain,
ahead of the zone jump where rich rules live, so no rich-rule priority beats it.
Fighting that with a foreign base chain referencing firewalld's set is fragile
and gets clobbered on `firewall-cmd --reload`. conntrack flush is the
low-risk, surgical fix and only ever touches IPs we are already blocking.

### Files changed

* `modules/conntrack.py` — **new.** `ConntrackFlusher` (detect binary, flush a
  source IP/CIDR, report deleted-flow count).
* `backends/firewalld.py` — construct the flusher from `[firewall]
  flush_conntrack`; flush after `block()`/`block_cidr()`; startup arm-check
  warning when the binary is missing.
* `backends/nftables.py` — same flush wiring for parity / faster teardown.
* `update.sh` — **new table-driven `SYSTEM_DEPS` preflight** for OS-package
  binaries (first entry: conntrack); detects the package manager, offers to
  install, honors a per-dep `fatal` flag. Extensible for future OS deps.
* `wp-guardian.conf.example`, `wp-guardian.conf` — new `[firewall]
  flush_conntrack` option (documented, default `true`).
* `install.sh` — `install_conntrack_tools()` helper, invoked for the
  firewalld/nftables backends.
* `README.md`, `CLAUDE.md`, `VERSION` (→ 1.7.7).

## v1.7.6 — apache_vhost_uid: recognize per-user PHP-FPM / suEXEC isolation (2026-06-02)

The `apache_vhost_uid` posture check previously recognized only the three
Apache-*native* per-tenant uid directives — `AssignUserID` (mod_ruid2 /
mod_hostinglimits), `SuexecUserGroup` (mod_suexec), and `User`+`Group`
(mpm_itk). On a host that pins the tenant uid in the **PHP-FPM pool** (or
via **mod_lsapi / suEXEC CGI**) rather than in the vhost, none of those
directives appear — so the check failed *every* tenant vhost and reported
"would run PHP as system apache". Real example: `web.maiahost.com`
(Apache + CloudLinux alt-php-fpm) raised a HIGH posture-drift alert for
**186 of 186** vhosts even though all of them route PHP to per-user FPM
sockets. A 100%-of-vhosts failure was the signature of an architecture
mismatch, not 186 misconfigurations.

### What changed

`posture_checks/check_apache_vhost_uid.py` now resolves each tenant
vhost's actual **PHP-execution identity** instead of looking only for the
three Apache directives. A vhost counts as correctly isolated if it uses
ANY of:

* an Apache-native uid directive (as before), OR
* a **per-user PHP-FPM** handler — `SetHandler "proxy:unix:/…/<user>.sock|fcgi://…"`
  or `ProxyPassMatch … unix:/…/<user>.sock` — whose socket resolves to a
  real, non-shared local user, OR
* a **mod_lsapi / suEXEC CGI** handler (`application/x-httpd-php<NN>-cgi`,
  `lsphp`, `lsapi`, `fcgid`), which runs as the file owner, OR
* `SetHandler none` (PHP disabled for that vhost).

It now FAILs (HIGH) only the genuinely dangerous cases — PHP wired to a
**shared pool**: a TCP `fcgi://host:port`, a shared socket (`www.sock`),
a socket that resolves to `apache`/`nobody`, or plain mod_php
(`application/x-httpd-php` with no per-user suffix).

A vhost with **no detectable PHP wiring at all** (it would fall through to
a server-global handler the vhost can't reveal) is now a softer **WARN**
(MEDIUM), and only when the host otherwise uses per-vhost handlers — so a
single copy-pasted "ghost vhost" still stands out, while hosts that pin
the uid globally (e.g. global mod_ruid2) stay quiet instead of getting a
false HIGH on every site.

Evaluation is now **per source file** (one tenant site per `*.conf` on
the common stacks), so a site's `:80` redirect stub no longer masks the
`:443` block's per-user handler.

Verified against live `httpd -S` on `web.maiahost.com`: the same 186
vhost blocks now resolve to 93 tenant sites (90 per-user FPM, 2
suEXEC/lsapi, 1 php-disabled) → **0 risk / 0 unwired → PASS**.

### Behavior change

* The check's `value` payload changed shape (`tenant_site_count`,
  `mechanisms`, `risk_sites`, `unwired_sites` replace the old
  `ghost_vhosts`). The first run after upgrade records one posture-state
  re-baseline transition; no action needed.
* Hosts with a genuine shared-apache vhost still FAIL HIGH as before.

### Files changed

* `posture_checks/check_apache_vhost_uid.py` — FPM/lsapi-aware rewrite.
* `VERSION` — bumped to 1.7.6.

### Rollout

```bash
cd /opt/wp-guardian && git pull && sudo bash update.sh
```

No config changes required. The check re-evaluates on the next posture
audit cycle (restart the daemon to re-run immediately).

## v1.7.5 — update.sh preflight: check the full requirements.txt (2026-05-28)

Hardens the `update.sh` Python-dependency preflight after a real-world
incident on `srv.dotcom.services`: a post-reinstall server had been
running for 21 days with `geoip2` (and several other modules) missing,
because the pre-v1.7.5 preflight only checked dependencies for features
*currently enabled* in `wp-guardian.conf`. With `[geoip] enabled = false`
in the live config, `geoip2` was never imported by the preflight and
the gap stayed invisible — until the operator flipped the switch.

### What changed

`update.sh`'s "Checking Python dependencies" step now:

* Parses the full `requirements.txt` (strips version specs, markers,
  extras) and maps PyPI package names to import names via a
  `PKG_TO_MODULE` table (e.g. `PyMySQL` → `pymysql`).
* Tries to import every entry, regardless of which features are
  currently toggled on.
* For each missing module, surfaces a `feature label — consequence`
  line via a `CONSEQUENCES` map so the operator knows what they lose
  if they decline to install. New entries in `requirements.txt` should
  add a `CONSEQUENCES` row at the same time.
* The post-install re-check uses the same full-requirements-txt
  approach (no more feature-gated re-verify that would falsely report
  "OK" if the new dep was for a disabled feature).

### Caveats / out of scope

* This only catches the gap when `update.sh` actually runs. Operators
  who do `git pull && systemctl restart wp-guardian` directly still
  bypass the preflight. A follow-up could move an equivalent check to
  daemon startup, but that's a wp-guardian.py change and lives outside
  this patch.
* The `CONSEQUENCES` map in `update.sh` must be kept in sync with
  `requirements.txt`. If you add a new dependency without updating
  `CONSEQUENCES`, the preflight still flags it as missing, just with a
  generic "feature using this module will fail at runtime" message.

### Files changed

* `update.sh` — preflight rewrite (full requirements.txt scan + recheck).
* `VERSION` — bumped to 1.7.5.

### Rollout

```bash
cd /opt/wp-guardian && git pull && sudo bash update.sh
```

No config changes required. No daemon restart required (this is a
build-tooling fix).

## v1.7.4 — firewalld backend: native ipsets, no `--reload` on hot path (2026-05-28)

The firewalld backend used to add one permanent `rule family="ipv4"
source address="<ip>" drop` per blocked IP and then run
`firewall-cmd --reload` on every single block. On `wp.maiahost.com` that
list had grown to **1,097 rich rules**, every dropped packet walked the
entire `ip saddr` comparison chain in nftables, and each new block cost
a full firewalld reload (D-Bus churn + a momentary packet-filter
flush).

### Refactor

The backend now mirrors the design already in place in
`backends/nftables.py`:

* Two firewalld-managed ipsets:
  * `wp_guardian_blocked` — `hash:ip`, family `inet`, individual IPs
    (tier 1 / 2 / 3).
  * `wp_guardian_cidr` — `hash:net`, family `inet`, /24 aggregations.
* One drop rich rule per ipset in the configured zone — every blocked
  packet matches a single set lookup.
* `block()` / `unblock()` / `is_blocked()` / `block_cidr()` /
  `is_cidr_blocked()` are now single `firewall-cmd --ipset` calls
  (runtime + `--permanent` for reboot persistence). **No `--reload` on
  the hot path.**
* `ensure_firewall_rules()` is idempotent: a healthy steady-state
  startup does four queries and no reload at all. Reloads only happen
  when something was actually created.
* `get_block_counts()` returns `{ips, cidr, total}` from
  `--get-entries` instead of walking the rich-rule list.

### Migration tool

```bash
sudo python3 /opt/wp-guardian/tools/migrate_firewalld_to_ipset.py --dry-run
sudo python3 /opt/wp-guardian/tools/migrate_firewalld_to_ipset.py
```

Folds existing legacy rich rules into the new ipsets. Stops the
daemon, ensures the ipsets and ipset-referencing rich rules exist,
imports each legacy `rule family="ipv4" source address="<addr>" drop`
into `wp_guardian_blocked` (or `wp_guardian_cidr` if `<addr>` carries
a prefix), removes the legacy rule, performs a single
`firewall-cmd --reload`, and restarts the daemon. Idempotent — safe to
re-run.

### Behaviour preserved

* Tier TTLs remain owned by the WP-Guardian database / cleanup loop.
  We deliberately do NOT use ipset per-entry timeouts; the other
  backends behave the same way and the daemon already knows how to
  expire blocks.
* `FirewalldBackend` public method signatures, `supports_cidr = True`,
  and `supports_friendly_list = False` are unchanged — `factory.py`
  and the Blocker module need no changes.
* No config changes required. `[firewalld] zone` still controls which
  zone the drop rich rules are added to.
* IPv4-only, same as before.

### Files changed

* `backends/firewalld.py` — full rewrite.
* `tools/migrate_firewalld_to_ipset.py` — new one-shot migration tool.
* `VERSION` — bumped to 1.7.4.

### Rollout

```bash
cd /opt/wp-guardian && git pull && sudo bash update.sh
sudo python3 tools/migrate_firewalld_to_ipset.py --dry-run
sudo python3 tools/migrate_firewalld_to_ipset.py
```

Verify on the host:

```bash
firewall-cmd --permanent --get-ipsets        # wp_guardian_blocked wp_guardian_cidr
firewall-cmd --zone=public --list-rich-rules # 2 lines, both ipset-referencing
nft list ruleset | wc -l                     # collapsed from ~1,595 to ~500
```

## v1.7.3 — Log discovery: catch unprefixed `access.log` filename (2026-05-27)

Patch fix for `discover_access_logs()` in `wp-guardian.py`. The discovery
patterns only matched `/home/*/logs/*.access_log` and
`/home/*/logs/*.access.log` — names that include a domain prefix. Hosts
where the per-vhost access log is named simply `access.log` (no prefix)
were missed entirely.

### Symptom

On `wp.maiahost.com` (OLS, 187 vhosts) and `web.maiahost.com` (Apache,
13 vhosts), `--discover-logs-save` populated `logfiles.txt` only with
the global server log (`/usr/local/lsws/logs/access.log` /
`/var/log/httpd/access_log` etc.). All 179 + 13 per-vhost access logs
were silently unmonitored — WordPress brute-force, tripwire, login
isolation and POST-flood detection were inactive on those hosts since
the original discovery runs on 2026-05-03 and 2026-05-05.

### Fix

Added `/home/*/logs/access.log` to the patterns list. Re-running
`--discover-logs-save` followed by a daemon restart now picks up the
per-vhost logs. Existing entries in `logfiles.txt` are preserved
(merge, not replace).

### Files changed

* `wp-guardian.py` — `discover_access_logs()` patterns + the help text
  printed when no logs are found.

### Rollout

```bash
cd /opt/wp-guardian && git pull && \
  python3 wp-guardian.py --discover-logs-save && \
  sudo systemctl restart wp-guardian
```

## v1.7.2 — Livepatch detection: use tool-state, not systemd is-active (2026-05-07)

Same-day correctness fix on top of v1.7.1. The detection added in
v1.7.1 used `systemctl is-active <service>` as the "is the livepatch
running?" signal. That works for long-running daemons but is wrong for
KernelCare, whose `kcare.service` is a **oneshot** unit that exits
after pulling and applying patches via the timer. Between timer
firings, `is-active` returns `inactive` — even though the kernel is
fully livepatched.

Result: every KernelCare-protected host (including srv.dotcom.services
on AlmaLinux 9 with KernelCare 3.6) would have shipped a false
MEDIUM "kernelcare installed but service inactive" finding from the
new `livepatch_state` check, AND `kernel_copy_fail` would not have
demoted CRITICAL on those hosts.

### Detection now uses authoritative per-provider signals

For each provider, the v1.7.2 detection asks the provider's own CLI
whether a patch is loaded into the running kernel — that's what we
actually care about, regardless of whether a systemd service happens
to be running RIGHT NOW.

  * **KernelCare**: `kcarectl --info` output contains
    `patch is applied`. Fallback: `kcare.timer` reports active.
  * **kpatch**: `kpatch list` shows loaded patch modules. Fallback:
    `/sys/kernel/livepatch/` directory non-empty (kernel-exposed
    livepatch entries).
  * **Ksplice**: `uptrack-show` succeeds with at least one entry.

If a tool is installed but no livepatch is currently loaded AND no
recurring timer/service is enabled, the detection reports
`active=False` — which is the genuinely-dangerous state the
`livepatch_state` MEDIUM finding is for.

### Verified on srv.dotcom.services

Before fix: detection would have reported
`{provider:'kernelcare', active:False}`.

After fix: `kcarectl --info` returns
`kpatch-state: patch is applied` → detection reports
`{provider:'kernelcare', active:True}`.

`kernel_copy_fail` correctly demotes severity from CRITICAL to LOW
(and notes "verify CVE coverage with `kcarectl --patch-info`").
`livepatch_state` reports PASS.

### Files modified

- `modules/host_profile.py` — `_detect_livepatch()` rewritten with
  per-provider authoritative signals + sensible fallbacks
- `VERSION` — 1.7.1 → 1.7.2

### Backwards compat

No schema, config, or check API changes. Existing
`extras.livepatch_provider` / `extras.livepatch_active` field
contract is unchanged; only the *values* the detector produces become
correct on KernelCare hosts.

## v1.7.1 — Kernel livepatch awareness (KernelCare / kpatch / Ksplice) (2026-05-07)

Defensive-correctness fix on top of v1.7.0. The v1.6.0 `kernel_copy_fail`
check assumed kernel patches always come via "upgrade kernel + reboot"
and compared `uname -r` against a per-distro patched-RPM baseline. This
false-alarms CRITICAL on every host running KernelCare or kpatch — the
kernel image string still reports the OLD pre-livepatch version even
when CVEs are patched at runtime. The check now correctly understands
that scenario, plus we surface the livepatch posture as its own check
since not every operator runs one.

### Profile detection

`modules/host_profile.py` gains `_detect_livepatch()` which probes for:
  * **KernelCare** — `kcarectl` binary + `kcare` systemd unit
  * **kpatch** — `kpatch` binary + `kpatch` systemd unit (RHEL/Alma free)
  * **Ksplice** — `uptrack-uname` binary + `uptrack` unit (Oracle Linux)

Detection result lands in `extras.livepatch_provider` (one of
`kernelcare`/`kpatch`/`ksplice`/`none`) and `extras.livepatch_active`
(bool — provider's systemd unit reports active). KernelCare wins on
hosts with multiple installed (the CL stack convention).

### `check_kernel_copy_fail` — livepatch-aware severity ladder

New cascade when the kernel uname is below the patched baseline:

  1. **Livepatch service active** → LOW. Trust the running livepatch
     subscription to have applied the CVE patch at runtime; surface
     the provider's verify command (`kcarectl --patch-info`,
     `kpatch list`, `uptrack-show`) so the operator can spot-check
     CVE-specific coverage.
  2. **GRUB initcall mitigation** → MEDIUM (unchanged from v1.6).
  3. **Neither** → CRITICAL (unchanged).

Patched-by-version is still PASS regardless of livepatch state. The
PASS detail mentions both belt-and-braces signals (GRUB mitigation
and active livepatch) when present.

### New `livepatch_state` check

Standalone visibility check, applies to all Linux:
  * **Provider installed AND active** → PASS
  * **Provider installed BUT service inactive** → MEDIUM. The dangerous
    state — operator may believe kernel patches are being applied when
    they're not. Detail points at `systemctl status` and the CLI tool.
  * **No provider detected** → PASS-with-note. Doesn't penalize
    third-party operators on the public GitHub repo who don't run a
    paid livepatch subscription; just surfaces the choice and lists
    options (KernelCare paid, kpatch free on RHEL/Alma 8+).

### `ALL_CHECKS` count: 21 → 22

### Files added

- `posture_checks/check_livepatch_state.py`

### Files modified

- `modules/host_profile.py` — `_detect_livepatch()` + extras additions
- `posture_checks/check_copy_fail.py` — livepatch-aware severity cascade
- `posture_checks/__init__.py` — register `LivepatchStateCheck`
- `VERSION` — 1.7.0 → 1.7.1
- `CHANGELOG.md`, `README.md`, `CLAUDE.md`

### Why this is 1.7.1 not 1.7.0

v1.7.0 had already shipped (in our local repo); rather than amend-and-
force-push a still-young commit, the livepatch correctness landed as a
patch release on top.

### Backwards compat

- New extras fields default safely (`'none'`/`False`) on existing
  profiles. Profile re-detection on next posture run picks them up.
- No schema or config changes.
- Hosts WITHOUT KernelCare see no behavior change in
  `check_kernel_copy_fail` — the existing severity cascade still applies.
- Hosts WITH KernelCare go from false-CRITICAL to LOW with a
  helpful detail. Bootstrap dampening keeps the upgrade quiet on
  Telegram.

## v1.7.0 — Layered defense Sprint 1: generic CVE feed + SELinux + ModSec mode (2026-05-07)

First batch of task #123 — the post-#122 defensive layering aimed at
the AI-accelerated CVE disclosure rate. Hand-curated per-CVE checks
(`pwnkit`, `kernel_copy_fail`) don't scale to that pace; this release
replaces the long tail with one generic check that consults the distro
security team's curated errata feed, and adds two visibility checks
for defense-in-depth measures that are commonly disabled on shared-
hosting boxes.

### New posture checks

- **`security_updates`** — generic "pending security errata?" check.
  Consults the distro security team's curated feed:
    * RHEL/CL/Alma/Rocky/CentOS/Fedora/OL 8+: `dnf updateinfo list security`
    * RHEL/CL 7: `yum --security check-update`
    * Debian/Ubuntu/Mint: `apt list --upgradable` filtered for *-security suite
  Severity ladder (worst-of pending):
    * 0 pending → PASS
    * any Moderate/Low/unclassified → LOW
    * any Important → MEDIUM
    * any Critical → HIGH
    * Critical AND kernel package → CRITICAL
  Stored value is bucket-only so day-to-day errata count drift doesn't
  fire transitions; only severity-class crossings (or kernel-critical
  appearing) do. The named-CVE checks (`pwnkit`, `kernel_copy_fail`)
  stay as overrides for high-priority bugs where distro tagging is
  too quiet or the alert needs to fire before the errata shows up.
- **`selinux`** — runtime state via `getenforce`. Reports Enforcing
  (PASS), Permissive (LOW), Disabled-on-single-site (PASS-with-note),
  Disabled-on-multi-tenant (MEDIUM). Pure visibility; no remediation —
  re-enabling SELinux on a long-running multi-tenant box requires a
  labeling pass and is its own operational project. Applies: EL family.
- **`modsec_mode`** — companion to existing `modsec_volume` (which
  measures audit log size health). This check looks at the
  `SecRuleEngine` directive: On (PASS), DetectionOnly (LOW — common
  transitional state during rule rollout, but reported so the operator
  doesn't forget to promote to On), Off (MEDIUM — module loaded but
  not doing its primary job). Applies: has_modsec.

### `ALL_CHECKS` count: 18 → 21

### Files added

- `posture_checks/check_security_updates.py`
- `posture_checks/check_selinux.py`
- `posture_checks/check_modsec_mode.py`

### Files modified

- `posture_checks/__init__.py` — register new checks
- `VERSION` — 1.6.2 → 1.7.0
- `README.md` — features list + file tree
- `CLAUDE.md` — applicability matrix + v1.7 section

### Why these three together

All three address the same gap: **defense layers that are commonly
absent or degraded on shared hosting**, where the operator needs the
state surfaced rather than auto-remediated. They share the `applies_to`
gating pattern, ship as drop-in posture checks with no new config, and
match the visibility-first philosophy of the v1.5/1.6 modules.

### Backwards compat

No config or schema changes. `git pull && update.sh` on an existing
v1.6.x host enables the three new checks on the next posture-audit
run. Bootstrap dampening continues to apply on the first run, so the
upgrade doesn't flood Telegram even on hosts where the new checks
land in MEDIUM/HIGH state immediately (the typical case for SELinux
Disabled and ModSec DetectionOnly across the maiahost fleet).

### Still pending from #123

Coming in subsequent sprints:
- Sprint 2: operational runbooks (`dnf-automatic` rollout, KernelCare
  audit) + SECURITY.md
- Sprint 3: outbound SMTP volume detector (complement to
  `DistributedAuthDetector`)
- Deferred: vuls/trivy integration, AIDE/FIM, postfwd outbound rate
  limits — separate followup tasks once Sprints 1–3 land

## v1.6.2 — tmp_cleanup digest fix: dry_run always sends (2026-05-07)

Same-day patch on top of v1.6.1. The empty-suppression rule in
`_send_digest` was originally a "don't spam the Telegram channel on
quiet days" heuristic, but it accidentally suppressed the entire
*evaluation* phase: an operator who enables `dry_run` to evaluate the
module never sees a single Telegram message if their /tmp happens to
be clean — leaving them unable to tell whether the module is even
running.

### Behavior change

- **`mode = dry_run`**: digest is now sent on EVERY scheduled run,
  including empty ones. Daily ping confirms the module is alive,
  reports the candidate count (zero or otherwise), and ships the
  `Largest /tmp entries` top-N visibility view (which is the most
  useful part of the message anyway, since it surfaces bloat that's
  not even cleanable — like `/tmp/lshttpd/swap`).
- **`mode = live`**: unchanged. Empty runs still suppressed; you only
  hear from the module when something was actually cleaned or errored.
- The digest body now distinguishes "Cleaned:" vs "Would clean:" based
  on mode, and adds a clear "/tmp clean — no entries match cleanup
  criteria" line when a dry_run finds nothing, plus a one-liner
  reminder of what the criteria are.

### Files modified

- `modules/tmp_cleanup.py` — `_send_digest` policy + body refinements
- `VERSION` — 1.6.1 → 1.6.2

### Backwards compat

No config or schema changes. Live-mode users see no difference.
Dry_run-mode users see one extra Telegram message per day on hosts
where /tmp is clean — that's the entire point of the patch.

## v1.6.1 — tmp_cleanup module redesign after operational sweep (2026-05-07)

Same-day patch release after the Phase 6 operational sweep on
srv.dotcom.services revealed the v1.6.0 module would have caught
roughly none of the actual /tmp bloat on a real production host. The
operator-dropped artifacts were directories (claude-*, *-fresh,
restore-*, new-vhosts, node-compile-cache) plus mode-0750 timestamped
backup files — both excluded by v1.6.0's files-only and world-readable
gates. v1.6.1 fixes this without compromising the safety story.

### Module behavior changes (`modules/tmp_cleanup.py`)

- **Directory cleanup support.** Top-level `/tmp/<dir>` entries that
  match the allowlist now qualify, subject to a recursive validator
  that walks every contained file and rejects the whole tree if ANY
  file is non-root, ANY symlink targets outside /tmp, ANY subdir is a
  mountpoint, or the lsof check shows anything open. Single failure
  short-circuits — no partial deletes inside a candidate dir.
- **Hardcoded SYSTEM excludelist** that ALWAYS denies, with higher
  precedence than the allowlist. Initial entries protect: `lshttpd*`
  (OLS runtime — we observed 886 MB of `/tmp/lshttpd/swap` on srv;
  delete that and you take the web server down), `systemd-private-*`
  and `snap-private-*` (PrivateTmp bind-mounts), `.X11-unix`,
  `.ICE-unix`, `.font-unix`, `.XIM-unix` (X11 sockets), `tmux-*`
  (tmux server dirs), `mysql.sock` / `mariadb.sock` / `.s.PGSQL.*`
  (DB unix sockets in /tmp), `.crontab.lock`, `cagefs.sock`. Operator
  can EXTEND via `[tmp_cleanup] additional_excludes` but cannot make
  the list shorter than the safe baseline.
- **Mountpoint check** — `os.path.ismount()` per top-level entry, plus
  refusal to descend into subdir mountpoints during recursive validation.
  Defends against any tmpfs-mounted subtree we don't own.
- **World-readable requirement dropped.** v1.6.0 required mode bit
  `o+r` as a heuristic for "this was meant to be temp scratch", but it
  excluded legitimate root-owned scratch like `*.bak.*` files at 0750
  and the operator's own 0700 dirs. The allowlist + uid-0 + age + lsof
  remain as the gate; the mode bit added safety theatre, not safety.
- **Default allowlist expanded** to match what we actually saw in the
  field: `*.bak.*`, `*.backup.*`, `*-fresh`, `restore-*`, `staging-*`,
  `new-vhosts`, `node-compile-cache`, `python-compile-cache`,
  `pip-*-build` / `pip-tmp-*` / `pip-build-*`, `pymp-*` (Python
  multiprocessing leftover shared-mem dirs), `last_resp.json`,
  `build-manual-*.log`. Existing patterns retained.
- **Top-N-by-size reporting.** Every digest now includes a "Largest
  /tmp entries" section listing the 10 biggest top-level entries
  regardless of allowlist/age/owner. Pure visibility — surfaces the
  bloat the module is *correctly not touching* (active runtime dirs)
  so the operator sees the full picture, not just what got cleaned.

### New config options ([tmp_cleanup])

- `include_directories = true` (default) — set false to revert to
  v1.6.0 files-only behavior on more conservative hosts.
- `additional_excludes =` — comma-separated glob patterns; ADDED to
  the hardcoded SYSTEM excludelist, cannot remove from it.

### Files modified

- `modules/tmp_cleanup.py` — substantial rewrite; same public API
  (`run_now()`, `run_if_due()`, `status_summary()`)
- `wp-guardian.conf.example` — expanded `[tmp_cleanup]` section
- `wp-guardian.conf` — matching changes
- `VERSION` — 1.6.0 → 1.6.1

### Backwards compat

- Existing operators who already customized `allowlist_patterns` keep
  exactly their list — the broader defaults only ship to operators who
  haven't overridden it.
- `mode = off` default unchanged.
- Existing config files without `include_directories` or
  `additional_excludes` get safe defaults (true / empty respectively).
- The orchestrator wiring in `wp-guardian.py` is unchanged — same
  `Guardian.tmp_cleanup` attribute, same `run_if_due()` call site.

### What v1.6.1 would have done on srv.dotcom.services

Comparing against the actual operational sweep (Group A: 8 paths;
Group B: 11 pymp-* dirs):
- Group A: `claude-0/`, `*-fresh/` extract dirs, `restore-staging/`,
  `new-vhosts/`, `node-compile-cache/` would all match the new
  allowlist AND pass dir validation → would be cleaned automatically
  in `live` mode.
- Group B: `pymp-*` dirs match the new `pymp-*` allowlist pattern,
  pass validation (empty or 0-byte content, all uid 0) → cleaned
  automatically.
- `/tmp/httpd_config.conf.bak.1777281372` (mode 0750, root) — matches
  the new `*.bak.*` allowlist, no longer excluded by world-readable
  requirement → cleaned.
- `/tmp/lshttpd/`, `/tmp/.X11-unix`, `/tmp/tmux-0` — explicitly
  protected by SYSTEM excludelist; never touched.

So the same outcome as our manual sweep, but as a recurring scheduled
task — which is the entire point of the module.

## v1.6.0 — Posture-audit Phases 2–5 + active /tmp cleanup (2026-05-07)

Closes the bulk of task #122. The v1.5.0 update shipped the posture
foundation plus 4 reference checks; v1.6.0 fills out Phases 2–4 of the
plan (13 new checks) and adds the active /tmp cleanup module from
Part D.

### New posture checks (Phase 2 — generic Linux)

- `tmp_hygiene` (LOW, read-only) — count root-owned, world-readable
  entries in /tmp older than 7 days. Flags > 5 with a sample list.
  Stores a coarse over/under-threshold bool so day-to-day count wiggle
  doesn't trip transitions; only the threshold crossing fires an event.
  Companion to the active `tmp_cleanup` module — useful even on hosts
  where active cleanup stays disabled.
- `sshd_config` (MEDIUM, LOW behind perimeter, HIGH on PermitEmptyPasswords)
  — reads the effective sshd config via `sshd -T`. Reports
  PermitRootLogin / PasswordAuthentication / PermitEmptyPasswords /
  PubkeyAuthentication / Port / ListenAddress. Acceptable PermitRootLogin
  = no | prohibit-password | forced-commands-only AND
  PasswordAuthentication = no.
- `listening_ports` (MEDIUM, LOW behind perimeter) — `ss -lntup`
  inventory of TCP/UDP listeners. Stored value is the deterministic
  set of (proto, addr, port) tuples so transitions fire only when
  the listener set CHANGES (process restarts that keep bindings don't).
- `suid_baseline` (HIGH on additions, MEDIUM otherwise) — self-baselining
  SUID/SGID drift detector for /usr/{bin,sbin,libexec}, /bin, /sbin,
  /usr/local/{bin,sbin}. First run captures baseline silently; later
  runs flag added or modified entries. /usr/libexec is recursed one
  level deep (sudo/sesh, openssh/ssh-keysign).

### New posture checks (Phase 3 — multi-tenant + CL)

- `tenant_home_perms` (HIGH, multi-tenant only) — every /home/<tenant>/
  is 0711 with tenant ownership. Stored bad-paths list so transitions
  fire when the misconfigured set changes.
- `public_html_perms` (HIGH, multi-tenant only) — every public_html is
  0750, owner = tenant uid (verified via pwd lookup), group ∈
  {apache, www-data, httpd, nobody, nogroup, lsws} OR equals the
  tenant's own group name (OLS extprocessor case).
- `cagefs_state` (HIGH, CL only; LOW on lvestats-only outage) — kmodlve
  loaded, /proc/lve/list present, `cagefsctl --status` enabled,
  lvestats / cagefs-stats service active.
- `mod_hostinglimits` (HIGH on missing-runtime, MEDIUM on
  loaded-but-not-on-disk; CL+Apache+multi-tenant only) — Apache
  module loaded at runtime AND has a LoadModule directive on disk.
- `apache_vhost_uid` (HIGH; Apache+multi-tenant only) — every vhost with
  a tenant DocumentRoot has AssignUserID OR SuexecUserGroup OR
  User+Group in the block. Catches "ghost vhosts" that would silently
  serve PHP as the system apache uid. Source files enumerated via
  `httpd -S`.

### New host-health checks (Phase 4)

- `disk_usage` (HIGH ≥85%, MEDIUM ≥75%) — partition list driven by
  profile (/, /home, /var, plus /var/log when web_server is set, plus
  /var/lib/mysql when db_server is set). Same-st_dev partitions deduped.
  Bucketed stored value so daily wiggle doesn't trip transitions.
- `mta_queue_depth` (HIGH ≥1000, MEDIUM ≥100; postfix only) —
  `postqueue -p` summary parse. Bucket-stored.
- `worker_saturation` (HIGH ≥90%, MEDIUM ≥70%; Apache only — OLS
  reports as soft WARN-LOW pending implementation) — fetches
  `http://127.0.0.1/server-status?auto`, derives MaxRequestWorkers from
  Scoreboard length. Single-sample for now.
- `db_health` (HIGH any-bad, MEDIUM any-medium; mariadb/mysql only) —
  connection saturation, slow-query rate (cumulative), InnoDB buffer
  pool hit rate. Auth probe order: `/root/.my.cnf`,
  `/etc/mysql/debian.cnf`, then unix_socket.
- `modsec_volume` (HIGH ≥500MB, MEDIUM ≥100MB; has_modsec only) —
  audit log size as proxy for rotation health. Standard locations
  scanned across Apache, Apache/Debian, OLS layouts.

### Active /tmp cleanup module (`modules/tmp_cleanup.py`)

Companion *actor* to the read-only `tmp_hygiene` posture check. Daily
janitor that removes root-owned, world-readable, allowlisted, stale
files from /tmp. **Default mode = off** — opt-in only; free single-site
operators may not want guardian touching /tmp at all.

Modes:
- `off` — disabled.
- `dry_run` — scan, log, send Telegram digest. No deletes.
- `live` — scan + lsof + delete; each deletion logged to
  `posture_events` (check_id=`tmp_cleanup`) for forensics.

Strict deletion criteria — ALL must match:
- path strictly under /tmp/ (realpath check, no symlink escape)
- owner uid 0
- world-readable (mode bit 0o004)
- mtime older than `age_days` (default 7)
- basename matches an allowlist glob pattern
- file is NOT held open (lsof per-candidate; soft-fails to "treat as
  open" on lsof error so we never delete a file we couldn't verify)

Operators are expected to leave each new host in `dry_run` for ~14
days, review the digests, then promote to `live` by editing the
config. The module deliberately does NOT auto-promote — that human
review step is the whole point of the staged rollout.

### CLI

- `--tmp-cleanup-status` — print mode, allowlist, last-run summary
- `--tmp-cleanup-run` — run one cleanup pass now (respects configured
  mode; refuses if mode=off)

### Config

- New `[tmp_cleanup]` section: `mode`, `age_days`, `interval_seconds`,
  `allowlist_patterns`.

### Files added

- `posture_checks/check_tmp_hygiene.py`
- `posture_checks/check_sshd_config.py`
- `posture_checks/check_listening_ports.py`
- `posture_checks/check_suid_baseline.py`
- `posture_checks/check_tenant_home_perms.py`
- `posture_checks/check_public_html_perms.py`
- `posture_checks/check_cagefs_state.py`
- `posture_checks/check_mod_hostinglimits.py`
- `posture_checks/check_apache_vhost_uid.py`
- `posture_checks/check_disk_usage.py`
- `posture_checks/check_mta_queue.py`
- `posture_checks/check_worker_saturation.py`
- `posture_checks/check_db_health.py`
- `posture_checks/check_modsec_volume.py`
- `modules/tmp_cleanup.py`

### Files modified

- `posture_checks/__init__.py` — `ALL_CHECKS` grew from 4 to 18 entries
- `wp-guardian.py` — TmpCleanup wired into Guardian + main loop;
  `--tmp-cleanup-status` / `--tmp-cleanup-run` CLI flags
- `wp-guardian.conf.example` — new `[tmp_cleanup]` section
- `VERSION` — 1.5.0 → 1.6.0
- `install.sh` — interactive prompt for `[tmp_cleanup] mode` on install

### Still pending from #122

- Phase 6 — operational /tmp sweep on srv.dotcom.services (operator
  task; expected workflow is to deploy v1.6.0 with `mode = dry_run`,
  review the daily digest for ~14 days, then promote to `live`).
- Cross-tenant read smoke test (active fork+setuid verification on
  public_html). Out of scope for this release; the perms+ownership
  check is functionally equivalent absent ACLs and is much simpler
  to keep correct.
- Disk-usage growth-rate tracking (+10%/week alert) — needs a
  separate historical-sample table; deferred.
- DB slow-query DELTA rate (vs cumulative). Same reason as above.

## v1.5.0 — Multi-CMS scaffolding & POST-flood detector (2026-05-03)

> **Updated 2026-05-06 (task #122)**: posture-audit + host-health module
> foundation added. Foundation + three checks (PwnKit, /proc hidepid,
> SMART drive health with growth detection). Additional checks land
> incrementally in subsequent v1.5 updates: SUID drift, sshd config,
> listening ports, tenant home perms, mod_hostinglimits / mod_lsapi UID
> switching, CageFS state, disk usage, worker saturation, DB health,
> modsec volume, MTA queue, and active /tmp cleanup with dry-run rollout.

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
  `run(profile, previous=None) -> CheckResult`. Checks may override
  severity per result via `severity_override`. The `previous` arg
  carries the prior run's stored state to checks that need delta
  detection across runs (SMART growth, etc.) — most checks ignore it.
- `posture_checks/__init__.py` registers checks in `ALL_CHECKS` — adding
  a new check is a one-line registry edit.

### Checks

- `kernel_copy_fail` (CRITICAL) — Linux kernel patched against
  CVE-2026-31431 ("Copy Fail") — local privilege escalation in the
  algif_aead crypto userspace API. Patched-kernel baselines for CL/RHEL/
  AlmaLinux/Rocky 9 + 10 and CL 8 (CL 7 not affected). Reads `uname -r`,
  strips arch suffix, compares against vendor-published patched RPM
  strings (e.g. `5.14.0-611.49.2.el9_7` for EL9). Also probes
  `/proc/cmdline` for the GRUB mitigation
  `initcall_blacklist=algif_aead_init` — if mitigation is active on a
  vulnerable kernel, severity drops from CRITICAL to MEDIUM (operator
  encouraged to patch before next reboot anyway). Detail string includes
  exact remediation commands (`dnf upgrade kernel && reboot` or
  `grubby --update-kernel=ALL --args="initcall_blacklist=algif_aead_init"`).
- `pwnkit` (CRITICAL) — polkit/pkexec patched against CVE-2021-4034.
  Per-distro patched-version table for RHEL/AlmaLinux/Rocky/CloudLinux
  8 + 9 + 10 and Debian/Ubuntu 11/12 + 20.04/22.04/24.04. EL10 baseline
  uses the post-rewrite single-integer polkit versioning (121+).
  Pure-Python RPM/Debian-style version comparator (no rpmdevtools
  dependency). Falls back to WARN+LOW on unrecognized distros so we
  never raise a false CRITICAL.
- `proc_hidepid` (MEDIUM, escalates HIGH on multi-tenant) — `/proc`
  mounted with `hidepid=invisible`. Reads `/proc/mounts` directly.
  Reports PASS-with-note on single-site hosts since there's nobody to
  hide from.
- `smart` (host-health module) — per-drive SMART health with growth
  detection. Discovers physical drives via `lsblk`, queries each via
  `smartctl -a -j` (JSON), tracks reallocated/pending/uncorrectable/
  command-timeout counters across runs and alerts on ANY new bad
  sectors. Endurance ladder: ≥70% used → MEDIUM, ≥85% → HIGH, ≥95% →
  CRITICAL. SMART-overall-FAILED → CRITICAL "replace immediately".
  Skips on virtualized hosts (SMART through virtio is rarely meaningful)
  and on hosts without smartmontools installed. Stored value omits
  endurance % so daily creep doesn't generate transitions; severity
  changes still do.

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

### install.sh — input validation + Telegram-wizard UX fix

**UX fix.** The "Run Telegram setup wizard now?" prompt used to be asked
upfront in `gather_config`, but the wizard didn't actually run until the
end of the install — after a dozen more questions (commands, alert mode,
GeoIP, compromise detection, mail backend, profile, POST-flood). From
the operator's perspective those questions looked "injected" into the
Telegram step. The wizard prompt is now asked **right before the wizard
runs**, only if `bot_token` or `chat_id` are still empty after upfront
collection. No more interleaving.

**Input validation.** All install prompts that previously accepted any
string now validate format and retry on bad input. New helpers:

- `ask_int <prompt> <default> [<min>] [<max>]` — integer with optional bounds
- `ask_port <prompt> <default>` — `ask_int` clamped to 1–65535
- `ask_choice <prompt> <default> <v1> <v2> …` — must match one of the values
- `ask_ip <prompt> <default> <allow_empty> <allow_hostname>` — IPv4
  octet-range checked, optional hostname acceptance
- `ask_path <prompt> <default> <must_exist>` — optional file-existence check
- `ask_telegram_token <prompt> <default>` — `^\d+:[\w-]+$` format check
- `ask_telegram_chat_id <prompt> <default>` — numeric (incl. negative
  group/channel IDs) or `@username` (4+ chars)

Wired into: firewall backend choice, MikroTik host/port/key path,
key-choice menu, pfSense platform/host/port, Telegram alert-mode menu,
mail-recipe choice, mail-backend host/port, profile-mode choice. Bad
input prints a one-line warning to stderr and re-prompts; the captured
stdout (read by `var=$(ask_*)`) only ever contains a valid value.

**Files changed:** `install.sh`.

### Telegram commands for remote troubleshooting

Five new commands so the operator can investigate v1.5 state from chat
without SSHing into the box:

- `/sites [cms]` — list detected vhosts with their CMS classification.
  Tally by CMS at the top, then up to 30 sites listed (sorted). Optional
  filter, e.g. `/sites joomla`. `*` next to a CMS name means the entry
  was set via `vhosts.conf` rather than auto-detected.
- `/site <name>` — full registry entry for one site: CMS, docroot,
  admin paths, override flag, detection timestamp.
- `/cmsrefresh` — force an immediate CMS-registry rebuild (vs waiting
  for the 6h periodic refresh). Useful right after provisioning a new
  vhost or editing `vhosts.conf`.
- `/logs` — list of log files being tailed by each tailer (web / mail /
  ssh / roundcube), inferred web-server type (OpenLiteSpeed / Apache /
  nginx based on path patterns), `logfiles_list` location, and whether
  `auto_discover` is on.
- `/serverinfo` — version, schema version, firewall backend class,
  profile mode, dry-run flag, plus a v1.5 feature-flag summary
  (CMS auto-detect, POST-flood, ssh_root threshold).

`TelegramCommander.__init__` gains `cms_registry`, `firewall`,
`post_flood_detector`, `version`, and `config` parameters. Tailers are
attached after start via a new `set_tailers(tailers)` setter, called
from `Guardian.start()` once tailers exist.

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
