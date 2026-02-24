# WP-Guardian

Real-time security monitoring and automated threat response for WordPress hosting servers.

WP-Guardian monitors web, SMTP, IMAP/POP3, and SSH logs, automatically blocks attackers via your firewall, and sends alerts via Telegram. It features a three-tier escalation system (24h, 30d, permanent) and automatic CIDR /24 subnet aggregation for coordinated attacks.

## Features

- **Multi-service monitoring** — web access logs, mail (Postfix + Dovecot), SSH
- **Pluggable firewall backends** — CSF, firewalld, nftables, MikroTik, pfSense/OPNsense
- **Smart detection pipeline** — structural tripwires, known webshells, login isolation (CSS-based bot detection), brute force thresholds, PHP scanning detection, author enumeration, 404 storms
- **Three-tier escalation** — 24h block, 30d block, permanent ban with automatic tier advancement
- **CIDR /24 aggregation** — auto-blocks entire subnets when coordinated scanning is detected
- **Authenticated user protection** — WordPress-logged-in users are never auto-blocked
- **Telegram alerts** — real-time notifications for every block, with daily summaries
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
python3 wp-guardian.py --auto-analyze                        # Auto-discover + import
python3 wp-guardian.py --import-tripwires-incremental FILE   # Add new only
python3 wp-guardian.py --flush tripwires                     # Clear all

# Logs
python3 wp-guardian.py --discover-logs           # Find access logs
python3 wp-guardian.py --discover-logs-save       # Find and save

# Telegram
python3 wp-guardian.py --telegram-setup          # Interactive setup wizard
python3 wp-guardian.py --telegram-test           # Send test message

# Unblock
python3 wp-guardian.py --unblock 1.2.3.4

# Update
cd /opt/wp-guardian && git pull && sudo bash update.sh
sudo bash update.sh --rollback                   # Rollback last update
bash update.sh --status                          # Show versions
```

## Detection Pipeline

Each web access log line goes through these checks in order (first match wins):

1. Strip OpenLiteSpeed outer quotes
2. Parse IP, method, path, status
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

## File Structure

```
/opt/wp-guardian/
├── wp-guardian.py          # Main daemon + CLI
├── wp-guardian.conf        # Configuration (chmod 600!)
├── VERSION                 # Application version
├── update.sh               # Update with backup/rollback
├── whitelist.conf          # Never-block IPs
├── tripwires.txt           # Attack paths from log analysis
├── logfiles.txt            # Monitored access log paths
├── modules/
│   ├── database.py         # SQLite data layer
│   ├── config.py           # Config loader
│   ├── whitelist.py        # Three-source whitelist manager
│   ├── blocker.py          # Block decision engine
│   └── migrator.py         # Database migration runner
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
│   └── telegram.py         # Telegram alerts
├── tools/
│   ├── telegram_setup.py   # Interactive Telegram setup
│   └── log-analyzer.sh     # Tripwire discovery
├── migrations/
│   └── *.sql               # Database migrations
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
