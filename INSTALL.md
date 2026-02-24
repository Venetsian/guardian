# WP-Guardian Installation Guide

Complete step-by-step guide to installing and configuring WP-Guardian.

## Prerequisites

Before installing, make sure you have:

- **Linux server** (tested on AlmaLinux/CentOS/Rocky, should work on Ubuntu/Debian)
- **Python 3.6+** with `sqlite3` module (included with most distributions)
- **Root access** (the daemon monitors system logs)
- **A firewall** — CSF, firewalld, nftables, MikroTik router, or pfSense/OPNsense
- **WordPress sites** with access logs (OpenLiteSpeed, Apache, Nginx)

Optional:

- **Telegram account** for real-time alerts (highly recommended)
- **SSH key pair** if using MikroTik backend

## Quick Install

Clone directly to `/opt/wp-guardian` so that future updates work with `git pull`:

```bash
sudo git clone https://github.com/Venetsian/guardian.git /opt/wp-guardian
cd /opt/wp-guardian
sudo bash install.sh
```

The installer will walk you through configuration interactively. If you prefer manual setup, follow the detailed steps below.

---

## Detailed Installation

### Step 1: Clone the Repository

**Important:** Clone directly to `/opt/wp-guardian/` — this is the standard install path and enables easy updates via `git pull`.

```bash
sudo git clone https://github.com/Venetsian/guardian.git /opt/wp-guardian
cd /opt/wp-guardian
```

### Step 2: Run the Installer

```bash
sudo bash install.sh
```

The installer detects that it's running from `/opt/wp-guardian` and skips file copying (the files are already in place from `git clone`). It will:

1. Check Python version and dependencies
2. Create the directory structure (state, logs, etc.)
3. Ask which firewall backend to use
4. Offer to set up Telegram alerts
5. Create a whitelist with your server IPs
6. Discover access logs on your server
7. Install the systemd service

### Step 3: Choose Your Firewall Backend

WP-Guardian supports five firewall backends. Choose one during installation:

#### Option 1: CSF (ConfigServer Firewall)

Best for standalone servers that already have CSF installed.

- Blocks directly on the server via iptables
- Supports temporary blocks (tier 1 & 2) and permanent blocks (tier 3)
- Supports CIDR /24 subnet blocking
- No external hardware needed

**Note:** CSF reached end-of-life in August 2025. CyberPanel 2.4+ has switched to firewalld. If you're on a newer CyberPanel, use the firewalld backend instead.

```bash
# Check if CSF is installed
csf -v
```

#### Option 2: firewalld

Default on RHEL/AlmaLinux/CentOS and CyberPanel 2.4+. If your server runs CyberPanel, this is likely what you have.

- Uses `firewall-cmd` rich rules
- Supports temporary and permanent blocks
- Zone-configurable (default: `public`)

```bash
# Check if firewalld is running
systemctl status firewalld

# If not installed:
yum install firewalld
systemctl enable --now firewalld
```

#### Option 3: nftables (direct)

Modern Linux packet filtering without a frontend. Good for minimal setups.

- Creates a dedicated `wp_guardian` table with named sets
- Uses element timeouts for automatic expiry
- No additional software needed (nftables is built into modern kernels)

```bash
# Check if nft is available
nft --version
```

#### Option 4: MikroTik Router

Best for networks with a MikroTik router in front of the server. Blocks at the network edge before traffic reaches the server.

- Blocks via SSH commands to MikroTik RouterOS
- Uses address lists with automatic TTL expiry
- Requires SSH key-based authentication
- Supports CIDR /24 subnet blocking via separate address list

**MikroTik setup:**

1. Create a dedicated user on MikroTik:

   Open WinBox or the MikroTik CLI and run:

   ```
   /user add name=guardian group=full
   ```

2. Generate an SSH key pair on your server:

   ```bash
   ssh-keygen -t rsa -b 4096 -f /root/.ssh/mikrotik_guardian -N ""
   ```

3. Import the public key to MikroTik:

   Upload the public key file to MikroTik (via WinBox drag-and-drop or SCP), then:

   ```
   /user ssh-keys import public-key-file=mikrotik_guardian.pub user=guardian
   ```

4. Test the connection:

   ```bash
   ssh -i /root/.ssh/mikrotik_guardian -o Port=22 guardian@192.168.2.1 "/system identity print"
   ```

   You should see your router's identity name.

5. Create a "friendly" address list on MikroTik with IPs that should never be blocked:

   ```
   /ip firewall address-list add list=friendly address=YOUR_SERVER_IP comment="Web server"
   /ip firewall address-list add list=friendly address=YOUR_OFFICE_IP comment="Office"
   ```

#### Option 5: pfSense / OPNsense

For networks with a pfSense or OPNsense firewall appliance. Blocks at the network edge via REST API.

- Auto-detects pfSense vs OPNsense
- Uses firewall aliases for blocking
- Requires API key and secret
- You must create the block aliases and a firewall rule manually on the appliance before use

**Setup:**

1. Enable the REST API on your pfSense/OPNsense appliance
2. Create an API key and secret
3. Create two firewall aliases (e.g., `wp_guardian_blocked` and `wp_guardian_cidr`)
4. Create a block rule that drops traffic from those aliases

The installer will prompt for the API connection details.

---

## Step 4: Set Up Telegram Alerts (Recommended)

Telegram alerts let you know about blocked IPs, daily summaries, and system issues in real-time.

### 4.1: Create a Telegram Bot

1. Open Telegram on your phone or desktop
2. Search for **@BotFather** (the official bot for creating bots)
3. Send `/newbot`
4. Choose a **name** for your bot (e.g., "My Server Guardian")
5. Choose a **username** (must end in "bot", e.g., "myserver_guardian_bot")
6. BotFather will reply with your **bot token** — it looks like: `123456789:ABCdefGHIjklMNOpqrSTUvwxYZ`
7. **Save this token** — you'll need it in the next step

### 4.2: Find Your Chat ID

WP-Guardian includes a setup wizard that does this for you:

```bash
python3 /opt/wp-guardian/wp-guardian.py --telegram-setup
```

The wizard will:

1. Ask for your bot token
2. Validate it with Telegram
3. Ask you to send a message to your bot
4. Automatically detect your chat_id
5. Offer to save everything to the config file

**Manual alternative:** If the wizard doesn't work, you can find your chat_id by:

1. Send any message to your bot in Telegram
2. Open this URL in your browser (replace TOKEN with your bot token):

   `https://api.telegram.org/botTOKEN/getUpdates`

3. Look for `"chat":{"id":123456789}` in the JSON response
4. That number is your chat_id

### 4.3: Test Telegram

```bash
python3 /opt/wp-guardian/wp-guardian.py --telegram-test
```

You should receive a test message in Telegram.

---

## Step 5: Discover Your Logs

WP-Guardian needs to know which access log files to monitor.

```bash
# Find all access logs on the server
python3 /opt/wp-guardian/wp-guardian.py --discover-logs

# Find and save them to logfiles.txt
python3 /opt/wp-guardian/wp-guardian.py --discover-logs-save
```

The command searches common locations:

- `/home/*/logs/*.access_log` (CyberPanel, cPanel, DirectAdmin)
- `/var/log/httpd/*access*` (Apache on RHEL/CentOS)
- `/var/log/apache2/*access*` (Apache on Debian/Ubuntu)
- `/var/log/nginx/*access*` (Nginx)
- `/usr/local/lsws/logs/*access*` (LiteSpeed)

---

## Step 6: Generate Tripwires

Tripwires are PHP paths that bots commonly probe. WP-Guardian can discover these from your existing logs:

```bash
# Analyze logs and add tripwires (keeps existing ones)
python3 /opt/wp-guardian/wp-guardian.py --auto-analyze
```

Or run the log analyzer manually:

```bash
bash /opt/wp-guardian/tools/log-analyzer.sh -o /tmp/tripwires.txt
python3 /opt/wp-guardian/wp-guardian.py --import-tripwires-incremental /tmp/tripwires.txt
```

---

## Step 7: Test with Dry-Run

Before going live, run in dry-run mode to see what would be blocked:

```bash
python3 /opt/wp-guardian/wp-guardian.py --dry-run
```

This logs all detection events but doesn't actually block anything. Check the output and `logs/guardian.log` to make sure legitimate traffic isn't being caught.

---

## Step 8: Go Live

```bash
# Enable and start the service
systemctl enable wp-guardian
systemctl start wp-guardian

# Check status
systemctl status wp-guardian

# View live logs
journalctl -u wp-guardian -f

# Check WP-Guardian status
python3 /opt/wp-guardian/wp-guardian.py --status
```

---

## Updating

Since WP-Guardian is installed via `git clone` to `/opt/wp-guardian`, updates are simple:

```bash
cd /opt/wp-guardian
git pull
sudo bash update.sh
```

The update script will:

1. Create a timestamped backup (code + database)
2. Stop the service if running
3. Skip file copy (files are already updated by `git pull`)
4. Run any pending database migrations
5. Verify the installation
6. Restart the service

### Rollback

If something goes wrong after an update:

```bash
sudo bash /opt/wp-guardian/update.sh --rollback
```

This restores both code files and the database from the latest backup.

### Check Versions

```bash
# Show current and backup versions
bash /opt/wp-guardian/update.sh --status

# Show app version
python3 /opt/wp-guardian/wp-guardian.py --version

# Show database schema version
python3 /opt/wp-guardian/wp-guardian.py --db-version
```

---

## Configuration Reference

The config file is at `/opt/wp-guardian/wp-guardian.conf`. Key sections:

| Section | What It Controls |
|---------|-----------------|
| `[general]` | Dry-run mode, log level, logfiles path |
| `[thresholds]` | Detection sensitivity for all modules |
| `[escalation]` | Tier durations (24h, 30d, permanent) |
| `[cidr]` | Subnet /24 auto-aggregation |
| `[firewall]` | Which backend to use |
| `[mikrotik]` | MikroTik SSH connection details |
| `[csf]` | CSF-specific settings |
| `[firewalld]` | firewalld zone configuration |
| `[nftables]` | nftables priority settings |
| `[pfsense]` | pfSense/OPNsense API connection |
| `[telegram]` | Bot token, chat ID, rate limits |
| `[whitelist]` | Path to whitelist file |
| `[auth_tracking]` | WordPress login trust duration |
| `[log_analysis]` | Automated analysis schedule |
| `[database]` | DB path and retention periods |

See `wp-guardian.conf.example` for all options with descriptions.

---

## CLI Reference

```bash
# Daemon
python3 wp-guardian.py                     # Run live
python3 wp-guardian.py --dry-run           # Watch only
systemctl start|stop|restart wp-guardian   # Service control

# Version & Status
python3 wp-guardian.py --version           # App version
python3 wp-guardian.py --db-version        # Schema version
python3 wp-guardian.py --status            # Current stats
python3 wp-guardian.py --history IP        # IP block history
python3 wp-guardian.py --test-backend      # Test firewall connectivity

# Whitelist
python3 wp-guardian.py --whitelist-list    # Show all
python3 wp-guardian.py --whitelist-add IP  # Add IP
python3 wp-guardian.py --whitelist-remove IP

# Tripwires
python3 wp-guardian.py --auto-analyze                      # Discover + import
python3 wp-guardian.py --import-tripwires FILE             # Full import
python3 wp-guardian.py --import-tripwires-incremental FILE # Add new only
python3 wp-guardian.py --flush tripwires                   # Clear all tripwires

# Log Discovery
python3 wp-guardian.py --discover-logs        # Find logs
python3 wp-guardian.py --discover-logs-save   # Find and save

# Telegram
python3 wp-guardian.py --telegram-setup    # Interactive setup
python3 wp-guardian.py --telegram-test     # Send test message

# Manual Unblock
python3 wp-guardian.py --unblock IP

# Database
python3 wp-guardian.py --migrate           # Run pending migrations

# Update
cd /opt/wp-guardian && git pull && sudo bash update.sh
sudo bash update.sh --rollback             # Rollback last update
bash update.sh --status                    # Show versions
```

---

## Troubleshooting

**"Firewall backend failed to initialize"**

- CSF: Make sure `csf` command is available (`which csf`). Install CSF if needed.
- firewalld: Check that it's running (`systemctl status firewalld`).
- nftables: Check that `nft` is available (`nft --version`).
- MikroTik: Test SSH manually: `ssh -i /root/.ssh/mikrotik_guardian guardian@192.168.2.1 "/system identity print"`
- pfSense/OPNsense: Verify API connectivity and credentials.

**"No access logs found"**

- Check that your web server writes access logs to `/home/*/logs/`
- Add log paths manually to `logfiles.txt` (one path per line)

**"Telegram send failed"**

- Run `--telegram-setup` to verify token and chat_id
- Check that `requests` Python module is installed: `pip3 install requests`
- Check internet connectivity from server

**Legitimate users getting blocked**

- Add their IPs to `whitelist.conf`
- Check if they're hitting wp-login.php repeatedly (login isolation rule)
- Increase thresholds in `[thresholds]` section
- Check `logs/blocked.log` for the exact reason

**High CPU usage**

- Check how many log files are being tailed (`wc -l logfiles.txt`)
- Reduce `log_level` from DEBUG to INFO
- The daemon should use minimal CPU under normal conditions

---

## Adding a New Firewall Backend

See `backends/README.md` for instructions on creating custom backends.
