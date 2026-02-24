# WP-Guardian Installation Guide

Complete step-by-step guide to installing and configuring WP-Guardian.

## Prerequisites

Before installing, make sure you have:

- **Linux server** (tested on AlmaLinux/CentOS/Rocky, should work on Ubuntu/Debian)
- **Python 3.6+** with `sqlite3` module (included with most distributions)
- **Root access** (the daemon monitors system logs)
- **A firewall** — either CSF (ConfigServer Firewall) or a MikroTik router
- **WordPress sites** with access logs (OpenLiteSpeed, Apache, Nginx)

Optional:

- **Telegram account** for real-time alerts (highly recommended)
- **SSH key pair** if using MikroTik backend

## Quick Install

```bash
git clone https://github.com/YOUR_USERNAME/wp-guardian.git
cd wp-guardian
sudo bash install.sh
```

The installer will walk you through configuration interactively. If you prefer manual setup, follow the detailed steps below.

---

## Detailed Installation

### Step 1: Download

```bash
cd /root
git clone https://github.com/YOUR_USERNAME/wp-guardian.git
cd wp-guardian
```

Or download and extract:

```bash
wget https://github.com/YOUR_USERNAME/wp-guardian/archive/main.tar.gz
tar xzf main.tar.gz
cd wp-guardian-main
```

### Step 2: Run the Installer

```bash
sudo bash install.sh
```

The installer will:

1. Check Python version and dependencies
2. Create `/opt/wp-guardian/` directory structure
3. Ask which firewall backend to use (CSF or MikroTik)
4. Offer to set up Telegram alerts
5. Create a whitelist with your server IPs
6. Discover access logs on your server
7. Install the systemd service

### Step 3: Choose Your Firewall Backend

WP-Guardian supports two firewall backends. Choose one:

#### Option A: CSF (ConfigServer Firewall)

Best for standalone servers that already have CSF installed.

- Blocks directly on the server via iptables
- Supports temporary blocks (tier 1 & 2) and permanent blocks (tier 3)
- Supports CIDR /24 subnet blocking
- No external hardware needed

**CSF must be installed first:**

```bash
# Check if CSF is installed
csf -v

# If not, install it (CentOS/AlmaLinux):
cd /usr/src
wget https://download.configserver.com/csf.tgz
tar xzf csf.tgz
cd csf
bash install.sh
```

#### Option B: MikroTik Router

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

This is the trickiest part. WP-Guardian includes a setup wizard that does this for you:

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

## Configuration Reference

The config file is at `/opt/wp-guardian/wp-guardian.conf`. Key sections:

| Section | What It Controls |
|---------|-----------------|
| `[general]` | Dry-run mode, log level, logfiles path |
| `[thresholds]` | Detection sensitivity for all modules |
| `[escalation]` | Tier durations (24h, 30d, permanent) |
| `[cidr]` | Subnet /24 auto-aggregation |
| `[firewall]` | Which backend: `csf` or `mikrotik` |
| `[mikrotik]` | MikroTik SSH connection details |
| `[csf]` | CSF-specific settings |
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

# Status & History
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
```

---

## Troubleshooting

**"Firewall backend failed to initialize"**

- CSF: Make sure `csf` command is available (`which csf`). Install CSF if needed.
- MikroTik: Test SSH manually: `ssh -i /root/.ssh/mikrotik_guardian guardian@192.168.2.1 "/system identity print"`

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

## Upgrading

```bash
cd /path/to/wp-guardian-source
git pull
sudo bash install.sh
# The installer preserves your existing config
systemctl restart wp-guardian
```

---

## Adding a New Firewall Backend

See `backends/README.md` for instructions on creating custom backends for other firewalls and routers (nftables, iptables, pfSense, etc.).
