#!/bin/bash
###############################################################################
# WP-Guardian Installer
# Interactive installation with firewall, Telegram, and log configuration.
# Run as root: bash install.sh
###############################################################################

set -euo pipefail

INSTALL_DIR="/opt/wp-guardian"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Colors (if terminal supports them)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo -e "${BOLD}============================================${NC}"
    echo -e "${BOLD}  WP-Guardian Installer${NC}"
    echo -e "${BOLD}============================================${NC}"
    echo ""
}

print_step() {
    echo -e "${CYAN}[*]${NC} $1"
}

print_ok() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_err() {
    echo -e "${RED}[✗]${NC} $1"
}

install_conntrack_tools() {
    # conntrack arms [firewall] flush_conntrack: after blocking an IP, Guardian
    # runs `conntrack -D -s <ip>` so already-established (HTTP keep-alive)
    # connections are torn down instead of flooding until they close. Only the
    # firewalld/nftables backends use it. Safe to skip — Guardian no-ops and
    # warns at startup if it is missing.
    if command -v conntrack &>/dev/null; then
        print_ok "conntrack found (blocks will tear down live connections)"
        return
    fi
    print_warn "conntrack not found — blocks would only stop NEW connections;"
    print_warn "  an attacker on HTTP keep-alive keeps flooding until its connections close."
    local pkg="" cmd=""
    if command -v dnf &>/dev/null; then
        pkg="conntrack-tools"; cmd="dnf install -y conntrack-tools"
    elif command -v yum &>/dev/null; then
        pkg="conntrack-tools"; cmd="yum install -y conntrack-tools"
    elif command -v apt-get &>/dev/null; then
        pkg="conntrack"; cmd="apt-get install -y conntrack"
    fi
    if [[ -n "$cmd" ]] && ask_yn "  Install ${pkg} now?" "y"; then
        if eval "$cmd"; then
            print_ok "Installed ${pkg}"
        else
            print_warn "Install failed — run manually later: ${cmd}"
        fi
    elif [[ -n "$cmd" ]]; then
        print_warn "  Install later with: ${cmd}"
    else
        print_warn "  Install conntrack-tools (RHEL/AlmaLinux) or conntrack (Debian/Ubuntu) manually."
    fi
}

ask() {
    # $1 = prompt, $2 = default
    local prompt="$1"
    local default="${2:-}"
    if [[ -n "$default" ]]; then
        prompt="$prompt [$default]"
    fi
    read -r -p "$prompt: " answer
    echo "${answer:-$default}"
}

ensure_pip3() {
    # Make sure `pip3` is on PATH. On a minimal AlmaLinux/RHEL/CL install
    # python3 is present but python3-pip is a separate package — detect
    # and install via the system package manager. Returns 0 on success,
    # 1 if we couldn't find or install pip3.
    if command -v pip3 &>/dev/null; then
        return 0
    fi

    print_step "pip3 not found — installing python3-pip via system package manager..."

    local pkg_mgr=""
    if command -v dnf &>/dev/null; then pkg_mgr="dnf"
    elif command -v yum &>/dev/null; then pkg_mgr="yum"
    elif command -v apt-get &>/dev/null; then pkg_mgr="apt-get"
    elif command -v zypper &>/dev/null; then pkg_mgr="zypper"
    fi

    if [[ -z "$pkg_mgr" ]]; then
        print_err "No supported package manager found (dnf/yum/apt-get/zypper)."
        return 1
    fi

    case "$pkg_mgr" in
        dnf|yum)
            $pkg_mgr install -y python3-pip || return 1
            ;;
        apt-get)
            apt-get update >/dev/null 2>&1 || true
            apt-get install -y python3-pip || return 1
            ;;
        zypper)
            zypper --non-interactive install python3-pip || return 1
            ;;
    esac

    if command -v pip3 &>/dev/null; then
        print_ok "python3-pip installed via ${pkg_mgr}"
        return 0
    fi
    return 1
}

ask_yn() {
    # $1 = prompt, $2 = default (y or n)
    local prompt="$1"
    local default="${2:-n}"
    if [[ "$default" == "y" ]]; then
        prompt="$prompt [Y/n]"
    else
        prompt="$prompt [y/N]"
    fi
    read -r -p "$prompt: " answer
    answer="${answer:-$default}"
    [[ "$answer" =~ ^[Yy] ]]
}

# ---------------------------------------------------------------------------
# Input validators (v1.5+)
# All validators retry on bad input. They print warnings to STDERR so the
# captured stdout (echoed by `local v=$(ask_*)`) only contains the value.
# ---------------------------------------------------------------------------

_warn_retry() { echo -e "  ${YELLOW}[!]${NC} $1" >&2; }

ask_int() {
    # $1=prompt, $2=default, $3=min (optional), $4=max (optional)
    local prompt="$1" default="${2:-}" min="${3:-}" max="${4:-}"
    local answer
    while true; do
        answer=$(ask "$prompt" "$default")
        if [[ -z "$answer" ]]; then
            echo ""
            return
        fi
        if ! [[ "$answer" =~ ^[0-9]+$ ]]; then
            _warn_retry "Please enter a positive integer."
            continue
        fi
        if [[ -n "$min" ]] && (( answer < min )); then
            _warn_retry "Value must be at least $min."
            continue
        fi
        if [[ -n "$max" ]] && (( answer > max )); then
            _warn_retry "Value must be at most $max."
            continue
        fi
        echo "$answer"
        return
    done
}

ask_port() {
    # $1=prompt, $2=default — convenience for ask_int 1-65535
    ask_int "$1" "$2" 1 65535
}

ask_choice() {
    # $1=prompt, $2=default, $3+=valid values
    local prompt="$1" default="$2"
    shift 2
    local valid=("$@")
    local answer v
    while true; do
        answer=$(ask "$prompt" "$default")
        for v in "${valid[@]}"; do
            if [[ "$answer" == "$v" ]]; then
                echo "$answer"
                return
            fi
        done
        _warn_retry "Please choose one of: ${valid[*]}"
    done
}

ask_ip() {
    # $1=prompt, $2=default, $3=allow_empty (true|false), $4=allow_hostname (true|false)
    local prompt="$1" default="${2:-}"
    local allow_empty="${3:-false}" allow_host="${4:-true}"
    local ipv4_re='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    local hostname_re='^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$'
    local answer a b c d o ok
    while true; do
        answer=$(ask "$prompt" "$default")
        if [[ -z "$answer" ]]; then
            if [[ "$allow_empty" == "true" ]]; then
                echo ""
                return
            fi
            _warn_retry "This field is required."
            continue
        fi
        if [[ "$answer" =~ $ipv4_re ]]; then
            ok=true
            IFS='.' read -r a b c d <<< "$answer"
            for o in "$a" "$b" "$c" "$d"; do
                if (( o > 255 )); then ok=false; break; fi
            done
            if $ok; then echo "$answer"; return; fi
            _warn_retry "Each octet must be 0-255."
            continue
        fi
        if [[ "$allow_host" == "true" ]] && [[ "$answer" =~ $hostname_re ]]; then
            echo "$answer"
            return
        fi
        if [[ "$allow_host" == "true" ]]; then
            _warn_retry "Please enter a valid IPv4 address or hostname."
        else
            _warn_retry "Please enter a valid IPv4 address (e.g. 192.168.1.1)."
        fi
    done
}

ask_path() {
    # $1=prompt, $2=default, $3=must_exist (true|false)
    local prompt="$1" default="${2:-}" must_exist="${3:-false}"
    local answer
    while true; do
        answer=$(ask "$prompt" "$default")
        if [[ -z "$answer" ]]; then
            _warn_retry "Path is required."
            continue
        fi
        if [[ "$must_exist" == "true" ]] && [[ ! -f "$answer" ]]; then
            _warn_retry "File does not exist: $answer"
            if ask_yn "  Continue anyway?" "n"; then
                echo "$answer"
                return
            fi
            continue
        fi
        echo "$answer"
        return
    done
}

ask_telegram_token() {
    # Telegram bot tokens look like: <digits>:<base64-ish chars>
    # Empty input is allowed (caller can leave blank to use the wizard).
    local prompt="$1" default="${2:-}"
    local re='^[0-9]+:[A-Za-z0-9_-]+$'
    local answer
    while true; do
        answer=$(ask "$prompt" "$default")
        if [[ -z "$answer" ]]; then
            echo ""
            return
        fi
        if [[ "$answer" =~ $re ]]; then
            echo "$answer"
            return
        fi
        _warn_retry "Bot token format looks wrong. Expected like '123456789:ABCdef-_xyz'."
    done
}

ask_telegram_chat_id() {
    # Numeric (positive personal, negative group) or @username (5+ chars).
    # Empty input is allowed.
    local prompt="$1" default="${2:-}"
    local num_re='^-?[0-9]+$'
    local user_re='^@[A-Za-z0-9_]{4,}$'
    local answer
    while true; do
        answer=$(ask "$prompt" "$default")
        if [[ -z "$answer" ]]; then
            echo ""
            return
        fi
        if [[ "$answer" =~ $num_re ]] || [[ "$answer" =~ $user_re ]]; then
            echo "$answer"
            return
        fi
        _warn_retry "Chat ID must be numeric (e.g. 12345 or -100123) or @username."
    done
}

# ===========================================================================
# Pre-checks
# ===========================================================================
print_header

if [[ $EUID -ne 0 ]]; then
    print_err "Run as root: sudo bash install.sh"
    exit 1
fi

# Check Python
print_step "Checking Python..."
if ! command -v python3 &>/dev/null; then
    print_err "Python 3 not found. Please install Python 3.6+"
    exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
print_ok "Python ${PY_VERSION} found"

# Check sqlite3
if ! python3 -c "import sqlite3" 2>/dev/null; then
    print_err "Python sqlite3 module not available"
    exit 1
fi

# Install Python dependencies from requirements.txt.
#
# We always install ALL listed deps (requests + geoip2 + PyMySQL), not just
# `requests`, because operators often enable [geoip] or [mail_backend]
# during this same install wizard or shortly after — and discovering the
# Python module is missing on first daemon run produces silent feature
# failures (DistributedAuthDetector country/ASN rules never fire if
# geoip2 isn't installed; mailbox auto-disable can't fire without PyMySQL).
if [[ -f "${SCRIPT_DIR}/requirements.txt" ]]; then
    print_step "Installing Python dependencies from requirements.txt..."
    if ensure_pip3; then
        # Try with --break-system-packages first (needed on PEP 668-marked
        # installs, e.g. EL10, modern Debian/Ubuntu); fall back without it
        # for older pip versions that don't recognize the flag.
        if pip3 install -r "${SCRIPT_DIR}/requirements.txt" --break-system-packages 2>&1 \
                || pip3 install -r "${SCRIPT_DIR}/requirements.txt" 2>&1; then
            print_ok "Python dependencies installed"
        else
            print_err "pip install failed. Some features will not work:"
            print_err "  - Telegram alerts (requests)"
            print_err "  - GeoIP enrichment / compromise detection (geoip2)"
            print_err "  - Mailbox auto-disable (PyMySQL)"
            print_warn "Install manually after install.sh completes:"
            print_warn "  pip3 install -r ${SCRIPT_DIR}/requirements.txt --break-system-packages"
        fi
    else
        print_err "pip3 unavailable and could not be installed automatically."
        print_warn "Install python3-pip manually, then run:"
        print_warn "  pip3 install -r ${SCRIPT_DIR}/requirements.txt --break-system-packages"
    fi
else
    # No requirements.txt — fall back to the legacy requests-only check.
    if ! python3 -c "import requests" 2>/dev/null; then
        print_warn "Python 'requests' module not found (needed for Telegram)"
        if ask_yn "  Install it now?"; then
            if ensure_pip3; then
                pip3 install requests --break-system-packages 2>/dev/null || pip3 install requests || {
                    print_warn "Could not install 'requests'. Telegram alerts will not work."
                }
            else
                print_warn "pip3 unavailable. Telegram alerts will not work."
            fi
        fi
    fi
fi

echo ""

# ===========================================================================
# Create directory structure
# ===========================================================================
print_step "Creating directories..."
mkdir -p "${INSTALL_DIR}"/{modules,actions,backends,detectors,posture_checks,state,logs,tools,state/geoip}

# ===========================================================================
# Copy files (skip if running from the install directory, e.g. git clone)
# ===========================================================================
GIT_INSTALL=false
if [[ "$SCRIPT_DIR" == "$INSTALL_DIR" ]]; then
    GIT_INSTALL=true
    print_ok "Running from ${INSTALL_DIR} (git clone) — skipping file copy"
else
    print_step "Installing files..."
    cp "${SCRIPT_DIR}/wp-guardian.py" "${INSTALL_DIR}/"
    for dir in modules actions backends detectors posture_checks; do
        if [[ -d "${SCRIPT_DIR}/${dir}" ]]; then
            mkdir -p "${INSTALL_DIR}/${dir}"
            cp "${SCRIPT_DIR}/${dir}/"*.py "${INSTALL_DIR}/${dir}/" 2>/dev/null || true
        fi
    done

    # Copy VERSION file
    if [[ -f "${SCRIPT_DIR}/VERSION" ]]; then
        cp "${SCRIPT_DIR}/VERSION" "${INSTALL_DIR}/"
    fi

    # Copy migrations
    if [[ -d "${SCRIPT_DIR}/migrations" ]]; then
        mkdir -p "${INSTALL_DIR}/migrations"
        cp "${SCRIPT_DIR}/migrations/"*.sql "${INSTALL_DIR}/migrations/" 2>/dev/null || true
        cp "${SCRIPT_DIR}/migrations/README.md" "${INSTALL_DIR}/migrations/" 2>/dev/null || true
    fi

    # Copy update script
    if [[ -f "${SCRIPT_DIR}/update.sh" ]]; then
        cp "${SCRIPT_DIR}/update.sh" "${INSTALL_DIR}/"
        chmod +x "${INSTALL_DIR}/update.sh"
    fi

    # Copy tools
    if [[ -d "${SCRIPT_DIR}/tools" ]]; then
        cp "${SCRIPT_DIR}/tools/"*.py "${INSTALL_DIR}/tools/" 2>/dev/null || true
    fi
    if [[ -f "${SCRIPT_DIR}/log-analyzer.sh" ]]; then
        cp "${SCRIPT_DIR}/log-analyzer.sh" "${INSTALL_DIR}/tools/"
        chmod +x "${INSTALL_DIR}/tools/log-analyzer.sh"
    fi
    if [[ -f "${SCRIPT_DIR}/tools/log-analyzer.sh" ]]; then
        cp "${SCRIPT_DIR}/tools/log-analyzer.sh" "${INSTALL_DIR}/tools/"
        chmod +x "${INSTALL_DIR}/tools/log-analyzer.sh"
    fi
fi

# Make main script executable
chmod +x "${INSTALL_DIR}/wp-guardian.py"

WPG_VERSION=$(cat "${INSTALL_DIR}/VERSION" 2>/dev/null || echo "unknown")
print_ok "Files installed to ${INSTALL_DIR} (v${WPG_VERSION})"

# Stamp the installed version — update.sh reads this on later runs to know
# what version we're upgrading from (git pull overwrites VERSION in place).
mkdir -p "${INSTALL_DIR}/state"
echo "${WPG_VERSION}" > "${INSTALL_DIR}/state/installed_version"

# ===========================================================================
# Interactive Configuration
# ===========================================================================
echo ""
echo -e "${BOLD}--- Configuration ---${NC}"
echo ""

# Skip interactive config if config already exists
SKIP_CONFIG=false
if [[ -f "${INSTALL_DIR}/wp-guardian.conf" ]]; then
    print_warn "Existing wp-guardian.conf found."
    if ! ask_yn "  Reconfigure?" "n"; then
        SKIP_CONFIG=true
    else
        # Backup existing config
        cp "${INSTALL_DIR}/wp-guardian.conf" "${INSTALL_DIR}/wp-guardian.conf.bak"
        print_ok "Backed up existing config to wp-guardian.conf.bak"
    fi
fi

FIREWALL_BACKEND="csf"
TELEGRAM_ENABLED="false"
RUN_TELEGRAM_SETUP=false

if [[ "$SKIP_CONFIG" == "false" ]]; then

    # --- Firewall Backend ---
    echo ""
    echo -e "${BOLD}  Firewall Backend${NC}"
    echo "  Choose how WP-Guardian blocks attackers:"
    echo ""
    echo "    1) CSF (ConfigServer Firewall)"
    echo "       Blocks on this server. Classic, widely used."
    echo ""
    echo "    2) firewalld"
    echo "       Default on RHEL/AlmaLinux and CyberPanel 2.4+."
    echo ""
    echo "    3) nftables (direct)"
    echo "       Modern Linux firewall. No frontend needed."
    echo ""
    echo "    4) MikroTik Router"
    echo "       Blocks at network edge via SSH."
    echo ""
    echo "    5) pfSense / OPNsense"
    echo "       Blocks at network edge via REST API."
    echo ""

    BACKEND_CHOICE=$(ask_choice "  Choice" "1" 1 2 3 4 5 6)

    case "$BACKEND_CHOICE" in
        2)
            FIREWALL_BACKEND="firewalld"
            if ! command -v firewall-cmd &>/dev/null; then
                print_warn "firewall-cmd not found. Install firewalld first."
                print_warn "  yum install firewalld && systemctl enable --now firewalld"
            elif ! systemctl is-active --quiet firewalld 2>/dev/null; then
                print_warn "firewalld is installed but not running."
                print_warn "  systemctl enable --now firewalld"
            else
                print_ok "firewalld is running"
            fi
            install_conntrack_tools
            ;;
        3)
            FIREWALL_BACKEND="nftables"
            if ! command -v nft &>/dev/null; then
                print_warn "nft not found. Install nftables first."
                print_warn "  yum install nftables or apt install nftables"
            else
                print_ok "nftables found"
            fi
            install_conntrack_tools
            ;;
        4)
            FIREWALL_BACKEND="mikrotik"
            echo ""
            print_step "MikroTik configuration:"
            echo ""
            MK_HOST=$(ask_ip "    Router IP" "192.168.2.1" false true)
            MK_PORT=$(ask_port "    SSH port" "22")
            MK_USER=$(ask "    SSH user" "guardian")
            MK_FRIENDLY=$(ask "    Friendly address list name" "friendly")

            # --- SSH Key ---
            echo ""
            echo -e "    ${BOLD}SSH Key Setup${NC}"
            echo "    WP-Guardian connects to MikroTik via SSH using key-based auth."
            echo ""

            # Check for existing keys
            DEFAULT_KEY="/root/.ssh/mikrotik_guardian"
            if [[ -f "$DEFAULT_KEY" ]]; then
                echo "    Found existing key: ${DEFAULT_KEY}"
                MK_KEY=$(ask_path "    SSH private key path" "$DEFAULT_KEY" true)
            else
                # Look for any existing SSH keys
                EXISTING_KEYS=$(ls /root/.ssh/id_* 2>/dev/null | grep -v '\.pub$' || true)
                if [[ -n "$EXISTING_KEYS" ]]; then
                    echo "    Existing SSH keys found:"
                    echo "$EXISTING_KEYS" | while read -r k; do
                        echo "      - $k"
                    done
                    echo ""
                fi

                echo "    Options:"
                echo "      1) Enter path to an existing SSH key"
                echo "      2) Generate a new key pair for MikroTik"
                echo ""
                KEY_CHOICE=$(ask_choice "    Choice" "1" 1 2)

                if [[ "$KEY_CHOICE" == "2" ]]; then
                    MK_KEY="$DEFAULT_KEY"
                    echo ""
                    print_step "Generating SSH key pair..."
                    ssh-keygen -t rsa -b 4096 -f "$MK_KEY" -N "" -q
                    print_ok "Key generated: ${MK_KEY}"
                    echo ""
                    echo "    Now import the public key to MikroTik:"
                    echo "      1. Copy ${MK_KEY}.pub to MikroTik (via WinBox or SCP)"
                    echo "      2. In MikroTik, run:"
                    echo "         /user ssh-keys import public-key-file=$(basename "${MK_KEY}").pub user=${MK_USER}"
                    echo ""
                    read -r -p "    Press Enter when done (or skip and do it later)..."
                else
                    MK_KEY=$(ask_path "    SSH private key path" "$DEFAULT_KEY" true)
                fi
            fi

            # Verify key exists
            if [[ ! -f "$MK_KEY" ]]; then
                print_warn "Key file not found: ${MK_KEY}"
                print_warn "Make sure to create it before starting WP-Guardian."
            else
                print_ok "SSH key found: ${MK_KEY}"

                # Offer to test the connection
                if ask_yn "    Test MikroTik connection now?" "y"; then
                    echo ""
                    print_step "Testing SSH to ${MK_USER}@${MK_HOST}:${MK_PORT}..."
                    TEST_RESULT=$(ssh -i "$MK_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o "Port=${MK_PORT}" -o BatchMode=yes "${MK_USER}@${MK_HOST}" "/system identity print" 2>&1) && {
                        print_ok "Connected! Router identity: ${TEST_RESULT}"
                    } || {
                        print_warn "Connection failed: ${TEST_RESULT}"
                        print_warn "Check key, user, and MikroTik SSH settings."
                        print_warn "You can fix this later in wp-guardian.conf"
                    }
                fi
            fi
            ;;
        5)
            echo ""
            echo "    a) pfSense"
            echo "    b) OPNsense"
            PF_CHOICE=$(ask_choice "    Platform" "a" a b)
            if [[ "$PF_CHOICE" == "b" ]]; then
                FIREWALL_BACKEND="opnsense"
            else
                FIREWALL_BACKEND="pfsense"
            fi
            echo ""
            print_step "pfSense/OPNsense configuration:"
            PF_HOST=$(ask_ip "    Firewall IP" "192.168.1.1" false true)
            PF_PORT=$(ask_port "    API port" "443")
            PF_KEY=$(ask "    API key" "")
            PF_SECRET=$(ask "    API secret" "")
            PF_ALIAS=$(ask "    Block alias name" "wp_guardian_blocked")
            PF_CIDR_ALIAS=$(ask "    CIDR alias name" "wp_guardian_cidr")
            ;;
        *)
            FIREWALL_BACKEND="csf"
            if ! command -v csf &>/dev/null; then
                print_warn "CSF not found. Install it first or choose another backend."
                print_warn "Continuing with CSF backend (it will fail on startup without CSF)."
            else
                print_ok "CSF found"
            fi
            ;;
    esac

    # --- Telegram ---
    echo ""
    echo -e "${BOLD}  Telegram Alerts${NC}"
    TELEGRAM_TOKEN=""
    TELEGRAM_CHAT_ID=""
    RUN_TELEGRAM_SETUP=false
    if ask_yn "  Enable Telegram alerts?" "y"; then
        TELEGRAM_ENABLED="true"
        echo ""
        echo "  If you already have a bot token and chat ID, paste them now."
        echo "  Leave both blank to run the interactive setup wizard at the end of this install."
        echo ""
        TELEGRAM_TOKEN=$(ask_telegram_token "    Bot token (Enter to skip)" "")
        TELEGRAM_CHAT_ID=$(ask_telegram_chat_id "    Chat ID (Enter to skip)" "")

        echo ""
        echo "  Telegram commands let you manage WP-Guardian from your chat:"
        echo "    /status, /unblock, /whitelist, /history, /help"
        echo "  Only messages from your chat_id are processed."
        echo ""
        TELEGRAM_COMMANDS="false"
        if ask_yn "  Enable Telegram commands?" "y"; then
            TELEGRAM_COMMANDS="true"
        fi

        # --- Alert mode (v1.4+) ---
        echo ""
        echo -e "${BOLD}  Telegram Alert Mode (v1.4+)${NC}"
        echo "    1) verbose — every block alerts immediately (recommended for first week)"
        echo "    2) digest  — tier-1/tier-2 blocks are buffered into an hourly summary"
        echo "    3) quiet   — only compromise + BLOCK FAILED alert immediately"
        ALERT_MODE_CHOICE=$(ask_choice "  Choice" "1" 1 2 3)
        case "$ALERT_MODE_CHOICE" in
            2) TELEGRAM_ALERT_MODE="digest" ;;
            3) TELEGRAM_ALERT_MODE="quiet" ;;
            *) TELEGRAM_ALERT_MODE="verbose" ;;
        esac
    fi

    # --- GeoIP (v1.4+) ---
    echo ""
    echo -e "${BOLD}  GeoIP Enrichment (v1.4+)${NC}"
    echo "  Tags every auth event with country, city, and ASN."
    echo "  Required for the compromise-detection feature."
    echo "  You'll need MaxMind GeoLite2 database files (free registration)."
    echo "  See INSTALL.md for setup steps."
    echo ""
    GEOIP_ENABLED="false"
    if ask_yn "  Enable GeoIP enrichment?" "n"; then
        GEOIP_ENABLED="true"
        echo ""
        echo "  Place the following files under /opt/wp-guardian/state/geoip/:"
        echo "    - GeoLite2-City.mmdb"
        echo "    - GeoLite2-ASN.mmdb"
        echo ""
        echo "  Get them from https://www.maxmind.com/en/geolite2/signup"
        echo "  (Dashboard → Manage License Keys → Download Databases)"
        echo ""
        if [[ ! -f "${INSTALL_DIR}/state/geoip/GeoLite2-City.mmdb" ]]; then
            print_warn "GeoLite2-City.mmdb not yet present — place it before starting the daemon."
        else
            print_ok "GeoLite2-City.mmdb found"
        fi
        if [[ ! -f "${INSTALL_DIR}/state/geoip/GeoLite2-ASN.mmdb" ]]; then
            print_warn "GeoLite2-ASN.mmdb not yet present — place it before starting the daemon."
        else
            print_ok "GeoLite2-ASN.mmdb found"
        fi
    fi

    # --- Compromise detection (v1.4+) ---
    echo ""
    echo -e "${BOLD}  Compromise Detection (v1.4+)${NC}"
    echo "  Flags accounts authenticating from many distinct countries/ASNs/IPs"
    echo "  in a short window — the classic credential-abuse botnet signature."
    COMPROMISE_ENABLED="false"
    if ask_yn "  Enable compromise detection?" "n"; then
        COMPROMISE_ENABLED="true"
        if [[ "$GEOIP_ENABLED" != "true" ]]; then
            print_warn "GeoIP is NOT enabled — country/ASN rules will never trigger."
            print_warn "Only the distinct-IPs rule will work without GeoIP."
        fi
    fi

    # --- Block expiry reaper (v1.7.9+) ---
    echo ""
    echo -e "${BOLD}  Block expiry reaper (v1.7.9+)${NC}"
    echo "  Hourly sweep that unblocks tier-1/tier-2 IPs once their duration"
    echo "  has elapsed and resets their tier so repeat offenders still"
    echo "  escalate. Tier 3 (permanent) is never expired."
    echo ""
    echo "  Without it, 'tier1_duration = 24h' is not actually enforced:"
    echo "  on firewalld every block is permanent, and on mikrotik/nftables/csf"
    echo "  the firewall entry expires but the stale tier blocks re-blocking."
    echo "  Leave this on unless you deliberately want blocks to be forever."
    REAP_ENABLED="true"
    if ! ask_yn "  Enable the block expiry reaper?" "y"; then
        REAP_ENABLED="false"
    fi
    REAP_BATCH_LIMIT="500"
    if [[ "$REAP_ENABLED" == "true" ]]; then
        echo "  Each expiry is a firewall call, so a large existing backlog is"
        echo "  drained in batches rather than all at once."
        REAP_BATCH_LIMIT=$(ask_int "  Max blocks to expire per hourly sweep?" "500" 1 100000)
    fi

    # --- POST-flood detector (v1.5+) ---
    echo ""
    echo -e "${BOLD}  POST-flood detector (v1.5+)${NC}"
    echo "  Generic catch-all for admin/auth POST flooding. Watchlist-only —"
    echo "  guards registered admin paths (Joomla /administrator, Drupal /user/login,"
    echo "  /phpmyadmin/, etc.). Two-stage gate: rate threshold + behavioral check"
    echo "  (no CSS / off-host Referer / uniform Content-Length) to stay safe behind"
    echo "  office NAT. Off by default — enable on servers with non-WP CMSes."
    POST_FLOOD_ENABLED="false"
    if ask_yn "  Enable POST-flood detector?" "n"; then
        POST_FLOOD_ENABLED="true"
        echo "  POST-flood will start in digest mode (alerts batched hourly) so you"
        echo "  can observe FPs before promoting to immediate via /verbosity."
    fi

    # --- /tmp cleanup (v1.6+) ---
    echo ""
    echo -e "${BOLD}  /tmp cleanup module (v1.6+)${NC}"
    echo "  Daily janitor for stale, root-owned, world-readable, allowlisted"
    echo "  files in /tmp. Off by default. Recommended rollout: enable as"
    echo "  dry_run, watch the daily Telegram digest for ~14 days, then"
    echo "  promote to live by editing [tmp_cleanup] mode in wp-guardian.conf."
    echo "  Choices: off | dry_run | live"
    TMP_CLEANUP_MODE=$(ask_choice "  /tmp cleanup mode?" "off" "off" "dry_run" "live")

    # --- Mail backend (v1.4+) ---
    echo ""
    echo -e "${BOLD}  Mail Backend Integration (v1.4+)${NC}"
    echo "  Lets Guardian auto-disable a compromised mailbox."
    echo ""
    echo "  Choose your mail server type:"
    echo "    1) CyberPanel       — locks account by resetting password"
    echo "    2) Postfixadmin     — toggles 'active' column"
    echo "    3) Mailcow          — toggles 'active' column"
    echo "    4) iRedMail         — toggles 'active' column"
    echo "    5) Custom           — specify table/columns manually"
    echo "    6) None             — skip mail backend"
    echo ""
    MAIL_BACKEND_TYPE="none"
    MAIL_BACKEND_HOST="127.0.0.1"
    MAIL_BACKEND_PORT="3306"
    MAIL_BACKEND_DB=""
    MAIL_BACKEND_USER="wp_guardian"
    MAIL_BACKEND_PASSWORD=""
    MAIL_BACKEND_TABLE=""
    MAIL_RECIPE_CHOICE=$(ask_choice "  Choice" "6" 1 2 3 4 5 6)
    case "$MAIL_RECIPE_CHOICE" in
        1)
            MAIL_BACKEND_TYPE="cyberpanel"
            MAIL_BACKEND_DB="cyberpanel"
            MAIL_BACKEND_TABLE="e_users"
            echo ""
            echo "  CyberPanel mode: Guardian will reset the mailbox password to lock it."
            echo "  The original password hash is saved so it can be restored with --enable-mailbox."
            echo "  No schema changes needed."
            ;;
        2)
            MAIL_BACKEND_TYPE="postfixadmin"
            MAIL_BACKEND_DB="postfixadmin"
            MAIL_BACKEND_TABLE="mailbox"
            ;;
        3)
            MAIL_BACKEND_TYPE="mailcow"
            MAIL_BACKEND_DB="mailcow"
            MAIL_BACKEND_TABLE="mailbox"
            ;;
        4)
            MAIL_BACKEND_TYPE="iredmail"
            MAIL_BACKEND_DB="vmail"
            MAIL_BACKEND_TABLE="mailbox"
            ;;
        5)
            MAIL_BACKEND_TYPE="custom"
            MAIL_BACKEND_DB=$(ask "    Database name" "mailserver")
            MAIL_BACKEND_TABLE=$(ask "    Table name" "virtual_users")
            ;;
        *)
            MAIL_BACKEND_TYPE="none"
            ;;
    esac

    if [[ "$MAIL_BACKEND_TYPE" != "none" ]]; then
        echo ""
        MAIL_BACKEND_HOST=$(ask_ip "    MariaDB host" "$MAIL_BACKEND_HOST" false true)
        MAIL_BACKEND_PORT=$(ask_port "    MariaDB port" "$MAIL_BACKEND_PORT")
        MAIL_BACKEND_DB=$(ask "    Database name" "$MAIL_BACKEND_DB")
        MAIL_BACKEND_USER=$(ask "    MariaDB user" "$MAIL_BACKEND_USER")
        read -r -s -p "    MariaDB password: " MAIL_BACKEND_PASSWORD
        echo ""

        echo ""
        print_step "Before Guardian can manage mailboxes, run this on your mail server:"
        echo ""
        echo "    CREATE USER '${MAIL_BACKEND_USER}'@'localhost' IDENTIFIED BY '<your password>';"
        if [[ "$MAIL_BACKEND_TYPE" == "cyberpanel" ]]; then
            echo "    GRANT SELECT (email, password), UPDATE (password)"
        else
            echo "    GRANT SELECT (email, enabled), UPDATE (enabled)"
        fi
        echo "      ON ${MAIL_BACKEND_DB}.${MAIL_BACKEND_TABLE} TO '${MAIL_BACKEND_USER}'@'localhost';"
        echo "    FLUSH PRIVILEGES;"
        echo ""
        read -r -p "  Press Enter when done..."
    fi

    # --- Profile (v1.4+) ---
    echo ""
    echo -e "${BOLD}  Threshold Profile (v1.4+)${NC}"
    echo "    1) steady    — tight thresholds for normal operations (default)"
    echo "    2) migration — loose thresholds for post-cutover migration periods"
    PROFILE_CHOICE=$(ask_choice "  Choice" "1" 1 2)
    case "$PROFILE_CHOICE" in
        2) PROFILE_MODE="migration" ;;
        *) PROFILE_MODE="steady" ;;
    esac

    # --- Generate config ---
    print_step "Generating wp-guardian.conf..."

    if [[ -f "${INSTALL_DIR}/wp-guardian.conf.example" ]]; then
        cp "${INSTALL_DIR}/wp-guardian.conf.example" "${INSTALL_DIR}/wp-guardian.conf"
    elif [[ -f "${SCRIPT_DIR}/wp-guardian.conf.example" ]]; then
        cp "${SCRIPT_DIR}/wp-guardian.conf.example" "${INSTALL_DIR}/wp-guardian.conf"
    fi

    # Update config with user's choices
    sed -i "s|^backend = .*|backend = ${FIREWALL_BACKEND}|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true

    if [[ "$FIREWALL_BACKEND" == "mikrotik" ]]; then
        sed -i "/^\[mikrotik\]/,/^\[/ s|^host = .*|host = ${MK_HOST}|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
        sed -i "/^\[mikrotik\]/,/^\[/ s|^port = .*|port = ${MK_PORT}|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
        sed -i "/^\[mikrotik\]/,/^\[/ s|^user = .*|user = ${MK_USER}|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
        sed -i "/^\[mikrotik\]/,/^\[/ s|^key_file = .*|key_file = ${MK_KEY}|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
        sed -i "/^\[mikrotik\]/,/^\[/ s|^friendly_list = .*|friendly_list = ${MK_FRIENDLY}|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
    fi

    if [[ "$FIREWALL_BACKEND" == "pfsense" || "$FIREWALL_BACKEND" == "opnsense" ]]; then
        sed -i "/^\[pfsense\]/,/^\[/ s|^host = .*|host = ${PF_HOST}|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
        sed -i "/^\[pfsense\]/,/^\[/ s|^port = .*|port = ${PF_PORT}|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
        sed -i "/^\[pfsense\]/,/^\[/ s|^api_key = .*|api_key = ${PF_KEY}|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
        sed -i "/^\[pfsense\]/,/^\[/ s|^api_secret = .*|api_secret = ${PF_SECRET}|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
        sed -i "/^\[pfsense\]/,/^\[/ s|^alias_name = .*|alias_name = ${PF_ALIAS}|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
        sed -i "/^\[pfsense\]/,/^\[/ s|^alias_cidr = .*|alias_cidr = ${PF_CIDR_ALIAS}|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
        if [[ "$FIREWALL_BACKEND" == "opnsense" ]]; then
            sed -i "/^\[pfsense\]/,/^\[/ s|^platform = .*|platform = opnsense|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
        else
            sed -i "/^\[pfsense\]/,/^\[/ s|^platform = .*|platform = pfsense|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
        fi
    fi

    # Update Telegram section - find the [telegram] section and update within it
    if [[ -n "${TELEGRAM_TOKEN}" ]]; then
        sed -i "/^\[telegram\]/,/^\[/ s|^bot_token = .*|bot_token = ${TELEGRAM_TOKEN}|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
    fi
    if [[ -n "${TELEGRAM_CHAT_ID}" ]]; then
        sed -i "/^\[telegram\]/,/^\[/ s|^chat_id = .*|chat_id = ${TELEGRAM_CHAT_ID}|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
    fi
    if [[ "$TELEGRAM_ENABLED" == "true" ]]; then
        sed -i "/^\[telegram\]/,/^\[/ s|^enabled = .*|enabled = true|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
    fi
    if [[ "${TELEGRAM_COMMANDS:-false}" == "true" ]]; then
        sed -i "/^\[telegram\]/,/^\[/ s|^commands_enabled = .*|commands_enabled = true|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
    fi
    if [[ -n "${TELEGRAM_ALERT_MODE:-}" ]]; then
        sed -i "/^\[telegram\]/,/^\[/ s|^alert_mode = .*|alert_mode = ${TELEGRAM_ALERT_MODE}|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
    fi

    # v1.4 — GeoIP
    if [[ "${GEOIP_ENABLED:-false}" == "true" ]]; then
        sed -i "/^\[geoip\]/,/^\[/ s|^enabled = .*|enabled = true|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
    fi

    # v1.4 — Compromise detection
    if [[ "${COMPROMISE_ENABLED:-false}" == "true" ]]; then
        sed -i "/^\[compromise_detection\]/,/^\[/ s|^enabled = .*|enabled = true|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
    fi

    # v1.7.9 — Block expiry reaper
    if [[ "${REAP_ENABLED:-true}" == "false" ]]; then
        sed -i "/^\[escalation\]/,/^\[/ s|^reap_enabled = .*|reap_enabled = false|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
    fi
    if [[ -n "${REAP_BATCH_LIMIT:-}" && "${REAP_BATCH_LIMIT}" != "500" ]]; then
        sed -i "/^\[escalation\]/,/^\[/ s|^reap_batch_limit = .*|reap_batch_limit = ${REAP_BATCH_LIMIT}|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
    fi

    # v1.5 — POST-flood detector
    if [[ "${POST_FLOOD_ENABLED:-false}" == "true" ]]; then
        sed -i "/^\[post_flood\]/,/^\[/ s|^enabled = .*|enabled = true|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
    fi

    # v1.6 — /tmp cleanup
    if [[ -n "${TMP_CLEANUP_MODE:-}" && "${TMP_CLEANUP_MODE}" != "off" ]]; then
        sed -i "/^\[tmp_cleanup\]/,/^\[/ s|^mode = .*|mode = ${TMP_CLEANUP_MODE}|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
    fi

    # v1.4 — Mail backend
    # Write mail_backend values via Python configparser so passwords containing
    # sed-meaningful characters ($, &, /, |, newlines, quotes) are handled as
    # literal text. The password never touches the shell as an unquoted value.
    if [[ "${MAIL_BACKEND_TYPE:-none}" != "none" ]]; then
        MAIL_BACKEND_PASSWORD="${MAIL_BACKEND_PASSWORD}" \
        MAIL_BACKEND_TYPE="${MAIL_BACKEND_TYPE}" \
        MAIL_BACKEND_HOST="${MAIL_BACKEND_HOST}" \
        MAIL_BACKEND_PORT="${MAIL_BACKEND_PORT}" \
        MAIL_BACKEND_DB="${MAIL_BACKEND_DB}" \
        MAIL_BACKEND_USER="${MAIL_BACKEND_USER}" \
        MAIL_BACKEND_TABLE="${MAIL_BACKEND_TABLE}" \
        CONF_PATH="${INSTALL_DIR}/wp-guardian.conf" \
        python3 - <<'PYEOF' || print_warn "Failed to write mail_backend config"
import configparser, os, sys
path = os.environ['CONF_PATH']
cp = configparser.ConfigParser()
cp.read(path)
if not cp.has_section('mail_backend'):
    cp.add_section('mail_backend')
for k, env in (
    ('type',           'MAIL_BACKEND_TYPE'),
    ('host',           'MAIL_BACKEND_HOST'),
    ('port',           'MAIL_BACKEND_PORT'),
    ('database',       'MAIL_BACKEND_DB'),
    ('user',           'MAIL_BACKEND_USER'),
    ('password',       'MAIL_BACKEND_PASSWORD'),
    ('table',          'MAIL_BACKEND_TABLE'),
):
    v = os.environ.get(env)
    if v is not None:
        cp.set('mail_backend', k, v)
with open(path, 'w') as f:
    cp.write(f)
print('mail_backend config written ({n} chars in password)'.format(
    n=len(os.environ.get('MAIL_BACKEND_PASSWORD', ''))
))
PYEOF
    fi

    # v1.4 — Profile
    if [[ -n "${PROFILE_MODE:-}" ]]; then
        sed -i "/^\[profile\]/,/^\[/ s|^mode = .*|mode = ${PROFILE_MODE}|" "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || true
    fi

    print_ok "Config generated"

    # Run Telegram setup wizard — only if alerts were enabled AND token/chat_id
    # are still missing. We ask the question HERE (right before the wizard
    # actually runs) instead of upfront in gather_config, so the user isn't
    # surprised by other config questions appearing "inside" the Telegram step.
    if [[ "${TELEGRAM_ENABLED:-false}" == "true" ]] && \
       [[ -z "${TELEGRAM_TOKEN}" || -z "${TELEGRAM_CHAT_ID}" ]]; then
        echo ""
        echo -e "${BOLD}  Telegram Setup Wizard${NC}"
        echo "  Bot token and/or chat ID are not set yet."
        echo "  The wizard will walk you through getting them and write them to wp-guardian.conf."
        if ask_yn "  Run the Telegram setup wizard now?" "y"; then
            echo ""
            python3 "${INSTALL_DIR}/tools/telegram_setup.py" "${INSTALL_DIR}/wp-guardian.conf" || true
        else
            echo "  Skipped. Run later with: python3 ${INSTALL_DIR}/wp-guardian.py --telegram-setup"
        fi
    fi
fi

# ===========================================================================
# Whitelist
# ===========================================================================
echo ""
echo -e "${BOLD}  Whitelist${NC}"

if [[ ! -f "${INSTALL_DIR}/whitelist.conf" ]]; then
    cat > "${INSTALL_DIR}/whitelist.conf" << 'EOF'
# WP-Guardian Whitelist
# One IP or CIDR range per line. These IPs will NEVER be blocked.
127.0.0.1

# Search engine bots — DO NOT BLOCK
# Google (66.249.64.0/19 covers most Googlebot IPs)
66.249.64.0/19
# Bing
40.77.167.0/24
# Yandex
5.255.253.0/24
87.250.253.0/24
213.180.203.0/24
EOF

    # Auto-detect server IPs
    for ip in $(hostname -I 2>/dev/null); do
        echo "${ip}    # Server IP (auto-detected)" >> "${INSTALL_DIR}/whitelist.conf"
    done

    print_ok "Created whitelist.conf with server IPs and search engine bots"
else
    print_ok "Keeping existing whitelist.conf"
fi

echo ""
echo "  Add IPs or CIDR ranges that should never be blocked."
echo "  These are typically your own IP, office IPs, VPN ranges, or monitoring services."
echo ""
echo "  You can enter:"
echo "    - Single IPs:      203.0.113.50"
echo "    - CIDR ranges:     10.0.0.0/24"
echo "    - Multiple values:  203.0.113.50, 10.0.0.0/24, 192.168.1.100"
echo ""
echo "  Enter IPs/CIDRs (comma or space separated), or press Enter to skip."
echo "  Type 'done' on an empty line to finish if entering multiple lines."
echo ""

WHITELIST_COUNT=0
while true; do
    read -r -p "  > " EXTRA_IPS

    # Empty line or 'done' = finished
    if [[ -z "$EXTRA_IPS" || "$EXTRA_IPS" == "done" ]]; then
        break
    fi

    # Split on commas, spaces, or both
    for ip in $(echo "$EXTRA_IPS" | tr ',' ' '); do
        ip=$(echo "$ip" | tr -d ' ')
        if [[ -z "$ip" ]]; then
            continue
        fi

        # Basic validation: looks like an IP or CIDR
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
            echo "${ip}    # Added during install" >> "${INSTALL_DIR}/whitelist.conf"
            WHITELIST_COUNT=$((WHITELIST_COUNT + 1))
        else
            print_warn "Skipped invalid entry: ${ip}"
        fi
    done

    echo "  (Enter more, or press Enter to finish)"
done

if [[ "$WHITELIST_COUNT" -gt 0 ]]; then
    print_ok "Added ${WHITELIST_COUNT} entry/entries to whitelist"
fi

# ===========================================================================
# Log Discovery
# ===========================================================================
echo ""
echo -e "${BOLD}  Log Discovery${NC}"

if ask_yn "  Discover access logs on this server?" "y"; then
    echo ""
    python3 "${INSTALL_DIR}/wp-guardian.py" --discover-logs-save --config "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || {
        print_warn "Log discovery had issues. You can run it later with:"
        echo "    python3 ${INSTALL_DIR}/wp-guardian.py --discover-logs-save"
    }
fi

# ===========================================================================
# Tripwires (empty file if not exists)
# ===========================================================================
if [[ ! -f "${INSTALL_DIR}/tripwires.txt" ]]; then
    touch "${INSTALL_DIR}/tripwires.txt"
fi

# ===========================================================================
# Permissions
# ===========================================================================
print_step "Setting permissions..."
chmod 600 "${INSTALL_DIR}/wp-guardian.conf"
chmod 700 "${INSTALL_DIR}"

# ===========================================================================
# Systemd service
# ===========================================================================
print_step "Installing systemd service..."
if [[ -f "${INSTALL_DIR}/wp-guardian.service" ]]; then
    cp "${INSTALL_DIR}/wp-guardian.service" /etc/systemd/system/
    systemctl daemon-reload
    print_ok "Service installed"
elif [[ -f "${SCRIPT_DIR}/wp-guardian.service" ]]; then
    cp "${SCRIPT_DIR}/wp-guardian.service" /etc/systemd/system/
    systemctl daemon-reload
    print_ok "Service installed"
else
    print_warn "wp-guardian.service not found"
fi

# ===========================================================================
# Summary
# ===========================================================================
echo ""
echo -e "${BOLD}============================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${BOLD}============================================${NC}"
echo ""
echo "  Version:           v$(cat "${INSTALL_DIR}/VERSION" 2>/dev/null || echo "unknown")"
echo "  Install directory: ${INSTALL_DIR}"
echo "  Firewall backend:  ${FIREWALL_BACKEND}"
echo "  Telegram:          ${TELEGRAM_ENABLED}"
echo ""
echo "  Next steps:"
echo ""
echo "    1. Review your config:"
echo "       nano ${INSTALL_DIR}/wp-guardian.conf"
echo ""
echo "    2. Generate tripwires from your logs:"
echo "       python3 ${INSTALL_DIR}/wp-guardian.py --analyze-tripwires"
echo ""
echo "    3. Test with dry-run (watch but don't block):"
echo "       python3 ${INSTALL_DIR}/wp-guardian.py --dry-run"
echo ""
echo "    4. Check status:"
echo "       python3 ${INSTALL_DIR}/wp-guardian.py --status"
echo ""
echo "    5. When ready, start the service:"
echo "       systemctl enable wp-guardian"
echo "       systemctl start wp-guardian"
echo ""
echo "    6. View live logs:"
echo "       journalctl -u wp-guardian -f"
echo ""
echo "  To update in the future:"
if [[ "$GIT_INSTALL" == "true" ]]; then
echo "    cd ${INSTALL_DIR} && git pull && sudo bash update.sh"
else
echo "    cd /path/to/new-source && sudo bash update.sh"
fi
echo ""
