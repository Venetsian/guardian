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

# Check requests
if ! python3 -c "import requests" 2>/dev/null; then
    print_warn "Python 'requests' module not found (needed for Telegram)"
    if ask_yn "  Install it now?"; then
        pip3 install requests --break-system-packages 2>/dev/null || pip3 install requests || {
            print_warn "Could not install 'requests'. Telegram alerts will not work."
        }
    fi
fi

echo ""

# ===========================================================================
# Create directory structure
# ===========================================================================
print_step "Creating directories..."
mkdir -p "${INSTALL_DIR}"/{modules,actions,backends,state,logs,tools,state/geoip}

# ===========================================================================
# Copy files
# ===========================================================================
print_step "Installing files..."
cp "${SCRIPT_DIR}/wp-guardian.py" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/modules/"*.py "${INSTALL_DIR}/modules/"
cp "${SCRIPT_DIR}/actions/"*.py "${INSTALL_DIR}/actions/"
cp "${SCRIPT_DIR}/backends/"*.py "${INSTALL_DIR}/backends/"

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

# Make main script executable
chmod +x "${INSTALL_DIR}/wp-guardian.py"

WPG_VERSION=$(cat "${INSTALL_DIR}/VERSION" 2>/dev/null || echo "unknown")
print_ok "Files installed to ${INSTALL_DIR} (v${WPG_VERSION})"

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

    BACKEND_CHOICE=$(ask "  Choice" "1")

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
            ;;
        3)
            FIREWALL_BACKEND="nftables"
            if ! command -v nft &>/dev/null; then
                print_warn "nft not found. Install nftables first."
                print_warn "  yum install nftables or apt install nftables"
            else
                print_ok "nftables found"
            fi
            ;;
        4)
            FIREWALL_BACKEND="mikrotik"
            echo ""
            print_step "MikroTik configuration:"
            MK_HOST=$(ask "    Router IP" "192.168.2.1")
            MK_PORT=$(ask "    SSH port" "22")
            MK_USER=$(ask "    SSH user" "guardian")
            MK_KEY=$(ask "    SSH key path" "/root/.ssh/mikrotik_guardian")
            MK_FRIENDLY=$(ask "    Friendly address list name" "friendly")
            ;;
        5)
            echo ""
            echo "    a) pfSense"
            echo "    b) OPNsense"
            PF_CHOICE=$(ask "    Platform" "a")
            if [[ "$PF_CHOICE" == "b" ]]; then
                FIREWALL_BACKEND="opnsense"
            else
                FIREWALL_BACKEND="pfsense"
            fi
            echo ""
            print_step "pfSense/OPNsense configuration:"
            PF_HOST=$(ask "    Firewall IP" "192.168.1.1")
            PF_PORT=$(ask "    API port" "443")
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
    if ask_yn "  Enable Telegram alerts?" "y"; then
        TELEGRAM_ENABLED="true"
        echo ""
        echo "  Run the setup wizard to configure your bot."
        echo "  (You can also do this later with: wp-guardian.py --telegram-setup)"
        echo ""
        if ask_yn "  Run Telegram setup wizard now?" "y"; then
            RUN_TELEGRAM_SETUP=true
        else
            RUN_TELEGRAM_SETUP=false
            TELEGRAM_TOKEN=$(ask "    Bot token (or press Enter to skip)" "")
            TELEGRAM_CHAT_ID=$(ask "    Chat ID (or press Enter to skip)" "")
        fi
    fi

    # --- Generate config ---
    print_step "Generating wp-guardian.conf..."

    if [[ -f "${SCRIPT_DIR}/wp-guardian.conf.example" ]]; then
        cp "${SCRIPT_DIR}/wp-guardian.conf.example" "${INSTALL_DIR}/wp-guardian.conf"
    elif [[ -f "${SCRIPT_DIR}/wp-guardian.conf" ]]; then
        cp "${SCRIPT_DIR}/wp-guardian.conf" "${INSTALL_DIR}/wp-guardian.conf"
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

    print_ok "Config generated"

    # Run Telegram setup wizard if requested
    if [[ "${RUN_TELEGRAM_SETUP}" == "true" ]]; then
        echo ""
        python3 "${INSTALL_DIR}/tools/telegram_setup.py" "${INSTALL_DIR}/wp-guardian.conf" || true
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
echo "  Add any additional IPs to always allow (comma-separated)."
echo "  These are typically your own IP, office IPs, or monitoring services."
EXTRA_IPS=$(ask "  Extra IPs to whitelist (or Enter to skip)" "")

if [[ -n "$EXTRA_IPS" ]]; then
    IFS=',' read -ra IP_ARRAY <<< "$EXTRA_IPS"
    for ip in "${IP_ARRAY[@]}"; do
        ip=$(echo "$ip" | tr -d ' ')
        if [[ -n "$ip" ]]; then
            echo "${ip}    # Added during install" >> "${INSTALL_DIR}/whitelist.conf"
        fi
    done
    print_ok "Added ${#IP_ARRAY[@]} IP(s) to whitelist"
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
if [[ -f "${SCRIPT_DIR}/wp-guardian.service" ]]; then
    cp "${SCRIPT_DIR}/wp-guardian.service" /etc/systemd/system/
    systemctl daemon-reload
    print_ok "Service installed"
else
    print_warn "wp-guardian.service not found in source directory"
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
echo "       python3 ${INSTALL_DIR}/wp-guardian.py --auto-analyze"
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
echo "    cd /path/to/new-source && sudo bash update.sh"
echo ""
