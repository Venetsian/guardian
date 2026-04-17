#!/bin/bash
###############################################################################
# WP-Guardian Update Script
# Updates WP-Guardian from a source directory (git clone or extracted tarball).
# Creates a backup before updating, runs migrations, verifies, and supports
# rollback if something goes wrong.
#
# Usage:
#   bash update.sh                    # Update from current directory
#   bash update.sh /path/to/source    # Update from specified source
#   bash update.sh --rollback         # Rollback to previous version
#   bash update.sh --status           # Show current and backup versions
#
# The script will:
#   1. Create a timestamped backup of the current installation
#   2. Copy new files (preserves config, state, logs)
#   3. Run database migrations
#   4. Verify the new version starts correctly
#   5. Restart the service (if running)
#
# If anything fails, run: bash update.sh --rollback
###############################################################################

set -euo pipefail

INSTALL_DIR="/opt/wp-guardian"
BACKUP_BASE="/opt/wp-guardian-backups"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

print_header() {
    echo ""
    echo -e "${BOLD}============================================${NC}"
    echo -e "${BOLD}  WP-Guardian Updater${NC}"
    echo -e "${BOLD}============================================${NC}"
    echo ""
}

print_step() { echo -e "${CYAN}[*]${NC} $1"; }
print_ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
print_err()  { echo -e "${RED}[✗]${NC} $1"; }

ask_yn() {
    # $1 = prompt, $2 = default (y or n). Exit 0 = yes, 1 = no.
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

get_version() {
    local dir="$1"
    if [[ -f "${dir}/VERSION" ]]; then
        cat "${dir}/VERSION"
    else
        echo "unknown"
    fi
}

# Resolve the version that's currently "installed" (i.e. the one the running
# service is based on). In the `git pull && update.sh` workflow SOURCE_DIR
# equals INSTALL_DIR, so VERSION has already been overwritten by git pull —
# reading it would return the NEW version and "current == new" would be wrong.
#
# Resolution order:
#   1. state/installed_version stamp file (written on successful update/install)
#   2. ORIG_HEAD:VERSION — set by git pull, holds the pre-pull tip
#   3. Current VERSION file (fallback for fresh installs / external-source updates)
get_installed_version() {
    local dir="$1"
    local source="${2:-$dir}"

    if [[ -f "${dir}/state/installed_version" ]]; then
        tr -d '[:space:]' < "${dir}/state/installed_version"
        return
    fi

    local dir_real source_real
    dir_real=$(readlink -f "$dir" 2>/dev/null || echo "$dir")
    source_real=$(readlink -f "$source" 2>/dev/null || echo "$source")
    if [[ "$dir_real" == "$source_real" ]] && [[ -d "${dir}/.git" ]]; then
        local prev
        prev=$(git -C "$dir" show ORIG_HEAD:VERSION 2>/dev/null | tr -d '[:space:]')
        if [[ -n "$prev" ]]; then
            echo "$prev"
            return
        fi
    fi

    get_version "$dir"
}

# Write the version stamp after a successful install/update/rollback.
# The stamp file is ignored by git (belongs in state/) and is what future
# update.sh invocations read to know what version is actually running.
write_installed_version() {
    local dir="$1"
    local version="$2"
    mkdir -p "${dir}/state"
    echo "$version" > "${dir}/state/installed_version"
}

get_db_version() {
    if [[ -f "${INSTALL_DIR}/state/guardian.db" ]]; then
        python3 -c "
import sqlite3, sys
try:
    conn = sqlite3.connect('${INSTALL_DIR}/state/guardian.db')
    cur = conn.execute('SELECT MAX(version) FROM schema_version')
    row = cur.fetchone()
    print(row[0] if row and row[0] is not None else 0)
    conn.close()
except Exception:
    print(0)
" 2>/dev/null
    else
        echo "0"
    fi
}

latest_backup() {
    if [[ -d "${BACKUP_BASE}" ]]; then
        ls -1td "${BACKUP_BASE}"/backup-* 2>/dev/null | head -1
    fi
}

# ===========================================================================
# --status: Show version info
# ===========================================================================
if [[ "${1:-}" == "--status" ]]; then
    print_header
    echo "  Current version:    $(get_installed_version "${INSTALL_DIR}" "${INSTALL_DIR}")"
    echo "  VERSION file:       $(get_version "${INSTALL_DIR}")"
    echo "  Schema version:     $(get_db_version)"

    LATEST=$(latest_backup)
    if [[ -n "$LATEST" ]]; then
        echo "  Latest backup:      $(basename "$LATEST")"
        echo "  Backup version:     $(get_version "$LATEST")"
    else
        echo "  Latest backup:      (none)"
    fi

    echo ""
    exit 0
fi

# ===========================================================================
# --rollback: Restore from the most recent backup
# ===========================================================================
if [[ "${1:-}" == "--rollback" ]]; then
    print_header

    if [[ $EUID -ne 0 ]]; then
        print_err "Rollback requires root: sudo bash update.sh --rollback"
        exit 1
    fi

    LATEST=$(latest_backup)
    if [[ -z "$LATEST" || ! -d "$LATEST" ]]; then
        print_err "No backup found in ${BACKUP_BASE}"
        exit 1
    fi

    BACKUP_VERSION=$(get_version "$LATEST")
    CURRENT_VERSION=$(get_installed_version "${INSTALL_DIR}" "${INSTALL_DIR}")

    echo "  Current version: ${CURRENT_VERSION}"
    echo "  Rollback to:     ${BACKUP_VERSION} ($(basename "$LATEST"))"
    echo ""

    read -r -p "Proceed with rollback? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy] ]]; then
        echo "Rollback cancelled."
        exit 0
    fi

    # Stop service if running
    WAS_RUNNING=false
    if systemctl is-active --quiet wp-guardian 2>/dev/null; then
        print_step "Stopping WP-Guardian service..."
        systemctl stop wp-guardian
        WAS_RUNNING=true
    fi

    # Restore files (skip state/, logs/, and config)
    print_step "Restoring files from backup..."

    # Restore Python files
    cp "${LATEST}/wp-guardian.py" "${INSTALL_DIR}/" 2>/dev/null || true
    cp "${LATEST}/VERSION" "${INSTALL_DIR}/" 2>/dev/null || true

    # Restore modules
    if [[ -d "${LATEST}/modules" ]]; then
        cp "${LATEST}/modules/"*.py "${INSTALL_DIR}/modules/"
    fi

    # Restore actions
    if [[ -d "${LATEST}/actions" ]]; then
        cp "${LATEST}/actions/"*.py "${INSTALL_DIR}/actions/"
    fi

    # Restore backends
    if [[ -d "${LATEST}/backends" ]]; then
        cp "${LATEST}/backends/"*.py "${INSTALL_DIR}/backends/"
    fi

    # Restore tools
    if [[ -d "${LATEST}/tools" ]]; then
        cp "${LATEST}/tools/"* "${INSTALL_DIR}/tools/" 2>/dev/null || true
    fi

    # Restore migrations
    if [[ -d "${LATEST}/migrations" ]]; then
        mkdir -p "${INSTALL_DIR}/migrations"
        cp "${LATEST}/migrations/"* "${INSTALL_DIR}/migrations/" 2>/dev/null || true
    fi

    # Restore database backup if it exists
    if [[ -f "${LATEST}/state/guardian.db.backup" ]]; then
        print_step "Restoring database backup..."
        cp "${LATEST}/state/guardian.db.backup" "${INSTALL_DIR}/state/guardian.db"
    fi

    print_ok "Files restored from backup"

    # Restart service if it was running
    if [[ "$WAS_RUNNING" == "true" ]]; then
        print_step "Starting WP-Guardian service..."
        systemctl start wp-guardian
        sleep 2
        if systemctl is-active --quiet wp-guardian 2>/dev/null; then
            print_ok "Service started successfully"
        else
            print_err "Service failed to start after rollback!"
            print_warn "Check: journalctl -u wp-guardian -n 50"
        fi
    fi

    # Stamp the restored version so future update.sh runs know the truth
    write_installed_version "${INSTALL_DIR}" "${BACKUP_VERSION}"

    echo ""
    print_ok "Rollback complete — now running v$(get_version "${INSTALL_DIR}")"
    echo ""
    exit 0
fi

# ===========================================================================
# Main update flow
# ===========================================================================
print_header

if [[ $EUID -ne 0 ]]; then
    print_err "Run as root: sudo bash update.sh"
    exit 1
fi

# Determine source directory
SOURCE_DIR="${1:-$SCRIPT_DIR}"

if [[ ! -f "${SOURCE_DIR}/wp-guardian.py" ]]; then
    print_err "Source not found: ${SOURCE_DIR}/wp-guardian.py"
    echo "  Usage: bash update.sh [/path/to/source]"
    exit 1
fi

if [[ ! -d "${INSTALL_DIR}" ]]; then
    print_err "WP-Guardian not installed at ${INSTALL_DIR}"
    echo "  Run install.sh for first-time installation."
    exit 1
fi

# Show version info
# For the in-place git-pull case, VERSION has already been overwritten — use
# the stamp file or ORIG_HEAD to find the version we're upgrading FROM.
CURRENT_VERSION=$(get_installed_version "${INSTALL_DIR}" "${SOURCE_DIR}")
NEW_VERSION=$(get_version "${SOURCE_DIR}")

echo "  Current version: ${CURRENT_VERSION}"
echo "  New version:     ${NEW_VERSION}"
echo ""

if [[ "$CURRENT_VERSION" == "$NEW_VERSION" ]]; then
    print_warn "Versions are the same. Continuing anyway (may contain fixes)."
    echo ""
fi

# ===========================================================================
# Step 1: Create backup
# ===========================================================================
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="${BACKUP_BASE}/backup-${TIMESTAMP}-v${CURRENT_VERSION}"

print_step "Creating backup at ${BACKUP_DIR}..."
mkdir -p "${BACKUP_DIR}"

# Backup code files
cp "${INSTALL_DIR}/wp-guardian.py" "${BACKUP_DIR}/" 2>/dev/null || true
cp "${INSTALL_DIR}/VERSION" "${BACKUP_DIR}/" 2>/dev/null || true

for dir in modules actions backends tools migrations; do
    if [[ -d "${INSTALL_DIR}/${dir}" ]]; then
        mkdir -p "${BACKUP_DIR}/${dir}"
        cp -r "${INSTALL_DIR}/${dir}/"* "${BACKUP_DIR}/${dir}/" 2>/dev/null || true
    fi
done

# Backup database
if [[ -f "${INSTALL_DIR}/state/guardian.db" ]]; then
    mkdir -p "${BACKUP_DIR}/state"
    cp "${INSTALL_DIR}/state/guardian.db" "${BACKUP_DIR}/state/guardian.db.backup"
fi

# Backup config (for reference only — we don't overwrite config during update)
cp "${INSTALL_DIR}/wp-guardian.conf" "${BACKUP_DIR}/" 2>/dev/null || true

print_ok "Backup created: $(du -sh "${BACKUP_DIR}" | cut -f1)"

# ===========================================================================
# Step 2: Stop service
# ===========================================================================
WAS_RUNNING=false
if systemctl is-active --quiet wp-guardian 2>/dev/null; then
    print_step "Stopping WP-Guardian service..."
    systemctl stop wp-guardian
    WAS_RUNNING=true
    sleep 1
fi

# ===========================================================================
# Step 3: Copy new files (skip if source IS the install dir, e.g. git pull)
# ===========================================================================
if [[ "$SOURCE_DIR" == "$INSTALL_DIR" ]]; then
    print_ok "Running in-place (git pull) — skipping file copy"

    # Prevent filemode changes from blocking future git pulls
    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        git -C "${INSTALL_DIR}" config core.fileMode false
    fi
else
    print_step "Installing new files..."

    # Main script
    cp "${SOURCE_DIR}/wp-guardian.py" "${INSTALL_DIR}/"

    # VERSION file
    cp "${SOURCE_DIR}/VERSION" "${INSTALL_DIR}/" 2>/dev/null || true

    # Modules
    for dir in modules actions backends tools; do
        if [[ -d "${SOURCE_DIR}/${dir}" ]]; then
            mkdir -p "${INSTALL_DIR}/${dir}"
            cp "${SOURCE_DIR}/${dir}/"*.py "${INSTALL_DIR}/${dir}/" 2>/dev/null || true
        fi
    done

    # Shell scripts in tools/
    if [[ -d "${SOURCE_DIR}/tools" ]]; then
        cp "${SOURCE_DIR}/tools/"*.sh "${INSTALL_DIR}/tools/" 2>/dev/null || true
        chmod +x "${INSTALL_DIR}/tools/"*.sh 2>/dev/null || true
    fi

    # Migrations
    if [[ -d "${SOURCE_DIR}/migrations" ]]; then
        mkdir -p "${INSTALL_DIR}/migrations"
        cp "${SOURCE_DIR}/migrations/"*.sql "${INSTALL_DIR}/migrations/" 2>/dev/null || true
        cp "${SOURCE_DIR}/migrations/README.md" "${INSTALL_DIR}/migrations/" 2>/dev/null || true
    fi

    print_ok "Files updated"
fi

# Systemd service file (always update — goes to /etc/systemd/system/)
if [[ -f "${INSTALL_DIR}/wp-guardian.service" ]]; then
    cp "${INSTALL_DIR}/wp-guardian.service" /etc/systemd/system/
    systemctl daemon-reload
fi

# ===========================================================================
# Step 4: Run database migrations
# ===========================================================================
print_step "Checking database migrations..."

SCHEMA_BEFORE=$(get_db_version)

if [[ -f "${INSTALL_DIR}/state/guardian.db" ]]; then
    python3 "${INSTALL_DIR}/wp-guardian.py" --migrate --config "${INSTALL_DIR}/wp-guardian.conf" 2>/dev/null || {
        print_warn "Migration check had issues (may be fine on first run)"
    }
fi

SCHEMA_AFTER=$(get_db_version)

if [[ "$SCHEMA_BEFORE" != "$SCHEMA_AFTER" ]]; then
    print_ok "Database migrated: schema v${SCHEMA_BEFORE} -> v${SCHEMA_AFTER}"
else
    print_ok "Database schema up to date (v${SCHEMA_AFTER})"
fi

# ===========================================================================
# Step 5: Config upgrade check
# ===========================================================================
if [[ -f "${INSTALL_DIR}/wp-guardian.conf" ]] && [[ -f "${INSTALL_DIR}/tools/config-upgrade.py" ]]; then
    print_step "Checking config for new options..."

    # Show what's new and detect missing config
    DIFF_OUTPUT=$(python3 "${INSTALL_DIR}/tools/config-upgrade.py" --diff-only --quiet \
        --config "${INSTALL_DIR}/wp-guardian.conf" \
        --example "${INSTALL_DIR}/wp-guardian.conf.example" 2>&1) || true
    DIFF_EXIT=$?

    if echo "$DIFF_OUTPUT" | grep -q "Missing config"; then
        # Show what's new from changelog
        python3 "${INSTALL_DIR}/tools/config-upgrade.py" --diff-only \
            --config "${INSTALL_DIR}/wp-guardian.conf" \
            --example "${INSTALL_DIR}/wp-guardian.conf.example" 2>/dev/null || true

        echo ""
        if ask_yn "  Run config upgrade wizard to set up new options?" "y"; then
            python3 "${INSTALL_DIR}/tools/config-upgrade.py" \
                --config "${INSTALL_DIR}/wp-guardian.conf" \
                --example "${INSTALL_DIR}/wp-guardian.conf.example"
        else
            echo ""
            if ask_yn "  Add new options with default values?" "y"; then
                python3 "${INSTALL_DIR}/tools/config-upgrade.py" --auto \
                    --config "${INSTALL_DIR}/wp-guardian.conf" \
                    --example "${INSTALL_DIR}/wp-guardian.conf.example"
            else
                print_warn "Skipped config upgrade. Run later with:"
                echo "    python3 ${INSTALL_DIR}/tools/config-upgrade.py"
            fi
        fi
    else
        print_ok "Config is up to date"
    fi
else
    print_warn "Config or upgrade tool not found — skipping config check"
fi

# ===========================================================================
# Step 6: Verify
# ===========================================================================
print_step "Verifying installation..."

# Check Python syntax
VERIFY_OK=true

python3 -c "
import sys, os
sys.path.insert(0, '${INSTALL_DIR}')
# Check imports
from modules.config import load_config
from modules.database import GuardianDB
from modules.blocker import Blocker
from backends.factory import create_backend
print('All imports OK')
" 2>/dev/null || {
    print_err "Import verification failed!"
    VERIFY_OK=false
}

# Check optional dependencies based on config
if [[ -f "${INSTALL_DIR}/wp-guardian.conf" ]]; then
    python3 -c "
import sys, os
sys.path.insert(0, '${INSTALL_DIR}')
from modules.config import load_config
config = load_config('${INSTALL_DIR}/wp-guardian.conf')
warnings = []

# Check PyMySQL for mail_backend
mb_type = config.get('mail_backend', 'type', fallback='none').strip().lower()
if mb_type != 'none' and mb_type != '':
    try:
        import pymysql
    except ImportError:
        warnings.append('PyMySQL (required for [mail_backend] type={t})'.format(t=mb_type))

# Check geoip2 for geoip
geoip = config.get('geoip', 'enabled', fallback='false').strip().lower()
if geoip == 'true':
    try:
        import geoip2
    except ImportError:
        warnings.append('geoip2 (required for [geoip] enabled=true)')

if warnings:
    print('MISSING:' + '|'.join(warnings))
else:
    print('OK')
" 2>/dev/null | while IFS= read -r line; do
        if [[ "$line" == MISSING:* ]]; then
            DEPS="${line#MISSING:}"
            IFS='|' read -ra DEP_LIST <<< "$DEPS"
            print_warn "Missing Python dependencies for enabled features:"
            for dep in "${DEP_LIST[@]}"; do
                echo "    - $dep"
            done
            echo ""
            echo "    Install with: pip3 install -r ${INSTALL_DIR}/requirements.txt --break-system-packages"
            echo ""
        fi
    done
fi

# Quick version check
INSTALLED_VERSION=$(python3 -c "
import sys, os
sys.path.insert(0, '${INSTALL_DIR}')
f = open('${INSTALL_DIR}/VERSION')
print(f.read().strip())
f.close()
" 2>/dev/null || echo "unknown")

if [[ "$INSTALLED_VERSION" == "$NEW_VERSION" ]]; then
    print_ok "Version verified: v${INSTALLED_VERSION}"
else
    print_warn "Version mismatch: expected ${NEW_VERSION}, got ${INSTALLED_VERSION}"
fi

if [[ "$VERIFY_OK" == "false" ]]; then
    print_err "Verification failed! Consider rolling back:"
    echo "    sudo bash ${SOURCE_DIR}/update.sh --rollback"
    echo ""
    exit 1
fi

# Stamp the installed version — read by the next update.sh run as the
# authoritative "current version", so `git pull && update.sh` shows the
# real old → new transition even though VERSION has already been overwritten.
write_installed_version "${INSTALL_DIR}" "${NEW_VERSION}"

# ===========================================================================
# Step 7: Restart service
# ===========================================================================
if [[ "$WAS_RUNNING" == "true" ]]; then
    print_step "Starting WP-Guardian service..."
    systemctl start wp-guardian
    sleep 2

    if systemctl is-active --quiet wp-guardian 2>/dev/null; then
        print_ok "Service started successfully"
    else
        print_err "Service failed to start!"
        print_warn "Check logs: journalctl -u wp-guardian -n 50"
        print_warn "To rollback: sudo bash ${SOURCE_DIR}/update.sh --rollback"
        exit 1
    fi
fi

# ===========================================================================
# Step 8: Cleanup old backups (keep last 5)
# ===========================================================================
if [[ -d "${BACKUP_BASE}" ]]; then
    BACKUP_COUNT=$(ls -1d "${BACKUP_BASE}"/backup-* 2>/dev/null | wc -l)
    if [[ "$BACKUP_COUNT" -gt 5 ]]; then
        REMOVE_COUNT=$((BACKUP_COUNT - 5))
        ls -1td "${BACKUP_BASE}"/backup-* | tail -n "$REMOVE_COUNT" | while read -r old_backup; do
            rm -rf "$old_backup"
        done
        print_ok "Cleaned up ${REMOVE_COUNT} old backup(s) (keeping 5)"
    fi
fi

# ===========================================================================
# Summary
# ===========================================================================
echo ""
echo -e "${BOLD}============================================${NC}"
echo -e "${GREEN}  Update Complete!${NC}"
echo -e "${BOLD}============================================${NC}"
echo ""
echo "  Version:        v${CURRENT_VERSION} -> v${NEW_VERSION}"
echo "  Schema:         v${SCHEMA_BEFORE} -> v${SCHEMA_AFTER}"
echo "  Backup:         $(basename "${BACKUP_DIR}")"
echo ""
echo "  If something is wrong, rollback with:"
echo "    sudo bash update.sh --rollback"
echo ""
