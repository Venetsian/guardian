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

    # Restore Python packages — modules, actions, backends, detectors, posture_checks
    for dir in modules actions backends detectors posture_checks; do
        if [[ -d "${LATEST}/${dir}" ]]; then
            mkdir -p "${INSTALL_DIR}/${dir}"
            cp "${LATEST}/${dir}/"*.py "${INSTALL_DIR}/${dir}/" 2>/dev/null || true
        fi
    done

    # Restore tools (mixed .py + .sh)
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
# Preflight: Check optional Python dependencies for enabled features
# ===========================================================================
# Runs BEFORE any backup/file copy/migration, so if deps are missing and the
# operator aborts, the install is untouched. If the operator accepts and
# install succeeds, we continue. If they decline, we exit 1 — no silent
# half-working updates where a feature is enabled in config but its
# Python dep is missing (e.g. geoip2 → DistributedAuthDetector country rules
# never fire because GeoIPResolver fails safe to None).
print_step "Checking optional Python dependencies..."

DEP_CHECK=""
if [[ -f "${INSTALL_DIR}/wp-guardian.conf" ]]; then
    DEP_CHECK=$(python3 -c "
import sys, os
sys.path.insert(0, '${INSTALL_DIR}')
try:
    from modules.config import load_config
    config = load_config('${INSTALL_DIR}/wp-guardian.conf')
except Exception as e:
    print('ERROR:config load failed: {e}'.format(e=e))
    sys.exit(0)

warnings = []

# PyMySQL — required for [mail_backend] type != none
mb_type = config.get('mail_backend', 'type', fallback='none').strip().lower()
if mb_type and mb_type != 'none':
    try:
        import pymysql  # noqa: F401
    except ImportError:
        warnings.append('PyMySQL|[mail_backend] type={t} — mailbox disable/enable will fail'.format(t=mb_type))

# geoip2 — required for [geoip] enabled=true
if config.get('geoip', 'enabled', fallback='false').strip().lower() == 'true':
    try:
        import geoip2  # noqa: F401
    except ImportError:
        warnings.append('geoip2|[geoip] enabled=true — country/ASN detection silently disabled; DistributedAuthDetector rules will never fire')

# requests — required for [telegram] enabled=true
if config.get('telegram', 'enabled', fallback='false').strip().lower() == 'true':
    try:
        import requests  # noqa: F401
    except ImportError:
        warnings.append('requests|[telegram] enabled=true — no alerts, no /verbosity commands')

if warnings:
    print('MISSING:' + '\n'.join(warnings))
else:
    print('OK')
" 2>/dev/null || echo "ERROR:python check crashed")
fi

# Treat anything unrecognized as a soft warning — don't block the update on
# a diagnostic glitch, but DO block on a confirmed MISSING.
if [[ "$DEP_CHECK" == ERROR:* ]]; then
    print_warn "Could not verify dependencies: ${DEP_CHECK#ERROR:}"
    echo "    Proceeding — import verification at step 6 will catch hard failures."
    echo ""
elif [[ -z "$DEP_CHECK" || ( "$DEP_CHECK" != "OK" && "$DEP_CHECK" != MISSING:* ) ]]; then
    print_warn "Dep check returned unexpected output — skipping gate."
    echo ""
elif [[ "$DEP_CHECK" == MISSING:* ]]; then
    echo ""
    echo -e "${RED}${BOLD}============================================${NC}"
    echo -e "${RED}${BOLD}  MISSING REQUIRED DEPENDENCIES${NC}"
    echo -e "${RED}${BOLD}============================================${NC}"
    echo ""
    echo "  The live config has features enabled that need Python modules"
    echo "  which are not installed. Continuing as-is would leave those"
    echo "  features silently broken:"
    echo ""
    DEPS_LIST="${DEP_CHECK#MISSING:}"
    while IFS='|' read -r pkg reason; do
        [[ -z "$pkg" ]] && continue
        echo -e "    ${RED}•${NC} ${BOLD}${pkg}${NC}"
        echo "      ${reason}"
    done <<< "$DEPS_LIST"
    echo ""

    # Non-interactive run (no TTY on stdin) — refuse by default. Safer to
    # fail visibly than to let an automated caller skip silently.
    if [[ ! -t 0 ]]; then
        print_err "Non-interactive run with missing dependencies — aborting."
        echo "    Install with: pip3 install -r ${SOURCE_DIR}/requirements.txt --break-system-packages"
        echo "    Or set features to disabled in ${INSTALL_DIR}/wp-guardian.conf."
        exit 1
    fi

    REQ_FILE="${SOURCE_DIR}/requirements.txt"
    if [[ ! -f "$REQ_FILE" ]]; then
        REQ_FILE="${INSTALL_DIR}/requirements.txt"
    fi

    if [[ -f "$REQ_FILE" ]] && ask_yn "  Install missing dependencies now (pip3 install -r requirements.txt)?" "y"; then
        echo ""
        if ensure_pip3; then
            print_step "Running: pip3 install -r ${REQ_FILE} --break-system-packages"
            if pip3 install -r "${REQ_FILE}" --break-system-packages; then
                echo ""
                print_ok "Dependencies installed — re-checking..."
                RECHECK=$(python3 -c "
import sys
sys.path.insert(0, '${INSTALL_DIR}')
from modules.config import load_config
config = load_config('${INSTALL_DIR}/wp-guardian.conf')
still_missing = []
mb_type = config.get('mail_backend', 'type', fallback='none').strip().lower()
if mb_type and mb_type != 'none':
    try: import pymysql
    except ImportError: still_missing.append('PyMySQL')
if config.get('geoip', 'enabled', fallback='false').strip().lower() == 'true':
    try: import geoip2
    except ImportError: still_missing.append('geoip2')
if config.get('telegram', 'enabled', fallback='false').strip().lower() == 'true':
    try: import requests
    except ImportError: still_missing.append('requests')
print('|'.join(still_missing) if still_missing else 'OK')
" 2>/dev/null)
                if [[ "$RECHECK" == "OK" ]]; then
                    print_ok "All dependencies now satisfied"
                    echo ""
                else
                    print_err "Still missing after install: ${RECHECK}"
                    if ask_yn "  Continue update with FEATURES DISABLED anyway?" "n"; then
                        print_warn "Proceeding with known-broken features."
                        echo ""
                    else
                        print_err "Update aborted. Nothing has been changed."
                        exit 1
                    fi
                fi
            else
                print_err "pip install failed — see output above."
                if ask_yn "  Continue update with FEATURES DISABLED anyway?" "n"; then
                    print_warn "Proceeding with known-broken features."
                    echo ""
                else
                    print_err "Update aborted. Nothing has been changed."
                    exit 1
                fi
            fi
        else
            print_err "Could not get pip3 onto PATH (system package manager couldn't install python3-pip)."
            print_err "Install python3-pip manually, then re-run update.sh:"
            print_err "  EL/CL/Fedora:  dnf install python3-pip"
            print_err "  Debian/Ubuntu: apt-get install python3-pip"
            echo ""
            if ask_yn "  Continue update with FEATURES DISABLED anyway?" "n"; then
                print_warn "Proceeding with known-broken features."
                echo ""
            else
                print_err "Update aborted. Nothing has been changed."
                exit 1
            fi
        fi
    else
        echo ""
        echo "  Install manually later with:"
        echo "    pip3 install -r ${REQ_FILE} --break-system-packages"
        echo ""
        if ask_yn "  Continue update with FEATURES DISABLED?" "n"; then
            print_warn "Proceeding with known-broken features."
            echo ""
        else
            print_err "Update aborted. Nothing has been changed."
            exit 1
        fi
    fi
else
    print_ok "All enabled features have their dependencies"
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

for dir in modules actions backends detectors posture_checks tools migrations; do
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

    # Modules + sibling Python packages (detectors/, posture_checks/)
    for dir in modules actions backends detectors posture_checks tools; do
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

# Optional-dep check ran at preflight — no need to repeat here.

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
