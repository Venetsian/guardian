#!/bin/bash
###############################################################################
# WP-Guardian Log Analyzer
#
# Analyzes access logs to discover bot scanning patterns by finding PHP
# requests that return 404 or 401. Output is a ranked list of suspected
# attack paths for use as tripwires in the guardian service.
#
# Usage:
#   ./log-analyzer.sh [OPTIONS]
#
# Options:
#   -l FILE    Path to logfiles list (default: /root/logfiles.txt)
#   -n NUM     Show top N results (default: 50)
#   -o FILE    Export tripwire list (clean paths, one per line)
#   -i         Show top scanning IPs
#   -h         Show help
#
###############################################################################

set +e  # Don't exit on errors — we handle them ourselves

# Defaults
LOGFILES_LIST="/root/logfiles.txt"
TOP_N=50
OUTPUT_FILE=""
SHOW_IPS=false

# Colors
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

show_help() {
    cat <<'EOF'
WP-Guardian Log Analyzer — Discover bot scanning patterns

Usage: ./log-analyzer.sh [OPTIONS]

Options:
  -l FILE    Path to logfiles list (default: /root/logfiles.txt)
  -n NUM     Show top N results (default: 50)
  -o FILE    Export clean tripwire list for guardian
  -i         Also show top scanning IPs
  -h         Show this help

Examples:
  ./log-analyzer.sh                                    # Basic scan
  ./log-analyzer.sh -n 100 -i                          # Top 100 with IPs
  ./log-analyzer.sh -o /opt/wp-guardian/tripwires.txt   # Export for guardian
EOF
}

while getopts "l:n:o:ih" opt; do
    case "$opt" in
        l) LOGFILES_LIST="$OPTARG" ;;
        n) TOP_N="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        i) SHOW_IPS=true ;;
        h) show_help; exit 0 ;;
        *) show_help; exit 1 ;;
    esac
done

# Validate
if [[ ! -f "$LOGFILES_LIST" ]]; then
    echo -e "${RED}Error: Logfiles list not found: ${LOGFILES_LIST}${RESET}"
    echo "Create it with: find /home/*/logs -name '*.access_log' -type f > /root/logfiles.txt"
    exit 1
fi

LOG_COUNT=$(grep -c -v '^\s*$\|^\s*#' "$LOGFILES_LIST" 2>/dev/null || echo 0)

echo -e "${BOLD}═══════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  WP-Guardian Log Analyzer${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${RESET}"
echo -e "  Log files:  ${CYAN}${LOG_COUNT}${RESET}"
echo -e "  Top N:      ${CYAN}${TOP_N}${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${RESET}"
echo ""
echo -e "${CYAN}Analyzing logs...${RESET}"

# Temp file for results: PATH|IP
TMPFILE=$(mktemp /tmp/wpg-analyzer.XXXXXX)
trap "rm -f $TMPFILE" EXIT

# The proven pipeline: xargs grep -h to suppress filenames, gsub to strip leading quotes from IPs
cat "$LOGFILES_LIST" | xargs grep -h '\.php' 2>/dev/null \
    | grep -E '" (401|403|404) ' \
    | awk '{match($0, /"(GET|POST|HEAD) ([^ ]+)/, a); sub(/\?.*/, "", a[2]); ip=$1; gsub(/"/, "", ip); path=tolower(a[2]); if(path != "" && path !~ /wp-login\.php/ && path !~ /xmlrpc\.php/) print path "|" ip}' \
    > "$TMPFILE"

TOTAL_HITS=$(wc -l < "$TMPFILE")
echo -e "  Total suspicious PHP hits: ${YELLOW}${TOTAL_HITS}${RESET}"
echo ""

if [[ "$TOTAL_HITS" -eq 0 ]]; then
    echo -e "${GREEN}No suspicious PHP requests found. Logs are clean!${RESET}"
    exit 0
fi

# ─────────────────────────────────────────────
# Report 1: Top probed paths
# ─────────────────────────────────────────────
echo -e "${BOLD}──────────────────────────────────────────────────────${RESET}"
echo -e "${BOLD}  TOP ${TOP_N} PROBED PHP PATHS${RESET}"
echo -e "${BOLD}──────────────────────────────────────────────────────${RESET}"
printf "  ${CYAN}%-8s %s${RESET}\n" "HITS" "PATH"
echo -e "${BOLD}──────────────────────────────────────────────────────${RESET}"

cut -d'|' -f1 "$TMPFILE" | sort | uniq -c | sort -rn | head -n "$TOP_N" | while read -r hits path; do
    printf "  ${YELLOW}%-8s${RESET} %s\n" "$hits" "$path"
done

echo ""

# ─────────────────────────────────────────────
# Report 2: Top scanning IPs
# ─────────────────────────────────────────────
if [[ "$SHOW_IPS" == true ]]; then
    echo -e "${BOLD}──────────────────────────────────────────────────────${RESET}"
    echo -e "${BOLD}  TOP 30 SCANNING IPs${RESET}"
    echo -e "${BOLD}──────────────────────────────────────────────────────${RESET}"
    printf "  ${CYAN}%-8s %-8s %s${RESET}\n" "HITS" "PATHS" "IP ADDRESS"
    echo -e "${BOLD}──────────────────────────────────────────────────────${RESET}"

    awk -F'|' '{ip[$2]++; paths[$2][$1]=1} END {for(i in ip) {p=0; for(x in paths[i]) p++; print ip[i], p, i}}' \
        "$TMPFILE" | sort -rn | head -30 | while read -r hits paths ip; do
        printf "  ${YELLOW}%-8s${RESET} %-8s %s\n" "$hits" "$paths" "$ip"
    done

    echo ""
fi

# ─────────────────────────────────────────────
# Report 3: Attack categories
# ─────────────────────────────────────────────
echo -e "${BOLD}──────────────────────────────────────────────────────${RESET}"
echo -e "${BOLD}  ATTACK CATEGORIES${RESET}"
echo -e "${BOLD}──────────────────────────────────────────────────────${RESET}"

cut -d'|' -f1 "$TMPFILE" | awk '
{
    path = $0
    if (path ~ /wp-login/) cat["WP Login Brute Force"]++
    else if (path ~ /xmlrpc/) cat["XML-RPC Abuse"]++
    else if (path ~ /wp-config/) cat["Config File Exposure"]++
    else if (path ~ /wp-content\/uploads\/.*\.php/) cat["Webshell in Uploads"]++
    else if (path ~ /wp-content\/plugins\//) cat["Plugin Exploits"]++
    else if (path ~ /wp-content\/themes\//) cat["Theme Exploits"]++
    else if (path ~ /wp-includes\//) cat["Core File Probing"]++
    else if (path ~ /eval-stdin|shell|c99|r57|wso|alfa|b374k|mini\.php/) cat["Known Webshells"]++
    else if (path ~ /phpinfo|php-info|info\.php/) cat["PHP Info Discovery"]++
    else if (path ~ /phpmyadmin|pma|myadmin|dbadmin|mysql/) cat["DB Admin Probing"]++
    else if (path ~ /\.env|\.git|\.svn/) cat["Sensitive File Discovery"]++
    else if (path ~ /setup|install|config/) cat["Setup/Install Probing"]++
    else if (path ~ /vendor\//) cat["Composer/Vendor Exploits"]++
    else cat["Other/Unknown"]++
}
END {
    for (c in cat) printf "%d|%s\n", cat[c], c
}' | sort -t'|' -k1 -rn | while IFS='|' read -r hits category; do
    printf "  ${YELLOW}%-8s${RESET} %s\n" "$hits" "$category"
done

echo ""

# ─────────────────────────────────────────────
# Export tripwire list
# ─────────────────────────────────────────────
if [[ -n "$OUTPUT_FILE" ]]; then
    echo -e "${BOLD}──────────────────────────────────────────────────────${RESET}"
    echo -e "${BOLD}  EXPORTING TRIPWIRE LIST${RESET}"
    echo -e "${BOLD}──────────────────────────────────────────────────────${RESET}"

    cut -d'|' -f1 "$TMPFILE" | sort | uniq -c | sort -rn | awk '
    {
        hits = $1
        path = $2

        # Minimum hit threshold
        if (hits < 10) next

        # Skip paths handled by threshold rules
        if (path == "/wp-login.php") next
        if (path == "/xmlrpc.php") next

        # Skip legitimate files that bots request everywhere
        if (path ~ /robots\.txt/) next

        # Only export PHP files
        if (path !~ /\.php$/) next

        # Skip common legitimate endpoints
        if (path == "/api.php") next
        if (path == "/ajax.php") next
        if (path == "/public.php") next
        if (path == "/panel.php") next
        if (path == "/cron.php") next
        if (path == "/rss.php") next
        if (path == "/feed.php") next

        # Skip WordPress admin and core paths (legitimate even when 404)
        if (path ~ /^\/wp-admin\//) next
        if (path ~ /^\/wp-includes\//) next
        if (path ~ /\/wp-admin\//) next

        # Skip real WordPress core files (legitimate even if 404 due to wrong prefix)
        if (path == "/wp-trackback.php" || path ~ /^\/[a-z]{2}\/wp-trackback\.php/) next
        if (path == "/wp-cron.php" || path ~ /^\/[a-z]{2}\/wp-cron\.php/) next
        if (path == "/wp-mail.php" || path ~ /^\/[a-z]{2}\/wp-mail\.php/) next
        if (path == "/wp-comments-post.php" || path ~ /^\/[a-z]{2}\/wp-comments-post\.php/) next
        if (path == "/wp-signup.php" || path ~ /^\/[a-z]{2}\/wp-signup\.php/) next
        if (path == "/wp-activate.php" || path ~ /^\/[a-z]{2}\/wp-activate\.php/) next
        if (path == "/wp-links-opml.php" || path ~ /^\/[a-z]{2}\/wp-links-opml\.php/) next
        if (path == "/wp-blog-header.php" || path ~ /^\/[a-z]{2}\/wp-blog-header\.php/) next
        if (path == "/wp-load.php" || path ~ /^\/[a-z]{2}\/wp-load\.php/) next
        if (path == "/wp-settings.php" || path ~ /^\/[a-z]{2}\/wp-settings\.php/) next
        if (path == "/index.php" || path ~ /^\/[a-z]{2}\/index\.php/) next
        if (path == "/wp-admin/admin-ajax.php") next
        if (path == "/wp-admin/admin-post.php") next

        print path
    }' > "$OUTPUT_FILE"

    TRIPWIRE_COUNT=$(wc -l < "$OUTPUT_FILE")
    echo -e "  Exported ${GREEN}${TRIPWIRE_COUNT}${RESET} tripwire paths to: ${CYAN}${OUTPUT_FILE}${RESET}"
    echo ""
fi

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
UNIQUE_PATHS=$(cut -d'|' -f1 "$TMPFILE" | sort -u | wc -l)
UNIQUE_IPS=$(cut -d'|' -f2 "$TMPFILE" | sort -u | wc -l)

echo -e "${BOLD}══════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  SUMMARY${RESET}"
echo -e "${BOLD}══════════════════════════════════════════════════════${RESET}"
echo -e "  Total suspicious requests: ${YELLOW}${TOTAL_HITS}${RESET}"
echo -e "  Unique paths probed:       ${YELLOW}${UNIQUE_PATHS}${RESET}"
echo -e "  Unique scanning IPs:       ${YELLOW}${UNIQUE_IPS}${RESET}"
echo -e "${BOLD}══════════════════════════════════════════════════════${RESET}"
echo ""
echo "Next steps:"
echo "  1. Review the paths — remove any false positives"
echo "  2. Export:  $0 -o /opt/wp-guardian/tripwires.txt"
echo "  3. Import:  python3 /opt/wp-guardian/wp-guardian.py --import-tripwires /opt/wp-guardian/tripwires.txt"
echo ""
