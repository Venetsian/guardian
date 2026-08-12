#!/bin/bash
#
# Fail if a tracked file contains a real-looking email address or public IP.
#
# This repo is PUBLIC. Real client addresses and IPs reached it repeatedly by
# accident, because incident analysis is written up while the real data is
# still on screen — a v1.7.11 test file replayed a genuine false-positive with
# the customer's mailbox and five of their home IP addresses, and v1.7.15 added
# more from a sample log line pasted into a task description. Under GDPR both
# an email address and an IP address are personal data.
#
# Use RFC 2606 reserved domains and RFC 5737 documentation ranges instead:
#
#   emails   alice@example.com   bob@example.net   carol@example.org
#            anything@*.test / *.invalid / *.example / *.localhost
#   IPv4     192.0.2.0/24   198.51.100.0/24   203.0.113.0/24
#
# The *shape* of incident data is what tests and docs need — "5 ASNs inside one
# country", "28 countries / 39 ASNs / 62 IPs". Whose mailbox it was is never
# load-bearing.
#
# Usage:
#   bash tools/check-pii.sh
#
# Install as a pre-commit hook:
#   ln -sf ../../tools/check-pii.sh .git/hooks/pre-commit
#
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

fail=0

# ---------------------------------------------------------------------------
# Email addresses on domains that are not reserved for documentation.
# ---------------------------------------------------------------------------
# Allowlisted: RFC 2606 reserved names, obvious throwaways used in tests, and
# third-party addresses that are already public (a project's security list).
EMAIL_OK='@(example\.(com|net|org)|[a-z0-9.-]+\.(test|invalid|example|localhost)|yourdomain\.com|(a|b|c|x|y|z)\.com|amazonses\.com|lists\.openwall\.com|maiahost\.com)'

emails=$(git ls-files -z \
    | xargs -0 grep -ohE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" 2>/dev/null \
    | sort -u | grep -viE "$EMAIL_OK" || true)

if [ -n "$emails" ]; then
    echo "PII CHECK FAILED — non-reserved email addresses in tracked files:"
    echo "$emails" | sed 's/^/  /'
    echo ""
    echo "  Replace with alice@example.com / bob@example.net / carol@example.org"
    echo "  and re-run. If an address is genuinely safe to publish, add its"
    echo "  domain to EMAIL_OK in this script with a comment saying why."
    echo ""
    fail=1
fi

# ---------------------------------------------------------------------------
# Public IPv4 addresses.
# ---------------------------------------------------------------------------
# Allowlisted: RFC 1918 private, loopback, RFC 5737 documentation, 0/255
# placeholders, single-digit examples, and the published crawler ranges the
# whitelist documentation legitimately cites (Googlebot, Bingbot, Yandex).
IP_OK='^(10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|0\.|255\.|[0-9]\.[0-9]\.[0-9]\.[0-9]+$|8\.8\.8\.8|66\.249\.|64\.233\.|72\.14\.|209\.85\.|40\.77\.|157\.55\.|207\.46\.|5\.255\.|87\.250\.|213\.180\.|34\.|35\.)'

ips=$(git ls-files -z \
    | xargs -0 grep -ohE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" 2>/dev/null \
    | sort -u | grep -vE "$IP_OK" || true)

if [ -n "$ips" ]; then
    echo "PII CHECK FAILED — public IP addresses in tracked files:"
    echo "$ips" | sed 's/^/  /'
    echo ""
    echo "  Replace with 192.0.2.x / 198.51.100.x / 203.0.113.x (RFC 5737)."
    echo "  Crawler ranges cited in whitelist docs belong in IP_OK above."
    echo ""
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PII check passed — no client identifiers in tracked files."
fi

exit "$fail"
