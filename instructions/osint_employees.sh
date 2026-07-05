#!/bin/bash
# =============================================================================
# OSINT Employees — gather employee names + email patterns for spray prep
#
# Pipeline:
#   1. theHarvester    — emails + names from search engines + CT logs
#   2. (opt) CrossLinked — LinkedIn employee names via Google/Bing dorks
#   3. username-anarchy — expand "First Last" into 32+ username permutations
#   4. (opt) pydictor --extend — personal-style password candidates from names
#
# Defaults are designed to stay OSINT-only (no LinkedIn auth, no shodan/censys
# API keys, no aggressive probing). LinkedIn search is opt-in.
#
# Usage:
#   tools/osint_employees.sh <target.com>
#   tools/osint_employees.sh <target.com> --company "Acme Corp" --with-linkedin
#   tools/osint_employees.sh <target.com> --sources bing,duckduckgo,crtsh --limit 200
# =============================================================================

set -euo pipefail

TARGET=""
COMPANY=""
SOURCES="duckduckgo,brave,yahoo,mojeek,crtsh,certspotter,hackertarget,otx"
LIMIT=500
WITH_LINKEDIN=false
WITH_SOCIAL=false
EMAIL_FORMAT='{first}.{last}'

while [[ $# -gt 0 ]]; do
    case "$1" in
        --company)              COMPANY="$2"; shift 2 ;;
        --sources)              SOURCES="$2"; shift 2 ;;
        --limit)                LIMIT="$2"; shift 2 ;;
        --email-format)         EMAIL_FORMAT="$2"; shift 2 ;;
        --with-linkedin)        WITH_LINKEDIN=true; shift ;;
        --with-pydictor-social) WITH_SOCIAL=true; shift ;;
        -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) echo "Unknown flag: $1" >&2; exit 1 ;;
        *) [ -z "$TARGET" ] && TARGET="$1" || { echo "Unexpected arg: $1" >&2; exit 1; }; shift ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target.com> [--company \"Acme Corp\"] [--with-linkedin]" >&2
    exit 1
fi

# Default company name = capitalize first label of domain (e.g., twilio.com -> Twilio)
if [ -z "$COMPANY" ]; then
    COMPANY="$(echo "$TARGET" | sed -E 's/^(www\.)?([^.]+)\..*/\2/' | awk '{print toupper(substr($0,1,1)) substr($0,2)}')"
fi

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1"; }

_have() { command -v "$1" >/dev/null 2>&1; }

EXT_DIR="${HOME}/.local/share/bug-bounty/credential-attack"

# Dependency check
MISSING=()
_have theHarvester || MISSING+=("theHarvester")
[ -f "$EXT_DIR/username-anarchy/username-anarchy" ] || MISSING+=("username-anarchy")
if [ "$WITH_LINKEDIN" = true ]; then
    _have crosslinked || MISSING+=("CrossLinked (run: pipx install crosslinked)")
fi
if [ "$WITH_SOCIAL" = true ]; then
    [ -f "$EXT_DIR/pydictor/pydictor.py" ] || MISSING+=("pydictor")
fi
if [ ${#MISSING[@]} -gt 0 ]; then
    log_err "Missing tools: ${MISSING[*]}"
    log_err "Install: ./install_tools.sh --with-credential-attack"
    exit 1
fi

OUT_DIR="recon/${TARGET}/osint"
mkdir -p "$OUT_DIR"
HARVESTER_OUT="$OUT_DIR/theharvester"
EMAILS="$OUT_DIR/emails.txt"
NAMES="$OUT_DIR/employee-names.txt"
USERNAMES="$OUT_DIR/usernames.txt"
PERSONAL_PW="$OUT_DIR/personal-passwords.txt"

echo ""
echo "============================================="
echo "  OSINT Employees — $TARGET"
echo "============================================="
echo "  Company:     $COMPANY"
echo "  Sources:     $SOURCES"
echo "  LinkedIn:    $WITH_LINKEDIN"
echo "  Social PWs:  $WITH_SOCIAL"
echo "============================================="

# Step 1: theHarvester (writes JSON to cwd, so we cd into OUT_DIR first)
log_ok "Step 1: theHarvester (limit=$LIMIT, sources=$SOURCES)"
HARVESTER_BASENAME="theharvester"
if ! (cd "$OUT_DIR" && theHarvester -d "$TARGET" -b "$SOURCES" -l "$LIMIT" -q -f "$HARVESTER_BASENAME") >/dev/null 2>&1; then
    log_warn "theHarvester exited non-zero (some sources may have rate-limited)"
fi

HARVESTER_JSON="$OUT_DIR/${HARVESTER_BASENAME}.json"
if [ -f "$HARVESTER_JSON" ]; then
    python3 -c "
import json
with open('$HARVESTER_JSON') as f:
    data = json.load(f)
for email in data.get('emails', []):
    print(email)
" | sort -u > "$EMAILS"
    EMAIL_COUNT=$(wc -l < "$EMAILS" | tr -d ' ')
    log_ok "Found $EMAIL_COUNT unique emails -> $EMAILS"
else
    log_warn "No theHarvester JSON output found"
    : > "$EMAILS"
    EMAIL_COUNT=0
fi

# Step 2: derive names from email local-parts
# Heuristic: john.smith@x → "John Smith"; jsmith@x → skip (ambiguous)
log_ok "Step 2: deriving names from email local-parts"
: > "$NAMES"
if [ -s "$EMAILS" ]; then
    awk -F@ '{print $1}' "$EMAILS" \
        | { grep -E '^[a-z]+[._-][a-z]+$' || true; } \
        | tr '._-' '  ' \
        | awk '{print toupper(substr($1,1,1)) substr($1,2), toupper(substr($2,1,1)) substr($2,2)}' \
        | sort -u > "$NAMES"
fi
NAME_COUNT_BEFORE=$(wc -l < "$NAMES" | tr -d ' ')
log_ok "Derived $NAME_COUNT_BEFORE names from email patterns"

# Step 3 (opt): CrossLinked for LinkedIn employees
if [ "$WITH_LINKEDIN" = true ]; then
    log_ok "Step 3: CrossLinked LinkedIn search for '$COMPANY'"
    CL_OUT="$OUT_DIR/crosslinked_names"
    if crosslinked \
            -f '{first} {last}' \
            -o "$CL_OUT" \
            "$COMPANY" 2>&1 | tail -5; then
        if [ -f "${CL_OUT}.txt" ]; then
            # Merge with email-derived names
            cat "${CL_OUT}.txt" "$NAMES" | sort -u > "${NAMES}.tmp" && mv "${NAMES}.tmp" "$NAMES"
            NAME_COUNT_AFTER=$(wc -l < "$NAMES" | tr -d ' ')
            log_ok "After LinkedIn merge: $NAME_COUNT_AFTER names (+$((NAME_COUNT_AFTER - NAME_COUNT_BEFORE)))"
        else
            log_warn "CrossLinked produced no output file"
        fi
    else
        log_warn "CrossLinked search failed (Google may have rate-limited)"
    fi
fi

# Step 4: username-anarchy expansion
if [ -s "$NAMES" ]; then
    log_ok "Step 4: username-anarchy permutations"
    "$EXT_DIR/username-anarchy/username-anarchy" -i "$NAMES" 2>/dev/null \
        | sort -u > "$USERNAMES"
    USERNAME_COUNT=$(wc -l < "$USERNAMES" | tr -d ' ')
    log_ok "Generated $USERNAME_COUNT username permutations -> $USERNAMES"
else
    log_warn "No names available; skipping username expansion"
    : > "$USERNAMES"
    USERNAME_COUNT=0
fi

# Step 5 (opt): pydictor personal-password candidates
if [ "$WITH_SOCIAL" = true ] && [ -s "$NAMES" ]; then
    log_ok "Step 5: pydictor personal-password candidates"
    # Use first-name list as base, --extend adds common variations (year, !, 123)
    awk '{print tolower($1)}' "$NAMES" | sort -u > "$OUT_DIR/firstnames-lower.txt"
    if python3 "$EXT_DIR/pydictor/pydictor.py" \
            -extend "$OUT_DIR/firstnames-lower.txt" \
            --level 3 \
            -o "$OUT_DIR/pydictor_raw" >/dev/null 2>&1; then
        # pydictor outputs to a directory; flatten
        find "$OUT_DIR/pydictor_raw" -type f -name "*.txt" -exec cat {} \; \
            | sort -u > "$PERSONAL_PW"
        PW_COUNT=$(wc -l < "$PERSONAL_PW" | tr -d ' ')
        log_ok "Generated $PW_COUNT personal-style passwords -> $PERSONAL_PW"
        rm -rf "$OUT_DIR/pydictor_raw" "$OUT_DIR/firstnames-lower.txt"
    else
        log_warn "pydictor extend failed"
    fi
fi

# Summary
echo ""
echo "============================================="
echo "  Summary"
echo "============================================="
printf "  %-12s %s\n" "Target:" "$TARGET"
printf "  %-12s %d emails        %s\n" "Emails:" "$EMAIL_COUNT" "$EMAILS"
printf "  %-12s %d names         %s\n" "Names:" "$(wc -l < "$NAMES" | tr -d ' ')" "$NAMES"
printf "  %-12s %d permutations  %s\n" "Usernames:" "$USERNAME_COUNT" "$USERNAMES"
if [ "$WITH_SOCIAL" = true ] && [ -f "$PERSONAL_PW" ]; then
    printf "  %-12s %d candidates   %s\n" "Personal PW:" "$(wc -l < "$PERSONAL_PW" | tr -d ' ')" "$PERSONAL_PW"
fi
echo ""
echo "  Next steps:"
echo "    - Manually review $NAMES — drop obvious false positives"
echo "    - Combine with /wordlist-gen output for spray (PR #5):"
echo "        cat $USERNAMES > users.txt"
echo "        cat recon/${TARGET}/wordlists/ranked.txt $PERSONAL_PW > passes.txt"
echo "============================================="
