#!/bin/bash
# =============================================================================
# Wordlist Engine — company-specific password wordlist generator
#
# Pipeline: cewler (crawl) -> dedup/clean -> hashcat rules (mutate) -> ranked
#
# Why not pydictor in this script: pydictor shines with social/OSINT inputs
# (birthdays, employee names, internal project codes). With only website-crawled
# words it overlaps hashcat rules. PR #3 will wire pydictor into the OSINT path.
#
# Usage:
#   tools/wordlist_engine.sh <target>
#   tools/wordlist_engine.sh <target> --depth 3 --mode aggressive
#   tools/wordlist_engine.sh <target> --filter loose   # keep noisy raw tokens
#
# Modes (rule set):
#   minimal      top10_2025.rule       ~10 rules  — fastest, for cautious spray
#   balanced     best66.rule           ~66 rules  — default
#   aggressive   OneRuleToRuleThemAll  52k rules  — offline cracking, NOT spray
#
# Filter (Step 2 cleanup, default strict):
#   strict   alphanum-only, max 14 chars, drops random-looking 10+ char tokens.
#            Designed for API-heavy sites (Twilio, Stripe) where docs leak
#            example tokens / CSS selectors / URL slugs as raw "words".
#   loose    only length + printable-ASCII filter (cewler's raw output minus
#            obvious garbage).
# =============================================================================

set -euo pipefail

DEPTH=2
MIN_LEN=5
MAX_LEN=14
MODE="balanced"
FILTER="strict"
RATE=5
USER_AGENT="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Bug-Bounty-Research"
TARGET=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --depth)   DEPTH="$2"; shift 2 ;;
        --min-len) MIN_LEN="$2"; shift 2 ;;
        --max-len) MAX_LEN="$2"; shift 2 ;;
        --mode)    MODE="$2"; shift 2 ;;
        --filter)  FILTER="$2"; shift 2 ;;
        --rate)    RATE="$2"; shift 2 ;;
        -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) echo "Unknown flag: $1" >&2; exit 1 ;;
        *) [ -z "$TARGET" ] && TARGET="$1" || { echo "Unexpected arg: $1" >&2; exit 1; }; shift ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target> [--depth N] [--mode minimal|balanced|aggressive] [--filter strict|loose]" >&2
    exit 1
fi

if [ "$FILTER" != "strict" ] && [ "$FILTER" != "loose" ]; then
    echo "Unknown filter: $FILTER (use: strict|loose)" >&2
    exit 1
fi

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

_have() { command -v "$1" >/dev/null 2>&1; }

# Dependency check
MISSING=()
_have cewler  || MISSING+=("cewler")
_have hashcat || MISSING+=("hashcat")
if [ ${#MISSING[@]} -gt 0 ]; then
    log_err "Missing tools: ${MISSING[*]}"
    log_err "Install: ./install_tools.sh --with-credential-attack"
    exit 1
fi

# Resolve hashcat rules dir (brew install layout)
HASHCAT_PREFIX="$(brew --prefix hashcat 2>/dev/null || true)"
HASHCAT_RULES_DIR="${HASHCAT_PREFIX}/share/doc/hashcat/rules"
EXT_DIR="${HOME}/.local/share/bug-bounty/credential-attack"

case "$MODE" in
    minimal)    RULE_FILE="$HASHCAT_RULES_DIR/top10_2025.rule" ;;
    balanced)   RULE_FILE="$HASHCAT_RULES_DIR/best66.rule" ;;
    aggressive) RULE_FILE="$EXT_DIR/rules/OneRuleToRuleThemAll.rule" ;;
    *) log_err "Unknown mode: $MODE (use: minimal|balanced|aggressive)"; exit 1 ;;
esac

if [ ! -f "$RULE_FILE" ]; then
    log_err "Rule file not found: $RULE_FILE"
    log_err "Check: ls $HASHCAT_RULES_DIR  (and $EXT_DIR/rules for aggressive mode)"
    exit 1
fi

# Output layout — fits existing recon/<target>/ convention
OUT_DIR="recon/${TARGET}/wordlists"
mkdir -p "$OUT_DIR"
RAW="$OUT_DIR/from-website.txt"
CLEAN="$OUT_DIR/cleaned.txt"
RANKED="$OUT_DIR/ranked.txt"

echo ""
echo "============================================="
echo "  Wordlist Engine — $TARGET ($MODE mode)"
echo "============================================="

# Step 1: cewler crawl
log_ok "Step 1/3: crawling https://${TARGET}"
echo "    depth=$DEPTH min-len=$MIN_LEN rate=${RATE}/s"
echo "    output -> $RAW"
if ! cewler "https://${TARGET}" \
        -d "$DEPTH" \
        -m "$MIN_LEN" \
        -l \
        -r "$RATE" \
        -u "$USER_AGENT" \
        -o "$RAW"; then
    log_warn "cewler exited non-zero (target may have partial content or anti-bot)"
fi

if [ ! -s "$RAW" ]; then
    log_err "cewler produced no output. Check target reachability, JS-heavy SPA, or WAF block."
    exit 1
fi
RAW_COUNT=$(wc -l < "$RAW" | tr -d ' ')
log_ok "Crawled $RAW_COUNT raw words"

# Step 2: dedup + clean
log_ok "Step 2/3: dedup + filter ($FILTER mode, $MIN_LEN-$MAX_LEN chars)"
if [ "$FILTER" = "strict" ]; then
    # Keep only: start with letter, alphanum only, no random-looking 10+char mixed tokens
    # Drops: #hex, CSS selectors, snake_case, URL slugs, raw API key examples, pure digits
    awk -v min="$MIN_LEN" -v max="$MAX_LEN" '
        length($0) >= min && length($0) <= max \
        && /^[a-z][a-z0-9]*$/ \
        && !(length($0) >= 10 && /[0-9]/ && /[a-z]/)
    ' "$RAW" | sort -u > "$CLEAN"
else
    # Loose: just length + printable filter (original behavior, lots of noise on API-doc-heavy sites)
    awk -v min="$MIN_LEN" -v max="$MAX_LEN" \
        'length($0) >= min && length($0) <= max && /^[[:print:]]+$/' \
        "$RAW" | sort -u > "$CLEAN"
fi
CLEAN_COUNT=$(wc -l < "$CLEAN" | tr -d ' ')
log_ok "Cleaned -> $CLEAN_COUNT unique words"

if [ "$CLEAN_COUNT" -lt 5 ]; then
    log_warn "Very few words after cleaning. Consider --min-len $((MIN_LEN - 1)) or --depth $((DEPTH + 1))"
fi

# Step 3: hashcat mutate
log_ok "Step 3/3: applying rules ($(basename "$RULE_FILE"))"
echo "    output -> $RANKED"
hashcat --stdout "$CLEAN" -r "$RULE_FILE" 2>/dev/null \
    | awk -v min="$MIN_LEN" -v max="$MAX_LEN" \
        'length($0) >= min && length($0) <= max' \
    | sort -u > "$RANKED"

RANKED_COUNT=$(wc -l < "$RANKED" | tr -d ' ')
log_ok "Final wordlist: $RANKED_COUNT candidates"

# Summary
echo ""
echo "============================================="
echo "  Summary"
echo "============================================="
printf "  %-12s %s\n" "Target:" "$TARGET"
printf "  %-12s %s (%s)\n" "Mode:" "$MODE" "$(basename "$RULE_FILE")"
printf "  %-12s %d words   %s\n" "Raw:" "$RAW_COUNT" "$RAW"
printf "  %-12s %d words   %s\n" "Cleaned:" "$CLEAN_COUNT" "$CLEAN"
printf "  %-12s %d candidates   %s\n" "Ranked:" "$RANKED_COUNT" "$RANKED"
echo ""
echo "  Next steps:"
echo "    - PR #4 will filter via HIBP k-anonymity (rank by leak prevalence)"
echo "    - Feed straight to spray (after PR #5):"
echo "        trevorspray --passes $RANKED -u <login-url> --delay 1800"
echo "============================================="
