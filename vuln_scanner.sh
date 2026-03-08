#!/bin/bash
# =============================================================================
# Vulnerability Scanner
# Automated vulnerability checks against recon results
# Usage: ./vuln_scanner.sh <recon_dir> [--quick]
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_ok()    { echo -e "${GREEN}[+]${NC} $1"; }
log_err()   { echo -e "${RED}[-]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_info()  { echo -e "${CYAN}[*]${NC} $1"; }
log_step()  { echo -e "    ${CYAN}[>]${NC} $1"; }
log_done()  { echo -e "    ${GREEN}[✓]${NC} $1"; }
log_vuln()  { echo -e "    ${RED}[VULN]${NC} $1"; }

RECON_DIR="${1:?Usage: $0 <recon_dir> [--quick]}"
QUICK_MODE="${2:-}"

if [ ! -d "$RECON_DIR" ]; then
    log_err "Recon directory not found: $RECON_DIR"
    exit 1
fi

# Determine target name from recon dir
TARGET=$(basename "$RECON_DIR")
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FINDINGS_DIR="$BASE_DIR/findings/$TARGET"
THREADS=10
RATE_LIMIT=20  # Conservative default to avoid WAF blocks (429/403)

mkdir -p "$FINDINGS_DIR"/{xss,takeover,misconfig,exposure,ssrf,cves,redirects,manual_review}

echo "============================================="
echo "  Vulnerability Scanner — $TARGET"
echo "  Recon: $RECON_DIR"
echo "  Findings: $FINDINGS_DIR"
echo "  Mode: $([ "$QUICK_MODE" = "--quick" ] && echo "Quick" || echo "Full")"
echo "============================================="
echo ""

# Helper: count findings
count_findings() {
    local file="$1"
    if [ -f "$file" ] && [ -s "$file" ]; then
        wc -l < "$file" | tr -d ' '
    else
        echo "0"
    fi
}

# Collect live URLs for scanning
LIVE_URLS="$RECON_DIR/live/urls.txt"
PARAM_URLS="$RECON_DIR/urls/with_params.txt"
ALL_URLS="$RECON_DIR/urls/all.txt"

if [ ! -s "$LIVE_URLS" ] 2>/dev/null; then
    log_warn "No live URLs found. Checking alternative locations..."
    if [ -s "$RECON_DIR/live/httpx_full.txt" ]; then
        awk '{print $1}' "$RECON_DIR/live/httpx_full.txt" > "$LIVE_URLS"
    else
        log_err "No live hosts data found in recon. Run recon_engine.sh first."
        exit 1
    fi
fi

LIVE_COUNT=$(wc -l < "$LIVE_URLS" 2>/dev/null || echo 0)
log_info "Scanning $LIVE_COUNT live hosts"

# ============================================================
# Check 1: XSS (Cross-Site Scripting)
# ============================================================
log_info "Check 1: XSS Detection"

# Dalfox — automated XSS scanner
if command -v dalfox &>/dev/null && [ -s "$PARAM_URLS" ]; then
    log_step "Running dalfox on parameterized URLs..."
    # Feed URLs with params to dalfox
    head -100 "$PARAM_URLS" | dalfox pipe \
        --silence \
        --no-color \
        --worker 5 \
        --delay 100 \
        --timeout 10 \
        --output "$FINDINGS_DIR/xss/dalfox_results.txt" 2>/dev/null || true

    DALFOX_COUNT=$(count_findings "$FINDINGS_DIR/xss/dalfox_results.txt")
    [ "$DALFOX_COUNT" -gt 0 ] && log_vuln "Dalfox found $DALFOX_COUNT potential XSS" || log_done "Dalfox: no XSS found"
fi

# Nuclei XSS templates
if command -v nuclei &>/dev/null; then
    log_step "Running nuclei XSS templates..."
    cat "$LIVE_URLS" | nuclei \
        -tags xss \
        -severity low,medium,high,critical \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        -concurrency "$THREADS" \
        -output "$FINDINGS_DIR/xss/nuclei_xss.txt" 2>/dev/null || true

    NUCLEI_XSS=$(count_findings "$FINDINGS_DIR/xss/nuclei_xss.txt")
    [ "$NUCLEI_XSS" -gt 0 ] && log_vuln "Nuclei found $NUCLEI_XSS XSS issues" || log_done "Nuclei XSS: clean"
fi

# ============================================================
# Check 2: Subdomain Takeover
# ============================================================
echo ""
log_info "Check 2: Subdomain Takeover"

SUBDOMAINS="$RECON_DIR/subdomains/all.txt"

# Subjack
if command -v subjack &>/dev/null && [ -s "$SUBDOMAINS" ]; then
    log_step "Running subjack..."
    subjack -w "$SUBDOMAINS" \
        -t "$THREADS" \
        -timeout 30 \
        -ssl \
        -o "$FINDINGS_DIR/takeover/subjack_results.txt" 2>/dev/null || true

    SUBJACK_COUNT=$(count_findings "$FINDINGS_DIR/takeover/subjack_results.txt")
    [ "$SUBJACK_COUNT" -gt 0 ] && log_vuln "Subjack found $SUBJACK_COUNT potential takeovers" || log_done "Subjack: no takeovers"
fi

# Nuclei takeover templates
if command -v nuclei &>/dev/null && [ -s "$LIVE_URLS" ]; then
    log_step "Running nuclei takeover templates..."
    cat "$LIVE_URLS" | nuclei \
        -tags takeover \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        -output "$FINDINGS_DIR/takeover/nuclei_takeover.txt" 2>/dev/null || true

    NUCLEI_TK=$(count_findings "$FINDINGS_DIR/takeover/nuclei_takeover.txt")
    [ "$NUCLEI_TK" -gt 0 ] && log_vuln "Nuclei found $NUCLEI_TK takeover issues" || log_done "Nuclei takeover: clean"
fi

# ============================================================
# Check 3: Misconfigurations
# ============================================================
echo ""
log_info "Check 3: Misconfigurations"

if command -v nuclei &>/dev/null && [ -s "$LIVE_URLS" ]; then
    # CORS misconfigurations
    log_step "Checking CORS misconfigurations..."
    cat "$LIVE_URLS" | nuclei \
        -tags cors \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        -output "$FINDINGS_DIR/misconfig/cors.txt" 2>/dev/null || true
    CORS_COUNT=$(count_findings "$FINDINGS_DIR/misconfig/cors.txt")
    [ "$CORS_COUNT" -gt 0 ] && log_vuln "CORS misconfigs: $CORS_COUNT" || log_done "CORS: clean"

    # Security headers
    log_step "Checking security headers..."
    cat "$LIVE_URLS" | nuclei \
        -tags headers,missing-headers \
        -severity medium,high,critical \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        -output "$FINDINGS_DIR/misconfig/headers.txt" 2>/dev/null || true
    HDR_COUNT=$(count_findings "$FINDINGS_DIR/misconfig/headers.txt")
    [ "$HDR_COUNT" -gt 0 ] && log_vuln "Header issues: $HDR_COUNT" || log_done "Headers: clean"

    # General misconfigurations
    log_step "Running misconfiguration templates..."
    cat "$LIVE_URLS" | nuclei \
        -tags misconfig \
        -severity medium,high,critical \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        -output "$FINDINGS_DIR/misconfig/general.txt" 2>/dev/null || true
    MISC_COUNT=$(count_findings "$FINDINGS_DIR/misconfig/general.txt")
    [ "$MISC_COUNT" -gt 0 ] && log_vuln "Misconfigs: $MISC_COUNT" || log_done "General misconfig: clean"
fi

# ============================================================
# Check 4: Sensitive Data Exposure
# ============================================================
echo ""
log_info "Check 4: Sensitive Data Exposure"

if command -v nuclei &>/dev/null && [ -s "$LIVE_URLS" ]; then
    # Exposed files (.git, .env, backups, etc.)
    log_step "Checking for exposed files (.git, .env, backups)..."
    cat "$LIVE_URLS" | nuclei \
        -tags exposure,file \
        -severity low,medium,high,critical \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        -output "$FINDINGS_DIR/exposure/exposed_files.txt" 2>/dev/null || true
    EXP_COUNT=$(count_findings "$FINDINGS_DIR/exposure/exposed_files.txt")
    [ "$EXP_COUNT" -gt 0 ] && log_vuln "Exposed files: $EXP_COUNT" || log_done "Exposed files: clean"

    # Exposed panels (admin, debug, etc.)
    log_step "Checking for exposed panels..."
    cat "$LIVE_URLS" | nuclei \
        -tags panel,login \
        -severity medium,high,critical \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        -output "$FINDINGS_DIR/exposure/panels.txt" 2>/dev/null || true
    PANEL_COUNT=$(count_findings "$FINDINGS_DIR/exposure/panels.txt")
    [ "$PANEL_COUNT" -gt 0 ] && log_vuln "Exposed panels: $PANEL_COUNT" || log_done "Panels: clean"

    # Technology detection & default credentials
    log_step "Checking for default credentials..."
    cat "$LIVE_URLS" | nuclei \
        -tags default-login \
        -severity high,critical \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        -output "$FINDINGS_DIR/exposure/default_creds.txt" 2>/dev/null || true
    CRED_COUNT=$(count_findings "$FINDINGS_DIR/exposure/default_creds.txt")
    [ "$CRED_COUNT" -gt 0 ] && log_vuln "Default creds: $CRED_COUNT" || log_done "Default creds: clean"
fi

# Manual check: sensitive paths from recon
if [ -s "$RECON_DIR/urls/sensitive_paths.txt" ]; then
    log_step "Verifying sensitive paths from recon..."
    while IFS= read -r url; do
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")
        if [ "$STATUS" = "200" ]; then
            echo "$STATUS $url" >> "$FINDINGS_DIR/exposure/verified_sensitive.txt"
        fi
    done < <(head -50 "$RECON_DIR/urls/sensitive_paths.txt")

    VERIFIED=$(count_findings "$FINDINGS_DIR/exposure/verified_sensitive.txt")
    [ "$VERIFIED" -gt 0 ] && log_vuln "Verified sensitive paths: $VERIFIED" || log_done "Sensitive paths: clean"
fi

# ============================================================
# Check 5: SSRF (Server-Side Request Forgery)
# ============================================================
echo ""
log_info "Check 5: SSRF Detection"

if command -v nuclei &>/dev/null && [ -s "$LIVE_URLS" ]; then
    log_step "Running nuclei SSRF templates..."
    cat "$LIVE_URLS" | nuclei \
        -tags ssrf \
        -severity medium,high,critical \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        -output "$FINDINGS_DIR/ssrf/nuclei_ssrf.txt" 2>/dev/null || true
    SSRF_COUNT=$(count_findings "$FINDINGS_DIR/ssrf/nuclei_ssrf.txt")
    [ "$SSRF_COUNT" -gt 0 ] && log_vuln "SSRF issues: $SSRF_COUNT" || log_done "SSRF: clean"
fi

# Flag URL parameters for manual SSRF testing
if [ -s "$RECON_DIR/params/interesting_params.txt" ]; then
    grep -iE '(url|redirect|dest|uri|path|file|doc|load|link|src|source|target|callback|domain|site|feed|rurl|return|next)' \
        "$RECON_DIR/params/interesting_params.txt" > "$FINDINGS_DIR/ssrf/ssrf_params_manual.txt" 2>/dev/null || true
    MANUAL_SSRF=$(count_findings "$FINDINGS_DIR/ssrf/ssrf_params_manual.txt")
    [ "$MANUAL_SSRF" -gt 0 ] && log_warn "Params for manual SSRF testing: $MANUAL_SSRF"
fi

# ============================================================
# Check 6: CVE Detection
# ============================================================
echo ""
log_info "Check 6: Known CVEs"

if command -v nuclei &>/dev/null && [ -s "$LIVE_URLS" ]; then
    log_step "Running nuclei CVE templates..."
    cat "$LIVE_URLS" | nuclei \
        -tags cve \
        -severity medium,high,critical \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        -concurrency "$THREADS" \
        -output "$FINDINGS_DIR/cves/nuclei_cves.txt" 2>/dev/null || true
    CVE_COUNT=$(count_findings "$FINDINGS_DIR/cves/nuclei_cves.txt")
    [ "$CVE_COUNT" -gt 0 ] && log_vuln "CVEs found: $CVE_COUNT" || log_done "CVEs: clean"
fi

# ============================================================
# Check 7: Open Redirects
# ============================================================
echo ""
log_info "Check 7: Open Redirects"

if command -v nuclei &>/dev/null && [ -s "$LIVE_URLS" ]; then
    log_step "Running nuclei redirect templates..."
    cat "$LIVE_URLS" | nuclei \
        -tags redirect \
        -severity low,medium,high \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        -output "$FINDINGS_DIR/redirects/nuclei_redirects.txt" 2>/dev/null || true
    REDIR_COUNT=$(count_findings "$FINDINGS_DIR/redirects/nuclei_redirects.txt")
    [ "$REDIR_COUNT" -gt 0 ] && log_vuln "Open redirects: $REDIR_COUNT" || log_done "Redirects: clean"
fi

# Flag redirect parameters for manual testing
if [ -s "$RECON_DIR/params/interesting_params.txt" ]; then
    grep -iE '(redirect|return|next|url|callback|goto|continue|dest|rurl|return_to|out)' \
        "$RECON_DIR/params/interesting_params.txt" > "$FINDINGS_DIR/redirects/redirect_params_manual.txt" 2>/dev/null || true
    MANUAL_REDIR=$(count_findings "$FINDINGS_DIR/redirects/redirect_params_manual.txt")
    [ "$MANUAL_REDIR" -gt 0 ] && log_warn "Params for manual redirect testing: $MANUAL_REDIR"
fi

# ============================================================
# Check 8: IDOR / Auth Bypass / Business Logic
# ============================================================
echo ""
log_info "Check 8: IDOR / Auth Bypass / Business Logic"

mkdir -p "$FINDINGS_DIR/idor"
mkdir -p "$FINDINGS_DIR/auth_bypass"

# 8a: Check for IDOR-prone parameters in collected URLs
if [ -s "$PARAM_URLS" ]; then
    log_step "Flagging IDOR-prone parameters..."
    grep -iE '[?&](id|user_id|uid|account|profile|order|order_id|invoice|doc|file_id|report|ticket|msg|message_id|comment_id|item|product_id|cart|session|ref|record)=' \
        "$PARAM_URLS" > "$FINDINGS_DIR/idor/idor_candidates.txt" 2>/dev/null || true
    IDOR_COUNT=$(count_findings "$FINDINGS_DIR/idor/idor_candidates.txt")
    [ "$IDOR_COUNT" -gt 0 ] && log_warn "IDOR candidate URLs: $IDOR_COUNT (manual testing required)" || log_done "IDOR params: none found"
fi

# 8b: Check for numeric/sequential IDs in API endpoints
if [ -s "$RECON_DIR/urls/api_endpoints.txt" ]; then
    log_step "Checking API endpoints for sequential IDs..."
    grep -E '/[0-9]{1,8}(/|$|\?)' "$RECON_DIR/urls/api_endpoints.txt" \
        > "$FINDINGS_DIR/idor/api_sequential_ids.txt" 2>/dev/null || true
    SEQ_COUNT=$(count_findings "$FINDINGS_DIR/idor/api_sequential_ids.txt")
    [ "$SEQ_COUNT" -gt 0 ] && log_warn "API endpoints with sequential IDs: $SEQ_COUNT" || log_done "Sequential IDs: none"
fi

# 8c: Auth bypass checks — test unauthenticated access to API endpoints
if [ -s "$RECON_DIR/urls/api_endpoints.txt" ]; then
    log_step "Testing API endpoints for unauthenticated access..."
    while IFS= read -r api_url; do
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$api_url" 2>/dev/null || echo "000")
        BODY_SIZE=$(curl -s --max-time 5 "$api_url" 2>/dev/null | wc -c | tr -d ' ')
        # Flag endpoints returning 200 with substantial body (not just error pages)
        if [ "$STATUS" = "200" ] && [ "$BODY_SIZE" -gt 500 ]; then
            echo "$STATUS $BODY_SIZE $api_url" >> "$FINDINGS_DIR/auth_bypass/unauth_api_access.txt"
        fi
    done < <(head -30 "$RECON_DIR/urls/api_endpoints.txt")
    UNAUTH_COUNT=$(count_findings "$FINDINGS_DIR/auth_bypass/unauth_api_access.txt")
    [ "$UNAUTH_COUNT" -gt 0 ] && log_vuln "Unauthenticated API access: $UNAUTH_COUNT" || log_done "Auth bypass: clean"
fi

# 8d: Exposed config files (env.js, app_env.js)
if [ -s "$RECON_DIR/exposure/config_files.txt" ] 2>/dev/null; then
    cp "$RECON_DIR/exposure/config_files.txt" "$FINDINGS_DIR/exposure/config_files.txt" 2>/dev/null || true
    CFG_COUNT=$(count_findings "$FINDINGS_DIR/exposure/config_files.txt")
    [ "$CFG_COUNT" -gt 0 ] && log_vuln "Exposed config files from recon: $CFG_COUNT"
fi

# 8e: HTTP method tampering (PUT/DELETE on endpoints that should only accept GET/POST)
if [ -s "$LIVE_URLS" ]; then
    log_step "Testing HTTP method tampering on sample endpoints..."
    while IFS= read -r url; do
        for METHOD in PUT DELETE PATCH; do
            STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X "$METHOD" --max-time 5 "$url" 2>/dev/null || echo "000")
            if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ] || [ "$STATUS" = "204" ]; then
                echo "$METHOD $STATUS $url" >> "$FINDINGS_DIR/auth_bypass/method_tampering.txt"
            fi
        done
    done < <(head -10 "$LIVE_URLS")
    METHOD_COUNT=$(count_findings "$FINDINGS_DIR/auth_bypass/method_tampering.txt")
    [ "$METHOD_COUNT" -gt 0 ] && log_warn "Method tampering findings: $METHOD_COUNT (manual verification needed)" || log_done "Method tampering: clean"
fi

# ============================================================
# Consolidate Findings
# ============================================================
echo ""
log_info "Consolidating findings..."

# Merge all findings into summary
TOTAL_FINDINGS=0
FINDING_SUMMARY="$FINDINGS_DIR/summary.txt"

{
    echo "============================================="
    echo "  Vulnerability Scan Summary — $TARGET"
    echo "  Scan Date: $(date)"
    echo "  Recon Data: $RECON_DIR"
    echo "============================================="
    echo ""

    for category in xss takeover misconfig exposure ssrf cves redirects idor auth_bypass; do
        CAT_TOTAL=0
        echo "--- $category ---"
        for file in "$FINDINGS_DIR/$category/"*.txt; do
            if [ -f "$file" ] && [ -s "$file" ]; then
                COUNT=$(wc -l < "$file" | tr -d ' ')
                CAT_TOTAL=$((CAT_TOTAL + COUNT))
                echo "  $(basename "$file"): $COUNT findings"
            fi
        done
        echo "  Category total: $CAT_TOTAL"
        TOTAL_FINDINGS=$((TOTAL_FINDINGS + CAT_TOTAL))
        echo ""
    done

    echo "============================================="
    echo "  TOTAL FINDINGS: $TOTAL_FINDINGS"
    echo "============================================="
    echo ""
    echo "  Items requiring manual review:"
    for file in "$FINDINGS_DIR"/*/manual*.txt "$FINDINGS_DIR/manual_review/"*.txt; do
        [ -f "$file" ] && [ -s "$file" ] && echo "    - $file ($(wc -l < "$file" | tr -d ' ') items)"
    done
} > "$FINDING_SUMMARY"

cat "$FINDING_SUMMARY"

echo ""
echo "  All findings saved to: $FINDINGS_DIR/"
echo ""
echo "  Next: Generate reports"
echo "    python3 tools/report_generator.py $FINDINGS_DIR"
echo "============================================="
