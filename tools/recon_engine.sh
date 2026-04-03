#!/bin/bash
# =============================================================================
# Enhanced Recon Engine
# Full reconnaissance pipeline for bug bounty targets
# Usage: ./recon_engine.sh <target-domain> [--quick]
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

TARGET="${1:?Usage: $0 <target> [--quick]  (target = FQDN, IP, or CIDR)}"
QUICK_MODE="${2:-}"
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RECON_DIR="$BASE_DIR/recon/$TARGET"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
THREADS=20
RATE_LIMIT=50  # requests per second

# ── Detect target type (passed from hunt.py or auto-detected here) ────────────
_detect_target_type() {
    local t="$1"
    if [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then echo "cidr"
    elif [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]];        then echo "ip"
    else echo "domain"; fi
}

_expand_cidr_hosts() {
    local target="$1"
    python3 - "$target" <<'PY'
import ipaddress
import itertools
import sys

network = ipaddress.ip_network(sys.argv[1], strict=False)
hosts = [str(host) for host in itertools.islice(network.hosts(), 254)]
if not hosts:
    hosts = [str(network.network_address)]
print("\n".join(hosts))
PY
}
TARGET_TYPE="${TARGET_TYPE:-$(_detect_target_type "$TARGET")}"

# For IP/CIDR: always scope-lock — no subdomain enum needed
if [ "$TARGET_TYPE" = "ip" ] || [ "$TARGET_TYPE" = "cidr" ]; then
    SCOPE_LOCK=1
fi

mkdir -p "$RECON_DIR"/{subdomains,live,ports,urls,js,dirs,params}

echo "============================================="
echo "  Recon Engine — $TARGET"
echo "  Output: $RECON_DIR/"
echo "  Mode: $([ "$QUICK_MODE" = "--quick" ] && echo "Quick" || echo "Full")"
echo "  Time: $(date)"
echo "============================================="
echo ""

# ============================================================
# Phase 1: Subdomain Enumeration (or Host Discovery for IP/CIDR)
# ============================================================
log_info "Phase 1: Subdomain Enumeration"

# ── For IP / CIDR targets: skip subdomain tools, do host discovery instead ───
if [ "$TARGET_TYPE" = "cidr" ]; then
    log_info "CIDR target — running nmap ping sweep to discover live hosts"
    if command -v nmap &>/dev/null; then
        nmap -sn "$TARGET" -oG - 2>/dev/null \
            | awk '/Up$/{print $2}' \
            > "$RECON_DIR/subdomains/all.txt" || true
        LIVE_COUNT=$(wc -l < "$RECON_DIR/subdomains/all.txt" 2>/dev/null || echo 0)
        if [ "$LIVE_COUNT" -eq 0 ]; then
            log_warn "nmap did not identify live hosts — expanding the CIDR locally for downstream probing"
            _expand_cidr_hosts "$TARGET" > "$RECON_DIR/subdomains/all.txt"
        fi
        log_ok "CIDR sweep: $(wc -l < "$RECON_DIR/subdomains/all.txt") live host(s) discovered"
    else
        log_warn "nmap not installed — expanding the CIDR locally for downstream probing"
        _expand_cidr_hosts "$TARGET" > "$RECON_DIR/subdomains/all.txt"
    fi
    # Skip all subdomain enum tools — jump straight to live host probing
elif [ "${SCOPE_LOCK:-0}" = "1" ] && [ "$TARGET_TYPE" = "ip" ]; then
    log_info "Single IP target — skipping subdomain enumeration"
    echo "$TARGET" > "$RECON_DIR/subdomains/all.txt"
else

# Subfinder (passive, fast)
if command -v subfinder &>/dev/null; then
    log_step "Running subfinder..."
    subfinder -d "$TARGET" -silent -all -o "$RECON_DIR/subdomains/subfinder.txt" 2>/dev/null || true
    log_done "subfinder: $(wc -l < "$RECON_DIR/subdomains/subfinder.txt" 2>/dev/null || echo 0) subdomains"
else
    log_warn "subfinder not installed — skipping"
fi

# Amass (passive)
if command -v amass &>/dev/null && [ "$QUICK_MODE" != "--quick" ]; then
    log_step "Running amass (passive, 5min timeout)..."
    timeout 300 amass enum -passive -d "$TARGET" -o "$RECON_DIR/subdomains/amass.txt" 2>/dev/null || true
    # Ensure amass output file exists even if amass failed
    [ ! -f "$RECON_DIR/subdomains/amass.txt" ] && touch "$RECON_DIR/subdomains/amass.txt"
    log_done "amass: $(wc -l < "$RECON_DIR/subdomains/amass.txt" 2>/dev/null || echo 0) subdomains"
else
    [ "$QUICK_MODE" = "--quick" ] && log_warn "Skipping amass (quick mode)"
fi

# crt.sh (certificate transparency)
log_step "Querying crt.sh..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null \
    | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    names = set()
    for entry in data:
        for name in entry.get('name_value', '').split('\n'):
            name = name.strip().lower()
            if name and '*' not in name and name.endswith('.$TARGET'):
                names.add(name)
            elif name and '*' not in name and '.' in name:
                names.add(name)
    for n in sorted(names):
        print(n)
except: pass
" > "$RECON_DIR/subdomains/crtsh.txt" 2>/dev/null || true
log_done "crt.sh: $(wc -l < "$RECON_DIR/subdomains/crtsh.txt" 2>/dev/null || echo 0) subdomains"

# Wayback subdomains
log_step "Querying Wayback Machine for subdomains..."
curl -s "https://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" 2>/dev/null \
    | sed -nE "s|.*://([a-zA-Z0-9._-]+\.$TARGET).*|\1|p" \
    | sort -u > "$RECON_DIR/subdomains/wayback_subs.txt" 2>/dev/null || true
log_done "wayback: $(wc -l < "$RECON_DIR/subdomains/wayback_subs.txt" 2>/dev/null || echo 0) subdomains"

# Merge and deduplicate all subdomains
cat "$RECON_DIR/subdomains/"*.txt 2>/dev/null | sort -u > "$RECON_DIR/subdomains/all.txt"
TOTAL_SUBS=$(wc -l < "$RECON_DIR/subdomains/all.txt" 2>/dev/null || echo 0)
log_ok "Total unique subdomains: $TOTAL_SUBS"

fi  # end of domain-only subdomain enum block

# ============================================================
# Phase 2: HTTP Probing
# ============================================================
echo ""
log_info "Phase 2: HTTP Probing"

if command -v httpx &>/dev/null && [ -s "$RECON_DIR/subdomains/all.txt" ]; then
    log_step "Probing with httpx (status, title, tech, content-length)..."
    httpx -l "$RECON_DIR/subdomains/all.txt" \
        -silent \
        -status-code \
        -title \
        -tech-detect \
        -content-length \
        -follow-redirects \
        -threads "$THREADS" \
        -rate-limit "$RATE_LIMIT" \
        -o "$RECON_DIR/live/httpx_full.txt" 2>/dev/null || true

    # Extract just the URLs for other tools
    awk '{print $1}' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/urls.txt" 2>/dev/null || true

    LIVE_COUNT=$(wc -l < "$RECON_DIR/live/urls.txt" 2>/dev/null || echo 0)
    log_done "Live hosts: $LIVE_COUNT"

    # Separate by status code
    grep '\[200\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_200.txt" 2>/dev/null || true
    grep '\[30[12]\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_3xx.txt" 2>/dev/null || true
    grep '\[403\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_403.txt" 2>/dev/null || true
    grep '\[401\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_401.txt" 2>/dev/null || true

    log_done "200 OK: $(wc -l < "$RECON_DIR/live/status_200.txt" 2>/dev/null || echo 0)"
    log_done "3xx Redirect: $(wc -l < "$RECON_DIR/live/status_3xx.txt" 2>/dev/null || echo 0)"
    log_done "403 Forbidden: $(wc -l < "$RECON_DIR/live/status_403.txt" 2>/dev/null || echo 0)"
    log_done "401 Auth Required: $(wc -l < "$RECON_DIR/live/status_401.txt" 2>/dev/null || echo 0)"
else
    log_warn "httpx not installed or no subdomains found — skipping"
fi

# ============================================================
# Phase 3: Port Scanning
# ============================================================
echo ""
log_info "Phase 3: Port Scanning"

if command -v nmap &>/dev/null; then
    log_step "Running nmap (top 1000 ports) on $TARGET..."
    nmap -sV --top-ports 1000 -T4 --open "$TARGET" \
        -oN "$RECON_DIR/ports/nmap_results.txt" \
        -oG "$RECON_DIR/ports/nmap_greppable.txt" 2>/dev/null || true
    log_done "Nmap scan complete"

    # Extract open ports (macOS compatible - no grep -P)
    grep "open" "$RECON_DIR/ports/nmap_greppable.txt" 2>/dev/null \
        | sed -nE 's/.*[^0-9]([0-9]+)\/open.*/\1\/open/p' \
        | sort -u > "$RECON_DIR/ports/open_ports.txt" 2>/dev/null || true
    log_done "Open ports: $(wc -l < "$RECON_DIR/ports/open_ports.txt" 2>/dev/null || echo 0)"
else
    log_warn "nmap not installed — skipping"
fi

# ============================================================
# Phase 4: URL Collection
# ============================================================
echo ""
log_info "Phase 4: URL Collection"

# GAU - Get All URLs (wayback, commoncrawl, otx, urlscan)
if command -v gau &>/dev/null; then
    log_step "Running gau (historical URLs)..."
    echo "$TARGET" | gau --threads 5 --o "$RECON_DIR/urls/gau.txt" 2>/dev/null || \
    echo "$TARGET" | gau > "$RECON_DIR/urls/gau.txt" 2>/dev/null || true
    log_done "gau: $(wc -l < "$RECON_DIR/urls/gau.txt" 2>/dev/null || echo 0) URLs"
else
    log_warn "gau not installed — using wayback fallback"
    curl -s "https://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey&limit=5000" \
        > "$RECON_DIR/urls/wayback.txt" 2>/dev/null || true
    log_done "wayback: $(wc -l < "$RECON_DIR/urls/wayback.txt" 2>/dev/null || echo 0) URLs"
fi

# Merge all collected URLs
cat "$RECON_DIR/urls/"*.txt 2>/dev/null | sort -u > "$RECON_DIR/urls/all.txt" 2>/dev/null || true
log_done "Total unique URLs: $(wc -l < "$RECON_DIR/urls/all.txt" 2>/dev/null || echo 0)"

# Filter interesting URLs
if [ -s "$RECON_DIR/urls/all.txt" ]; then
    # URLs with parameters (potential injection points)
    grep '?' "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/with_params.txt" 2>/dev/null || true
    log_done "URLs with parameters: $(wc -l < "$RECON_DIR/urls/with_params.txt" 2>/dev/null || echo 0)"

    # JS files
    grep -iE '\.js(\?|$)' "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/js_files.txt" 2>/dev/null || true
    log_done "JS files: $(wc -l < "$RECON_DIR/urls/js_files.txt" 2>/dev/null || echo 0)"

    # API endpoints
    grep -iE '(/api/|/v[0-9]+/|/graphql|/rest/)' "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/api_endpoints.txt" 2>/dev/null || true
    log_done "API endpoints: $(wc -l < "$RECON_DIR/urls/api_endpoints.txt" 2>/dev/null || echo 0)"

    # Potentially sensitive paths
    grep -iE '\.(env|config|xml|json|yaml|yml|bak|backup|old|orig|sql|db|log|txt|conf|ini|htaccess|htpasswd|git)' \
        "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/sensitive_paths.txt" 2>/dev/null || true
    log_done "Sensitive paths: $(wc -l < "$RECON_DIR/urls/sensitive_paths.txt" 2>/dev/null || echo 0)"
fi

# ============================================================
# Phase 5: JS Analysis
# ============================================================
echo ""
log_info "Phase 5: JavaScript Analysis"

if [ -s "$RECON_DIR/urls/js_files.txt" ]; then
    log_step "Extracting endpoints from JS files (top 50)..."
    mkdir -p "$RECON_DIR/js"

    head -50 "$RECON_DIR/urls/js_files.txt" | while IFS= read -r js_url; do
        curl -s --max-time 10 "$js_url" 2>/dev/null | \
            sed -nE 's/.*["'"'"']([a-zA-Z0-9_/.-]*(\/[a-zA-Z0-9_/.-]+)+)["'"'"'].*/\1/p' \
            >> "$RECON_DIR/js/endpoints_raw.txt" 2>/dev/null || true
    done

    if [ -f "$RECON_DIR/js/endpoints_raw.txt" ]; then
        sort -u "$RECON_DIR/js/endpoints_raw.txt" > "$RECON_DIR/js/endpoints.txt"
        log_done "JS endpoints: $(wc -l < "$RECON_DIR/js/endpoints.txt" 2>/dev/null || echo 0)"

        # Extract potential secrets from JS
        head -50 "$RECON_DIR/urls/js_files.txt" | while IFS= read -r js_url; do
            curl -s --max-time 10 "$js_url" 2>/dev/null | \
                grep -oiE '(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret[_-]?key)["\s]*[:=]["\s]*[a-zA-Z0-9_\-]{8,}' \
                >> "$RECON_DIR/js/potential_secrets.txt" 2>/dev/null || true
        done
        if [ -s "$RECON_DIR/js/potential_secrets.txt" ]; then
            sort -u "$RECON_DIR/js/potential_secrets.txt" -o "$RECON_DIR/js/potential_secrets.txt"
            log_warn "Potential secrets found in JS: $(wc -l < "$RECON_DIR/js/potential_secrets.txt")"
        fi
    fi
else
    log_warn "No JS files found — skipping JS analysis"
fi

# ============================================================
# Phase 6: Directory Fuzzing
# ============================================================
echo ""
log_info "Phase 6: Directory Fuzzing"

WORDLIST_DIR="$BASE_DIR/tools/wordlists"

if command -v ffuf &>/dev/null && [ -s "$RECON_DIR/live/urls.txt" ]; then
    # Select wordlist
    WORDLIST=""
    if [ -f "$WORDLIST_DIR/common.txt" ]; then
        WORDLIST="$WORDLIST_DIR/common.txt"
    elif [ -f /usr/share/wordlists/dirb/common.txt ]; then
        WORDLIST="/usr/share/wordlists/dirb/common.txt"
    fi

    if [ -n "$WORDLIST" ]; then
        # Fuzz top 5 live hosts
        FUZZ_COUNT=0
        MAX_FUZZ=$([ "$QUICK_MODE" = "--quick" ] && echo 2 || echo 5)

        while IFS= read -r url && [ "$FUZZ_COUNT" -lt "$MAX_FUZZ" ]; do
            domain=$(echo "$url" | sed 's|https\?://||;s|[/:].*||')
            log_step "Fuzzing: $url"
            ffuf -u "${url}/FUZZ" \
                -w "$WORDLIST" \
                -mc 200,301,302,403,405 \
                -t "$THREADS" \
                -rate "$RATE_LIMIT" \
                -sf \
                -timeout 10 \
                -o "$RECON_DIR/dirs/ffuf_${domain}.json" \
                -of json 2>/dev/null || true
            ((FUZZ_COUNT++))
        done < "$RECON_DIR/live/urls.txt"

        log_done "Directory fuzzing complete ($FUZZ_COUNT hosts)"
    else
        log_warn "No wordlist found — run: python3 tools/hunt.py --setup-wordlists"
    fi
else
    log_warn "ffuf not installed or no live hosts — skipping directory fuzzing"
fi

# ============================================================
# Phase 6.5: Config File Exposure Check
# ============================================================
echo ""
log_info "Phase 6.5: Config File Exposure Check"

if [ -s "$RECON_DIR/live/urls.txt" ]; then
    log_step "Checking for exposed config files (env.js, app_env.js, .env, etc.)..."
    CONFIG_PATHS=(
        "/env.js"
        "/app_env.js"
        "/config.js"
        "/settings.js"
        "/.env"
        "/.env.local"
        "/.env.production"
        "/.env.development"
        "/config/env.js"
        "/static/env.js"
        "/assets/env.js"
    )

    mkdir -p "$RECON_DIR/exposure"
    : > "$RECON_DIR/exposure/config_files.txt"

    while IFS= read -r base_url; do
        for path in "${CONFIG_PATHS[@]}"; do
            STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${base_url}${path}" 2>/dev/null || echo "000")
            if [ "$STATUS" = "200" ]; then
                CONTENT_TYPE=$(curl -sI --max-time 5 "${base_url}${path}" 2>/dev/null | grep -i content-type | head -1)
                # Only flag if it returns JS/JSON/text (not HTML error pages)
                if echo "$CONTENT_TYPE" | grep -qiE '(javascript|json|text/plain)'; then
                    echo "[EXPOSED] ${base_url}${path}" >> "$RECON_DIR/exposure/config_files.txt"
                    log_vuln "Config exposed: ${base_url}${path}"
                fi
            fi
        done
    done < <(head -30 "$RECON_DIR/live/urls.txt")

    CONFIG_COUNT=$(wc -l < "$RECON_DIR/exposure/config_files.txt" 2>/dev/null | tr -d ' ')
    [ "$CONFIG_COUNT" -gt 0 ] && log_warn "Exposed config files: $CONFIG_COUNT" || log_done "Config files: clean"
else
    log_warn "No live hosts — skipping config check"
fi

# ============================================================
# Phase 7: Parameter Discovery
# ============================================================
echo ""
log_info "Phase 7: Parameter Discovery"

if [ -s "$RECON_DIR/urls/with_params.txt" ]; then
    log_step "Extracting parameters from collected URLs..."

    # Extract parameter names (macOS compatible - no grep -P)
    sed -nE 's/.*[?&]([^=&]+)=.*/\1/p' "$RECON_DIR/urls/with_params.txt" 2>/dev/null \
        | sort | uniq -c | sort -rn > "$RECON_DIR/params/param_frequency.txt" 2>/dev/null || true

    # Get unique param names
    awk '{print $2}' "$RECON_DIR/params/param_frequency.txt" > "$RECON_DIR/params/unique_params.txt" 2>/dev/null || true
    log_done "Unique parameters: $(wc -l < "$RECON_DIR/params/unique_params.txt" 2>/dev/null || echo 0)"

    # Flag interesting params (potential injection points)
    grep -iE '(url|redirect|next|return|callback|dest|file|path|page|template|include|src|ref|uri|link|target|goto|out|view|dir|show|site|domain|rurl|return_to|continue|window|data|reference|to|img|load|doc|download)' \
        "$RECON_DIR/params/unique_params.txt" > "$RECON_DIR/params/interesting_params.txt" 2>/dev/null || true

    if [ -s "$RECON_DIR/params/interesting_params.txt" ]; then
        log_warn "Interesting params (potential vulns): $(wc -l < "$RECON_DIR/params/interesting_params.txt")"
        echo "      Params: $(head -5 "$RECON_DIR/params/interesting_params.txt" | tr '\n' ', ')"
    fi
else
    log_warn "No parameterized URLs found — skipping"
fi

# ============================================================
# Summary
# ============================================================
echo ""
echo "============================================="
echo "  Recon Summary — $TARGET"
echo "  Completed: $(date)"
echo "============================================="
echo ""
echo "  Subdomains:        $(wc -l < "$RECON_DIR/subdomains/all.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/live/urls.txt" ] && \
echo "  Live hosts:        $(wc -l < "$RECON_DIR/live/urls.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/ports/open_ports.txt" ] && \
echo "  Open ports:        $(wc -l < "$RECON_DIR/ports/open_ports.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/urls/all.txt" ] && \
echo "  URLs collected:    $(wc -l < "$RECON_DIR/urls/all.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/urls/with_params.txt" ] && \
echo "  Parameterized:     $(wc -l < "$RECON_DIR/urls/with_params.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/urls/api_endpoints.txt" ] && \
echo "  API endpoints:     $(wc -l < "$RECON_DIR/urls/api_endpoints.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/js/endpoints.txt" ] && \
echo "  JS endpoints:      $(wc -l < "$RECON_DIR/js/endpoints.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/params/unique_params.txt" ] && \
echo "  Unique params:     $(wc -l < "$RECON_DIR/params/unique_params.txt" 2>/dev/null || echo 0)"

echo ""
echo "  Results: $RECON_DIR/"
echo "============================================="
echo ""
echo "  Next: Run vulnerability scanner"
echo "    ./tools/vuln_scanner.sh $RECON_DIR"
echo "============================================="
