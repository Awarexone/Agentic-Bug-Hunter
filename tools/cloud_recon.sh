#!/bin/bash
# =============================================================================
# Cloud Recon — discover public S3/Azure/GCP assets and CloudFlare-bypassed origin IPs
#
# Wraps:
#   - S3Scanner   (sa7mon)         — scans S3 across providers, dumps perms
#   - cloud_enum  (initstring)     — multi-cloud OSINT (AWS/Azure/GCP)
#   - CloudFail   (m0rtem)         — origin IP behind CloudFlare via DNS history
#
# Usage:
#   ./tools/cloud_recon.sh --keyword <name>          # all three sweeps
#   ./tools/cloud_recon.sh --keyword acme --s3-only
#   ./tools/cloud_recon.sh --cf-bypass target.com
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/external_arsenal.sh"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; MAG='\033[0;35m'; NC='\033[0m'
log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
hit()  { echo -e "${MAG}[CLOUD]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1" >&2; }

KEYWORD=""; CF_TARGET=""; S3_ONLY=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --keyword)   shift; KEYWORD="${1:-}" ;;
    --cf-bypass) shift; CF_TARGET="${1:-}" ;;
    --s3-only)   S3_ONLY=1 ;;
    -h|--help)   sed -n '2,12p' "$0"; exit 0 ;;
    *) err "unknown arg: $1"; exit 2 ;;
  esac
  shift
done

[ -z "$KEYWORD" ] && [ -z "$CF_TARGET" ] && { err "--keyword or --cf-bypass required"; exit 2; }

OUT_DIR="${CLOUD_OUT_DIR:-$(pwd)/findings/cloud/$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUT_DIR"

# shellcheck source=banner.sh
. "$SCRIPT_DIR/banner.sh"
print_banner "Cloud Recon · S3 · Azure · GCP" "${KEYWORD:-$CF_TARGET}" \
    "S3 sweep|s3scanner across AWS/DO/Linode/Wasabi" \
    "Multi-cloud OSINT|cloud_enum across AWS/Azure/GCP" \
    "CF bypass|CloudFail — origin IP via DNS history"

# ── S3 buckets across providers ─────────────────────────────────────────────
if [ -n "$KEYWORD" ] && _have s3scanner; then
  log "s3scanner on keyword '$KEYWORD'..."
  s3scanner -bucket "$KEYWORD" -enumerate -threads 5 \
    > "$OUT_DIR/s3scanner.txt" 2>/dev/null || true
  n=$(grep -cE 'exists|public' "$OUT_DIR/s3scanner.txt" 2>/dev/null || echo 0)
  [ "$n" -gt 0 ] && hit "s3scanner: $n buckets matched" || ok "s3scanner: nothing public"
fi

# ── Multi-cloud enumeration (cloud_enum) ────────────────────────────────────
if [ -n "$KEYWORD" ] && [ "$S3_ONLY" = "0" ] && _have cloud_enum; then
  log "cloud_enum sweep across AWS/Azure/GCP..."
  cloud_enum -k "$KEYWORD" -t 5 --disable-aws-disk \
    -l "$OUT_DIR/cloud_enum.txt" 2>/dev/null || true
  n=$(wc -l < "$OUT_DIR/cloud_enum.txt" 2>/dev/null | tr -d ' ' || echo 0)
  [ "$n" -gt 0 ] && hit "cloud_enum: $n discoveries — review file" || ok "cloud_enum: clean"
fi

# ── CloudFlare origin-IP discovery (CloudFail) ──────────────────────────────
if [ -n "$CF_TARGET" ]; then
  if _have cloudfail; then
    log "CloudFail on $CF_TARGET..."
    cloudfail --target "$CF_TARGET" > "$OUT_DIR/cloudfail.txt" 2>&1 || true
    n=$(grep -cE '\[FOUND\]|origin' "$OUT_DIR/cloudfail.txt" 2>/dev/null || echo 0)
    [ "$n" -gt 0 ] && hit "CloudFail: $n origin/IP candidates" || ok "CloudFail: nothing exposed"
  else
    warn "CloudFail not installed — falling back to crt.sh + DNS history dig"
    log "Pulling crt.sh subdomains for $CF_TARGET..."
    curl -s "https://crt.sh/?q=%25.$CF_TARGET&output=json" 2>/dev/null \
      | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    seen = set()
    for e in d:
        for n in (e.get('name_value') or '').split('\n'):
            n = n.strip().lower().lstrip('*.')
            if n and '.' in n:
                seen.add(n)
    for h in sorted(seen):
        print(h)
except Exception:
    pass" > "$OUT_DIR/crtsh_subs.txt" || true
    log "Resolving each — flag any IP NOT in CloudFlare ranges..."
    : > "$OUT_DIR/non_cf_ips.txt"
    while IFS= read -r host; do
      ip=$(dig +short "$host" A 2>/dev/null | head -1)
      [ -z "$ip" ] && continue
      # CloudFlare /16 prefixes (subset — extend for full coverage)
      case "$ip" in
        103.21.244.*|103.22.200.*|103.31.4.*|104.16.*|104.17.*|104.18.*|104.19.*|104.20.*|104.21.*|104.22.*|104.23.*|104.24.*|104.25.*|104.26.*|104.27.*|104.28.*|108.162.192.*|131.0.72.*|141.101.64.*|162.158.*|172.64.*|172.65.*|172.66.*|172.67.*|173.245.48.*|188.114.96.*|190.93.240.*|197.234.240.*|198.41.128.*) ;;
        *) echo "$host -> $ip" >> "$OUT_DIR/non_cf_ips.txt" ;;
      esac
    done < "$OUT_DIR/crtsh_subs.txt"
    n=$(wc -l < "$OUT_DIR/non_cf_ips.txt" | tr -d ' ')
    [ "$n" -gt 0 ] && hit "Found $n subdomains pointing OUTSIDE CloudFlare — possible origin IPs" \
                    || ok "All resolved IPs are CloudFlare (origin not exposed via DNS)"
  fi
fi

ok "Done. Output → $OUT_DIR/"
