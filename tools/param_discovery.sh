#!/bin/bash
# =============================================================================
# Parameter Discovery — find hidden HTTP parameters on a target endpoint
#
# Wraps Arjun (s0md3v) and x8 (Sh1Yo) — both work by diffing responses for a
# wordlist of param names. Hidden params are gold for IDOR, SSRF, LFI, redirect.
#
# Usage:
#   ./tools/param_discovery.sh <url>
#   ./tools/param_discovery.sh -l <urls-file>
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/external_arsenal.sh"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; MAG='\033[0;35m'; NC='\033[0m'
log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
hit()  { echo -e "${MAG}[PARAM]${NC} $1"; }
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

OUT_DIR="${PARAM_OUT_DIR:-$(pwd)/findings/params/$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUT_DIR"

if _have arjun; then
  log "arjun discovery..."
  if [ -n "$URL" ]; then
    arjun -u "$URL" -oJ "$OUT_DIR/arjun.json" 2>/dev/null || true
  else
    arjun -i "$LIST" -oJ "$OUT_DIR/arjun.json" 2>/dev/null || true
  fi
  if [ -s "$OUT_DIR/arjun.json" ]; then
    python3 -c "
import json
d = json.load(open('$OUT_DIR/arjun.json'))
for ep, info in d.items():
    params = info.get('params', [])
    if params:
        print(f'{ep}  →  ' + ','.join(params))
" > "$OUT_DIR/arjun_summary.txt" || true
    n=$(wc -l < "$OUT_DIR/arjun_summary.txt" | tr -d ' ')
    [ "$n" -gt 0 ] && hit "arjun: $n endpoint(s) had hidden params" || ok "arjun: no hits"
  fi
elif _have x8; then
  log "x8 discovery (arjun unavailable)..."
  WL="$SCRIPT_DIR/../wordlists/params.txt"
  [ -f "$WL" ] || WL=""
  if [ -n "$URL" ]; then
    x8 -u "$URL" ${WL:+-w "$WL"} -o "$OUT_DIR/x8.txt" 2>/dev/null || true
  else
    while IFS= read -r u; do
      [ -z "$u" ] && continue
      x8 -u "$u" ${WL:+-w "$WL"} >> "$OUT_DIR/x8.txt" 2>/dev/null || true
    done < "$LIST"
  fi
  ok "x8 done — see $OUT_DIR/x8.txt"
else
  err "neither arjun nor x8 installed — see ./tools/external_arsenal.sh --install-hint arjun"
  exit 1
fi

ok "Done. Output → $OUT_DIR/"
