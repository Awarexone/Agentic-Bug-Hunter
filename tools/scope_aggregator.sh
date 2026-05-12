#!/bin/bash
# =============================================================================
# Scope Aggregator — pull in-scope assets across H1/Bugcrowd/Intigriti/YWH/Immunefi
#
# Two strategies (in order of preference):
#  1. bbscope     — authenticated multi-platform scope pull (sw33tLie/bbscope)
#  2. bounty-targets-data — hourly-updated public dump (arkadiyt/bounty-targets-data)
#
# The dump strategy needs no credentials and works for every public program; use
# it to bootstrap, then layer bbscope when you have platform tokens for private
# invites. Output is one host per line in $OUT, ready for `tools/recon_engine.sh
# <out_file>` (domain-list mode).
#
# Usage:
#   ./tools/scope_aggregator.sh <program-handle> [--platform h1|bc|it|ywh|imf|all]
#                              [--out <file>] [--include-oos] [--no-cache]
#
# Examples:
#   ./tools/scope_aggregator.sh shopify              # bbscope if available else dump
#   ./tools/scope_aggregator.sh shopify --platform h1 --out /tmp/shopify.txt
#   ./tools/scope_aggregator.sh --list-programs --platform h1
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/external_arsenal.sh"  # for _have

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
# All status output goes to stderr so functions can return data on stdout cleanly.
log()  { echo -e "${CYAN}[*]${NC} $1" >&2; }
ok()   { echo -e "${GREEN}[+]${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[!]${NC} $1" >&2; }
err()  { echo -e "${RED}[-]${NC} $1" >&2; }

PROGRAM=""; PLATFORM="all"; OUT=""; INCLUDE_OOS=0; NO_CACHE=0; LIST_PROGRAMS=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --platform)     shift; PLATFORM="${1:-all}" ;;
    --out)          shift; OUT="${1:-}" ;;
    --include-oos)  INCLUDE_OOS=1 ;;
    --no-cache)     NO_CACHE=1 ;;
    --list-programs) LIST_PROGRAMS=1 ;;
    -h|--help)
      sed -n '2,20p' "$0"; exit 0 ;;
    *)              PROGRAM="$1" ;;
  esac
  shift
done

CACHE_DIR="${BBHUNT_CACHE_DIR:-$HOME/.cache/bbhunt/scope}"
mkdir -p "$CACHE_DIR"

# Map our short labels to bbscope/dump platform names. Immunefi is intentionally
# absent from arkadiyt/bounty-targets-data — pull it through bbscope when needed.
declare -a PLATFORMS_TO_PULL
case "$PLATFORM" in
  h1)  PLATFORMS_TO_PULL=(hackerone) ;;
  bc)  PLATFORMS_TO_PULL=(bugcrowd) ;;
  it)  PLATFORMS_TO_PULL=(intigriti) ;;
  ywh) PLATFORMS_TO_PULL=(yeswehack) ;;
  fc)  PLATFORMS_TO_PULL=(federacy) ;;
  imf) PLATFORMS_TO_PULL=(immunefi) ;;  # bbscope only; no public dump
  all) PLATFORMS_TO_PULL=(hackerone bugcrowd intigriti yeswehack federacy) ;;
  *)   err "unknown platform: $PLATFORM"; exit 2 ;;
esac

# ── bounty-targets-data dump (always available, no auth) ─────────────────────
DUMP_BASE="https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"
_fetch_dump() {
  local platform="$1"
  local cache="$CACHE_DIR/${platform}.json"
  if [ "$NO_CACHE" = "1" ] || [ ! -s "$cache" ] || [ "$(find "$cache" -mmin +60 -print 2>/dev/null)" ]; then
    log "Fetching $platform scope dump (~10-30MB, cached 60min)..."
    curl -sSL --max-time 180 "$DUMP_BASE/${platform}_data.json" -o "$cache.tmp" \
      && mv "$cache.tmp" "$cache" \
      || { rm -f "$cache.tmp"; warn "$platform dump fetch failed"; return 1; }
  fi
  echo "$cache"
}

_extract_dump() {
  local cache="$1"
  local program="$2"
  python3 - "$cache" "$program" "$INCLUDE_OOS" <<'PY'
import json, sys, re

cache, program, include_oos = sys.argv[1], sys.argv[2].lower(), sys.argv[3] == "1"
hosts = set()

# Each platform's dump uses different field names. Normalise here.
ASSET_FIELDS = ("asset_identifier", "endpoint", "target", "asset", "name", "uri")
KIND_FIELDS  = ("asset_type", "type", "category")
GOOD_KINDS   = {"url", "wildcard", "web", "other_application", "android", "ios"}
HOST_RE = re.compile(r"^[a-zA-Z0-9*._-]+\.[a-zA-Z]{2,}$")

try:
    data = json.load(open(cache))
except Exception:
    sys.exit(0)

# Some dumps wrap programs under a list; others under a dict. Normalise.
if isinstance(data, dict):
    data = data.get("programs") or data.get("data") or list(data.values())

for entry in data or []:
    if not isinstance(entry, dict):
        continue
    handle  = (entry.get("handle") or entry.get("company_handle") or entry.get("name") or "").lower()
    url     = (entry.get("url") or "").lower()
    if program and program not in handle and program not in url:
        continue
    targets = entry.get("targets") or {}
    if isinstance(targets, list):
        in_scope, out_scope = targets, []
    else:
        in_scope  = targets.get("in_scope")  or entry.get("in_scope")  or []
        out_scope = targets.get("out_of_scope") or entry.get("out_of_scope") or []
    pools = [in_scope] + ([out_scope] if include_oos else [])
    for pool in pools:
        for t in pool or []:
            if isinstance(t, str):
                cand = t
            elif isinstance(t, dict):
                cand = ""
                for f in ASSET_FIELDS:
                    if t.get(f):
                        cand = t[f]; break
                kind = ""
                for f in KIND_FIELDS:
                    if t.get(f):
                        kind = str(t[f]).lower(); break
                # Reject types that obviously aren't web hosts (executables, hardware).
                if kind and kind not in GOOD_KINDS and "." not in cand:
                    continue
            else:
                continue
            cand = (cand or "").strip()
            cand = re.sub(r"^https?://", "", cand).rstrip("/").split("/")[0].split("?")[0]
            cand = cand.lower()
            if cand and HOST_RE.match(cand):
                hosts.add(cand)

for h in sorted(hosts):
    print(h)
PY
}

# ── --list-programs: dump program handles for the chosen platform(s) ─────────
if [ "$LIST_PROGRAMS" = "1" ]; then
  for p in "${PLATFORMS_TO_PULL[@]}"; do
    cache=$(_fetch_dump "$p") || continue
    log "Programs on $p:"
    python3 - "$cache" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
for entry in data:
    h = entry.get("handle") or entry.get("name") or "?"
    u = entry.get("url") or ""
    print(f"  {h:30s} {u}")
PY
  done
  exit 0
fi

[ -z "$PROGRAM" ] && { err "missing <program-handle>"; sed -n '20,30p' "$0"; exit 2; }

OUT="${OUT:-$CACHE_DIR/${PROGRAM}.scope.txt}"
: > "$OUT"

# ── Strategy 1: bbscope (authenticated, freshest) ────────────────────────────
if _have bbscope; then
  for p in "${PLATFORMS_TO_PULL[@]}"; do
    case "$p" in hackerone|bugcrowd|intigriti) ;; *) continue ;; esac
    short="${p:0:2}"; [ "$p" = "hackerone" ] && short="h1"
    log "Trying bbscope $short for '$PROGRAM'..."
    bbscope "$short" -p "$PROGRAM" -o t -c 2>/dev/null \
      | grep -E '^[a-zA-Z0-9*._-]+\.[a-zA-Z]{2,}$' \
      | sed 's|^\*\.||' \
      | sort -u >> "$OUT" || true
  done
fi

# ── Strategy 2: bounty-targets-data dump fallback ────────────────────────────
if [ ! -s "$OUT" ]; then
  warn "bbscope returned nothing or is not installed — falling back to bounty-targets-data dump"
  for p in "${PLATFORMS_TO_PULL[@]}"; do
    cache=$(_fetch_dump "$p") || continue
    _extract_dump "$cache" "$PROGRAM" >> "$OUT" || true
  done
fi

# Final cleanup: dedupe, drop wildcards, lower-case
sort -u "$OUT" -o "$OUT"
COUNT=$(wc -l < "$OUT" | tr -d ' ')

if [ "$COUNT" = "0" ]; then
  err "No assets found for '$PROGRAM' on $PLATFORM. Try --list-programs to confirm the handle."
  exit 1
fi

ok "$COUNT in-scope asset(s) written to: $OUT"
echo
log "Next: feed it to recon"
echo "  ./tools/recon_engine.sh \"$OUT\""
