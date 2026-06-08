#!/bin/bash
# =============================================================================
# CVE Scanner — fast nuclei sweep tagged for known CVEs, plus optional log4j-scan
#
# Why a separate wrapper:
#   - The recon engine's nuclei phase runs *all* templates by severity. This one
#     specifically targets the cve/ directory and prioritises the highest-impact
#     remote-exploitable bugs.
#   - When `log4j-scan` is installed it runs in parallel — log4shell still pays
#     on legacy hosts and the dedicated scanner has an OOB callback flow.
#
# Usage:
#   ./tools/cve_scan.sh <target-or-file>
#   ./tools/cve_scan.sh --recon <recon-dir>
#   ./tools/cve_scan.sh --year 2024 <target>      # filter by CVE year
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/external_arsenal.sh"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; MAG='\033[0;35m'; NC='\033[0m'
log()  { echo -e "${CYAN}[*]${NC} $1" >&2; }
ok()   { echo -e "${GREEN}[+]${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[!]${NC} $1" >&2; }
hit()  { echo -e "${MAG}[CVE]${NC} $1" >&2; }
err()  { echo -e "${RED}[-]${NC} $1" >&2; }

TARGET=""; YEAR=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --recon) shift; TARGET="${1:-}/live/urls.txt" ;;
    --year)  shift; YEAR="${1:-}" ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) TARGET="$1" ;;
  esac
  shift
done

[ -z "$TARGET" ] && { err "target host or -l <file> required"; exit 2; }

OUT_DIR="${CVE_OUT_DIR:-$(pwd)/findings/cve/$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUT_DIR"

# shellcheck source=banner.sh
. "$SCRIPT_DIR/banner.sh"
print_banner "CVE Scanner · nuclei sweep" "$TARGET" \
    "Update|nuclei template refresh (skip with NUCLEI_NO_UPDATE=1)" \
    "Scan|cve/ templates filtered by high+critical severity" \
    "Log4j|optional dedicated scanner with OOB callback" \
    "Report|JSONL hits + summary in findings dir" 1>&2

if ! _have nuclei; then
  err "nuclei required — see ./tools/external_arsenal.sh --install-hint nuclei"; exit 1
fi

log "Updating nuclei templates (skip with NUCLEI_NO_UPDATE=1)..."
[ "${NUCLEI_NO_UPDATE:-0}" = "1" ] || nuclei -update-templates -silent 2>/dev/null || true

# Build template path filter — defaults to every cve/ template, narrowed by year.
TEMPLATE_FILTER=( -tags cve )
[ -n "$YEAR" ] && TEMPLATE_FILTER+=( -tags "$YEAR" )

INPUT_ARG=( -u "$TARGET" )
[ -f "$TARGET" ] && INPUT_ARG=( -l "$TARGET" )

log "nuclei CVE sweep on $TARGET ${YEAR:+(year=$YEAR)}..."
nuclei "${INPUT_ARG[@]}" \
  "${TEMPLATE_FILTER[@]}" \
  -severity high,critical \
  -silent -stats \
  -jsonl -o "$OUT_DIR/nuclei_cve.jsonl" 2>/dev/null || true

if [ -s "$OUT_DIR/nuclei_cve.jsonl" ]; then
  n=$(wc -l < "$OUT_DIR/nuclei_cve.jsonl" | tr -d ' ')
  hit "nuclei: $n CVE finding(s)"
  python3 -c "
import json
seen=set()
for line in open('$OUT_DIR/nuclei_cve.jsonl'):
  try: d=json.loads(line)
  except: continue
  cve=(d.get('info',{}).get('classification',{}) or {}).get('cve-id') or d.get('template-id')
  host=d.get('matched-at') or d.get('host')
  sev=(d.get('info',{}).get('severity') or '').upper()
  k=(cve, host)
  if k in seen: continue
  seen.add(k)
  print(f'  {sev:8s} {cve}  {host}')
" >&2
else
  ok "nuclei: no CVE matches"
fi

# Parallel: log4j-scan when present (still pays on legacy enterprise stacks)
if _have log4j-scan; then
  log "log4j-scan probe..."
  log4j-scan -u "$TARGET" --run-all-tests > "$OUT_DIR/log4j.txt" 2>&1 || true
  if grep -qiE 'vulnerable|cve-2021-44228' "$OUT_DIR/log4j.txt"; then
    hit "log4j-scan: vulnerability indicator — review $OUT_DIR/log4j.txt"
  fi
fi

ok "Done. Output → $OUT_DIR/"
