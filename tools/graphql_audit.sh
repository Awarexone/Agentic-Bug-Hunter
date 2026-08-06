#!/bin/bash
# =============================================================================
# GraphQL Security Audit — multi-phase sweep for common GraphQL vulnerabilities
#
# Phases: introspection -> fingerprint -> field discovery -> batching DoS ->
#         alias bomb -> injection scan (gqlmap) -> graphql-cop checklist
#
# Falls back to built-in curl probes when optional tools are missing.
#
# Usage:
#   ./tools/graphql_audit.sh <graphql-endpoint-url>
#   ./tools/graphql_audit.sh <url> --cookie "session=abc"
#   ./tools/graphql_audit.sh <url> --header "Authorization: Bearer TOKEN"
#   ./tools/graphql_audit.sh <url> --proxy http://127.0.0.1:8080
#   ./tools/graphql_audit.sh <url> --output-dir ./findings/target/graphql
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/external_arsenal.sh"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAG='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
hit()  { echo -e "${MAG}[HIT]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1" >&2; }
skip() { echo -e "${YELLOW}[~]${NC} $1 (tool not installed)"; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
URL=""; COOKIE=""; AUTH_HEADER=""; PROXY=""; OUT_DIR=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --cookie)     shift; COOKIE="${1:-}" ;;
    --header)     shift; AUTH_HEADER="${1:-}" ;;
    --proxy)      shift; PROXY="${1:-}" ;;
    --output-dir) shift; OUT_DIR="${1:-}" ;;
    -h|--help)    sed -n '2,12p' "$0"; exit 0 ;;
    http*)        URL="$1" ;;
    *)            err "Unknown argument: $1"; exit 2 ;;
  esac
  shift
done

[ -z "$URL" ] && { err "GraphQL endpoint URL required"; exit 2; }

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
HOST=$(echo "$URL" | awk -F/ '{print $3}' | tr -d '[:space:]')
OUT_DIR="${OUT_DIR:-$(pwd)/findings/graphql/${HOST}/${TIMESTAMP}}"
mkdir -p "$OUT_DIR"

SUMMARY="$OUT_DIR/summary.txt"
echo "GraphQL Audit -- $URL" > "$SUMMARY"
echo "Date: $(date)" >> "$SUMMARY"
echo "---" >> "$SUMMARY"

# Build common curl args
CURL_ARGS=(-s --max-time 30)
[ -n "$COOKIE" ]      && CURL_ARGS+=(-H "Cookie: $COOKIE")
[ -n "$AUTH_HEADER" ] && CURL_ARGS+=(-H "$AUTH_HEADER")
[ -n "$PROXY" ]       && CURL_ARGS+=(--proxy "$PROXY")

_gql_post() {
  curl "${CURL_ARGS[@]}" -X POST "$URL" \
    -H 'Content-Type: application/json' \
    -d "$1"
}

# shellcheck source=banner.sh
. "$SCRIPT_DIR/banner.sh"
print_banner "GraphQL Security Audit" "$URL" \
    "Phases|introspection . fingerprint . field-discovery . batching . alias . injection . cop" \
    "Output|$OUT_DIR" \
    "Auth|${COOKIE:+cookie set}${AUTH_HEADER:+header set}${COOKIE:-}${AUTH_HEADER:-(none)}"

# ---------------------------------------------------------------------------
# Phase 0: Connectivity check
# ---------------------------------------------------------------------------
log "Phase 0 -- connectivity check"
HTTP_CODE=$(curl "${CURL_ARGS[@]}" -o /dev/null -w '%{http_code}' -X POST "$URL" \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __typename }"}' 2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "000" ]; then
  err "Cannot reach $URL -- aborting"
  exit 1
fi

ok "Endpoint responded: HTTP $HTTP_CODE"
echo "connectivity: HTTP $HTTP_CODE" >> "$SUMMARY"

# ---------------------------------------------------------------------------
# Phase 1: Introspection
# ---------------------------------------------------------------------------
log "Phase 1 -- introspection probe"

INTROSPECT_QUERY='{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name fields(includeDeprecated: true) { name isDeprecated } } } }"}'

INTROSPECT_RESP=$(_gql_post "$INTROSPECT_QUERY")
INTROSPECT_OUT="$OUT_DIR/introspection.json"

if echo "$INTROSPECT_RESP" | grep -q '"__schema"'; then
  hit "Introspection ENABLED -- schema dumped to introspection.json"
  echo "$INTROSPECT_RESP" | python3 -m json.tool > "$INTROSPECT_OUT" 2>/dev/null \
    || echo "$INTROSPECT_RESP" > "$INTROSPECT_OUT"
  echo "introspection: ENABLED" >> "$SUMMARY"

  # Extract interesting type/field names
  INTERESTING=$(echo "$INTROSPECT_RESP" | python3 -c "
import sys, json, re
try:
    data = json.load(sys.stdin)
    types = data.get('data',{}).get('__schema',{}).get('types',[])
    hits = []
    keywords = re.compile(r'admin|internal|secret|token|password|role|debug|legacy|private|key|flag', re.I)
    for t in types:
        if keywords.search(t.get('name','')):
            hits.append('TYPE: ' + t['name'])
        for f in (t.get('fields') or []):
            if keywords.search(f.get('name','')):
                hits.append('FIELD: ' + t['name'] + '.' + f['name'])
    print('\n'.join(hits) if hits else 'no obvious sensitive names found')
except Exception as e:
    print('parse error: ' + str(e))
" 2>/dev/null)
  echo -e "\n${BOLD}Interesting schema names:${NC}"
  echo "$INTERESTING"
  echo "$INTERESTING" > "$OUT_DIR/interesting_fields.txt"
else
  warn "Introspection appears disabled (or blocked)"
  echo "$INTROSPECT_RESP" > "$INTROSPECT_OUT"
  echo "introspection: DISABLED" >> "$SUMMARY"

  # Try bypass: GET method
  log "Trying introspection via GET..."
  GET_RESP=$(curl "${CURL_ARGS[@]}" -X GET \
    "$URL?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D" 2>/dev/null)
  if echo "$GET_RESP" | grep -q '"__schema"'; then
    hit "Introspection reachable via GET -- WAF bypass found"
    echo "introspection_get_bypass: YES" >> "$SUMMARY"
  fi
fi

# Field suggestions probe (works even when introspection is off)
log "Checking field suggestions..."
SUGGEST_RESP=$(_gql_post '{"query":"{ usr { id } }"}')
if echo "$SUGGEST_RESP" | grep -qi "did you mean\|suggestions"; then
  hit "Field suggestions ENABLED -- schema leakable via clairvoyance"
  echo "field_suggestions: ENABLED" >> "$SUMMARY"
else
  echo "field_suggestions: disabled or no hints" >> "$SUMMARY"
fi

# ---------------------------------------------------------------------------
# Phase 2: Engine fingerprinting (graphw00f)
# ---------------------------------------------------------------------------
log "Phase 2 -- engine fingerprinting"
FINGER_OUT="$OUT_DIR/fingerprint.txt"

if python3 -c "import graphw00f" 2>/dev/null; then
  python3 -m graphw00f.main -d -t "$URL" \
    ${PROXY:+--proxy "$PROXY"} 2>&1 | tee "$FINGER_OUT"
  echo "fingerprint: see fingerprint.txt" >> "$SUMMARY"
else
  skip "graphw00f"
  echo "(install: pip install graphw00f)" > "$FINGER_OUT"
  echo "fingerprint: skipped (graphw00f not installed)" >> "$SUMMARY"
fi

# ---------------------------------------------------------------------------
# Phase 3: Field discovery via clairvoyance
# ---------------------------------------------------------------------------
log "Phase 3 -- field discovery (clairvoyance)"
CLAIRVOYANCE_OUT="$OUT_DIR/field_suggestions.json"

if python3 -c "import clairvoyance" 2>/dev/null; then
  CLAIRVOYANCE_ARGS=(-u "$URL" -o "$CLAIRVOYANCE_OUT")
  [ -n "$AUTH_HEADER" ] && CLAIRVOYANCE_ARGS+=(-H "$AUTH_HEADER")
  [ -n "$PROXY" ]       && CLAIRVOYANCE_ARGS+=(--proxy "$PROXY")
  python3 -m clairvoyance "${CLAIRVOYANCE_ARGS[@]}" 2>&1 | tail -20
  ok "Clairvoyance output: $CLAIRVOYANCE_OUT"
  echo "clairvoyance: completed" >> "$SUMMARY"
else
  skip "clairvoyance"
  echo "(install: pip install clairvoyance)" > "$CLAIRVOYANCE_OUT"
  echo "clairvoyance: skipped (not installed)" >> "$SUMMARY"
fi

# ---------------------------------------------------------------------------
# Phase 4: Query batching DoS
# ---------------------------------------------------------------------------
log "Phase 4 -- batching DoS test"
BATCH_OUT="$OUT_DIR/batching_dos.txt"

T_SINGLE=$(curl "${CURL_ARGS[@]}" -X POST "$URL" \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __typename }"}' \
  -o /dev/null -w '%{time_total}' 2>/dev/null)

BATCH_PAYLOAD=$(python3 -c "import json; print(json.dumps([{'query':'{ __typename }'}]*100))")
BATCH_STATUS=$(curl "${CURL_ARGS[@]}" -X POST "$URL" \
  -H 'Content-Type: application/json' \
  -d "$BATCH_PAYLOAD" \
  -o "$BATCH_OUT" -w '%{http_code}' 2>/dev/null)
T_BATCH=$(curl "${CURL_ARGS[@]}" -X POST "$URL" \
  -H 'Content-Type: application/json' \
  -d "$BATCH_PAYLOAD" \
  -o /dev/null -w '%{time_total}' 2>/dev/null)

echo "single query time: ${T_SINGLE}s" | tee -a "$BATCH_OUT"
echo "100-query batch time: ${T_BATCH}s  HTTP: $BATCH_STATUS" | tee -a "$BATCH_OUT"

if grep -q '^\[' "$BATCH_OUT" 2>/dev/null; then
  hit "Array batching ACCEPTED -- ${T_BATCH}s for 100 queries (potential DoS / brute-force amplifier)"
  echo "array_batching: ENABLED" >> "$SUMMARY"
else
  warn "Array batching returned HTTP $BATCH_STATUS -- may be disabled"
  echo "array_batching: likely disabled (HTTP $BATCH_STATUS)" >> "$SUMMARY"
fi

# Alias bomb (500 aliases)
log "Testing alias bombing..."
ALIAS_PAYLOAD=$(python3 -c "
aliases = ' '.join(f'q{i}: __typename' for i in range(500))
import json; print(json.dumps({'query': '{ ' + aliases + ' }'}))
")
ALIAS_OUT="$OUT_DIR/alias_bomb.txt"
curl "${CURL_ARGS[@]}" -X POST "$URL" \
  -H 'Content-Type: application/json' \
  -d "$ALIAS_PAYLOAD" \
  -o "$ALIAS_OUT" -w '\n500-alias query: HTTP %{http_code}  time: %{time_total}s\n' 2>/dev/null \
  | tee -a "$ALIAS_OUT"

if grep -q 'q0' "$ALIAS_OUT" 2>/dev/null; then
  hit "Alias bomb ACCEPTED -- rate-limit bypass possible"
  echo "alias_bombing: ENABLED" >> "$SUMMARY"
else
  echo "alias_bombing: blocked or limited" >> "$SUMMARY"
fi

# ---------------------------------------------------------------------------
# Phase 5: Injection scan (gqlmap)
# ---------------------------------------------------------------------------
log "Phase 5 -- injection scan"
GQLMAP_OUT="$OUT_DIR/gqlmap.txt"

if _have gqlmap; then
  GQLMAP_ARGS=(--target "$URL" --query '{ users(search: GQLMAP) { id } }')
  [ -n "$PROXY" ] && GQLMAP_ARGS+=(--proxy "$PROXY")
  gqlmap "${GQLMAP_ARGS[@]}" 2>&1 | tee "$GQLMAP_OUT" || true
  echo "injection_scan: completed (see gqlmap.txt)" >> "$SUMMARY"
else
  skip "gqlmap"
  echo "(install: pip install gqlmap)" > "$GQLMAP_OUT"
  echo "injection_scan: skipped (gqlmap not installed)" >> "$SUMMARY"

  # Built-in quick SQLi probe
  log "Built-in SQLi quick probe..."
  SQLI_RESP=$(_gql_post '{"query":"{ users(search: \"1'\''--\") { id } }"}' 2>/dev/null || true)
  if echo "$SQLI_RESP" | grep -qi "syntax\|mysql\|pgsql\|sqlite\|ORA-\|error in your SQL"; then
    hit "SQL error in response -- possible SQLi in search argument"
    echo "$SQLI_RESP" >> "$GQLMAP_OUT"
    echo "sqli_quick_probe: POSSIBLE HIT" >> "$SUMMARY"
  else
    echo "sqli_quick_probe: no obvious errors" >> "$SUMMARY"
  fi
fi

# ---------------------------------------------------------------------------
# Phase 6: graphql-cop checklist
# ---------------------------------------------------------------------------
log "Phase 6 -- graphql-cop attack checklist"
COP_OUT="$OUT_DIR/cop_report.txt"

if _have graphql-cop; then
  COP_ARGS=(-t "$URL")
  [ -n "$AUTH_HEADER" ] && COP_ARGS+=(-H "$AUTH_HEADER")
  graphql-cop "${COP_ARGS[@]}" 2>&1 | tee "$COP_OUT"
  echo "graphql_cop: completed (see cop_report.txt)" >> "$SUMMARY"
else
  skip "graphql-cop"
  echo "(install: pip install graphql-cop)" > "$COP_OUT"
  echo "graphql_cop: skipped (not installed)" >> "$SUMMARY"
fi

# ---------------------------------------------------------------------------
# Phase 7: Depth limit probe (built-in)
# ---------------------------------------------------------------------------
log "Phase 7 -- depth limit probe"
DEPTH_OUT="$OUT_DIR/depth_bomb.txt"

DEPTH_QUERY=$(python3 -c "
depth = 15
inner = 'id'
for _ in range(depth):
    inner = f'edges {{ node {{ {inner} }} }}'
import json; print(json.dumps({'query': '{ viewer { ' + inner + ' } }'}))
")

DEPTH_HTTP=$(curl "${CURL_ARGS[@]}" -X POST "$URL" \
  -H 'Content-Type: application/json' \
  -d "$DEPTH_QUERY" \
  -o "$DEPTH_OUT" -w '%{http_code}' 2>/dev/null)
T_DEPTH=$(curl "${CURL_ARGS[@]}" -X POST "$URL" \
  -H 'Content-Type: application/json' \
  -d "$DEPTH_QUERY" \
  -o /dev/null -w '%{time_total}' 2>/dev/null)

echo "depth-15 query: HTTP $DEPTH_HTTP  time: ${T_DEPTH}s" | tee -a "$DEPTH_OUT"
if [ "$DEPTH_HTTP" = "200" ] && ! grep -qi "max.*depth\|query.*depth\|complexity" "$DEPTH_OUT" 2>/dev/null; then
  hit "Deep query (depth=15) accepted -- no depth limit detected"
  echo "depth_limit: NONE DETECTED" >> "$SUMMARY"
else
  echo "depth_limit: enforced or endpoint rejected query" >> "$SUMMARY"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}====== AUDIT SUMMARY ======${NC}"
cat "$SUMMARY"
echo ""
ok "All output saved to: $OUT_DIR"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Introspection on  -> import introspection.json into graphql-voyager or InQL (Burp)"
echo "  2. Batching accepted -> chain with login/OTP mutation for ATO PoC"
echo "  3. Field suggestions -> run clairvoyance manually with seed types"
echo "  4. Check interesting_fields.txt for IDOR / auth bypass targets"
echo "  5. Load cop_report.txt for remaining manual checks"
