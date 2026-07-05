#!/bin/bash
# =============================================================================
# Secrets Hunter — find leaked credentials across git history, JS bundles, repos
#
# Wraps trufflehog / noseyparker / gitleaks — whichever is installed wins. Each
# scanner has different strengths:
#   - trufflehog   : verifies live keys (AWS/Slack/etc) against the issuer API
#   - noseyparker  : fastest at scanning massive git histories with low FP
#   - gitleaks     : opinionated rule pack, decent default for repos
#
# Usage:
#   ./tools/secrets_hunter.sh --filesystem <dir>
#   ./tools/secrets_hunter.sh --git <repo-path-or-url>
#   ./tools/secrets_hunter.sh --js-bundle <recon-dir>     # scans recon/<t>/js/
#   ./tools/secrets_hunter.sh --github-org <org>          # needs trufflehog+token
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/external_arsenal.sh"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; MAG='\033[0;35m'; NC='\033[0m'
log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
hit()  { echo -e "${MAG}[SECRET]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1" >&2; }

MODE=""; TARGET=""; OUT_DIR="${SECRETS_OUT_DIR:-$(pwd)/findings/secrets/$(date +%Y%m%d_%H%M%S)}"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --filesystem)  MODE="fs";   shift; TARGET="${1:-}" ;;
    --git)         MODE="git";  shift; TARGET="${1:-}" ;;
    --js-bundle)   MODE="js";   shift; TARGET="${1:-}" ;;
    --github-org)  MODE="ghorg";shift; TARGET="${1:-}" ;;
    --out)         shift; OUT_DIR="${1:-}" ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) err "unknown arg: $1"; exit 2 ;;
  esac
  shift
done

[ -z "$MODE" ] || [ -z "$TARGET" ] && { err "mode + target required"; sed -n '12,16p' "$0"; exit 2; }

mkdir -p "$OUT_DIR"

# shellcheck source=banner.sh
. "$SCRIPT_DIR/banner.sh"
print_banner "Secrets Hunter · Leaked Credentials" "$TARGET" \
    "Scan|trufflehog · noseyparker · gitleaks (whichever is installed)" \
    "Verify|live-key validation against issuer APIs" \
    "Report|findings written to scan-output dir"

log "Findings → $OUT_DIR"

# Pick the strongest scanner for the mode
_run_trufflehog() {
  local target="$1" subcmd="$2"
  log "trufflehog $subcmd $target"
  trufflehog "$subcmd" "$target" --json --no-update --only-verified 2>/dev/null \
    > "$OUT_DIR/trufflehog.jsonl" || true
  local n; n=$(wc -l < "$OUT_DIR/trufflehog.jsonl" | tr -d ' ')
  [ "$n" -gt 0 ] && hit "trufflehog: $n verified secret(s)" || ok "trufflehog: clean"
}

_run_noseyparker() {
  local target="$1"
  log "noseyparker scan $target"
  local datastore="$OUT_DIR/.np-datastore"
  noseyparker scan --datastore "$datastore" "$target" >/dev/null 2>&1 || true
  noseyparker report --datastore "$datastore" --format jsonl > "$OUT_DIR/noseyparker.jsonl" 2>/dev/null || true
  local n; n=$(wc -l < "$OUT_DIR/noseyparker.jsonl" | tr -d ' ')
  [ "$n" -gt 0 ] && hit "noseyparker: $n match group(s)" || ok "noseyparker: clean"
}

_run_gitleaks() {
  local target="$1" subcmd="$2"
  log "gitleaks $subcmd $target"
  gitleaks "$subcmd" --source "$target" --report-format json --report-path "$OUT_DIR/gitleaks.json" --redact \
    >/dev/null 2>&1 || true
  if [ -s "$OUT_DIR/gitleaks.json" ]; then
    local n; n=$(python3 -c "import json; print(len(json.load(open('$OUT_DIR/gitleaks.json'))))" 2>/dev/null || echo 0)
    [ "$n" -gt 0 ] && hit "gitleaks: $n leak(s)" || ok "gitleaks: clean"
  fi
}

case "$MODE" in
  fs)
    _have trufflehog  && _run_trufflehog  "$TARGET" filesystem
    _have noseyparker && _run_noseyparker "$TARGET"
    _have gitleaks    && _run_gitleaks    "$TARGET" detect
    ;;
  git)
    _have trufflehog  && _run_trufflehog  "$TARGET" git
    _have noseyparker && _run_noseyparker "$TARGET"
    _have gitleaks    && _run_gitleaks    "$TARGET" detect
    ;;
  js)
    # Pull every .js fetched during recon and grep with regex + (if available)
    # trufflehog filesystem mode. Recon stores raw contents inline only for the
    # secrets-grep step, so we re-fetch top JS bundles here for verification.
    JS_LIST="$TARGET/urls/js_files.txt"
    [ -s "$JS_LIST" ] || { err "no js_files.txt under $TARGET"; exit 1; }
    JS_DIR="$OUT_DIR/js_bundles"
    mkdir -p "$JS_DIR"
    log "Downloading top 100 JS bundles for offline scanning..."
    head -100 "$JS_LIST" | while IFS= read -r url; do
      [ -z "$url" ] && continue
      fname=$(echo "$url" | tr '/?:&=#' '_' | head -c 200)
      curl -sk --max-time 10 "$url" -o "$JS_DIR/$fname.js" 2>/dev/null || true
    done
    _have trufflehog  && _run_trufflehog  "$JS_DIR" filesystem
    _have noseyparker && _run_noseyparker "$JS_DIR"
    # Fallback regex pass — runs even without trufflehog/noseyparker installed
    log "Regex fallback grep over downloaded JS..."
    grep -rEho '(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|bearer)["\s:=]+[a-zA-Z0-9_\-]{20,}' \
      "$JS_DIR" | sort -u > "$OUT_DIR/regex_hits.txt" 2>/dev/null || true
    n=$(wc -l < "$OUT_DIR/regex_hits.txt" | tr -d ' ')
    [ "$n" -gt 0 ] && hit "regex: $n potential secret(s) — manual triage required" || ok "regex: clean"
    ;;
  ghorg)
    _have trufflehog || { err "trufflehog required for --github-org"; exit 1; }
    [ -z "${GITHUB_TOKEN:-}" ] && warn "GITHUB_TOKEN unset — trufflehog will rate-limit fast"
    _run_trufflehog "$TARGET" github
    ;;
esac

ok "Done. Open $OUT_DIR/ for raw output."
