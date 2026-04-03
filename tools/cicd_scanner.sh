#!/bin/bash
# =============================================================================
# CI/CD Workflow Scanner (sisakulint wrapper)
# Scans GitHub Actions workflows for security issues via sisakulint -remote
# Usage: ./cicd_scanner.sh <owner/repo | "org:name"> [options]
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }

usage() {
    cat <<EOF
Usage: $(basename "$0") <target> [options]

Target formats:
  owner/repo          Single repository
  "org:orgname"       All repos in an organization
  https://github.com/owner/repo  GitHub URL (auto-normalized)

Options:
  -r, --recursive     Scan reusable workflows recursively
  -d, --depth N       Max recursion depth (default: 3)
  -l, --limit N       Max repos for org search (default: 30)
  -p, --parallel N    Parallel scan count (default: 3)
  -o, --output-dir D  Override output directory
  -h, --help          Show this help

Examples:
  $(basename "$0") torvalds/linux
  $(basename "$0") "org:kubernetes" --recursive --depth 5
  $(basename "$0") https://github.com/actions/runner --output-dir /tmp/scan
EOF
    exit 0
}

# Defaults
RECURSIVE=""
DEPTH=3
LIMIT=30
PARALLEL=3
OUTPUT_DIR=""

# Parse target
TARGET="${1:-}"
[ -z "$TARGET" ] && { log_err "No target specified"; usage; }
[ "$TARGET" = "-h" ] || [ "$TARGET" = "--help" ] && usage
shift

# Parse options
while [ $# -gt 0 ]; do
    case "$1" in
        -r|--recursive) RECURSIVE="-r"; shift ;;
        -d|--depth) DEPTH="$2"; shift 2 ;;
        -l|--limit) LIMIT="$2"; shift 2 ;;
        -p|--parallel) PARALLEL="$2"; shift 2 ;;
        -o|--output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) log_err "Unknown option: $1"; usage ;;
    esac
done

# Normalize GitHub URLs to owner/repo
TARGET=$(echo "$TARGET" | sed -E 's|^https?://github\.com/||' | sed 's|/$||' | sed 's|\.git$||')

# Check sisakulint
if ! command -v sisakulint &>/dev/null; then
    log_err "sisakulint not found."
    log_err "Install: bash install_tools.sh"
    log_err "Or manually: https://github.com/sisaku-security/sisakulint/releases"
    exit 1
fi

# Determine output directory (default: ./findings/<target>/cicd/ relative to cwd)
if [ -z "$OUTPUT_DIR" ]; then
    TARGET_SLUG=$(echo "$TARGET" | sed 's|[:/]|_|g')
    OUTPUT_DIR="$(pwd)/findings/$TARGET_SLUG/cicd"
fi
mkdir -p "$OUTPUT_DIR"

SCAN_RESULTS="$OUTPUT_DIR/scan_results.txt"
SUMMARY="$OUTPUT_DIR/summary.txt"

echo "============================================="
echo "  CI/CD Workflow Scanner"
echo "  Target: $TARGET"
echo "  Output: $OUTPUT_DIR/"
echo "  Time:   $(date)"
echo "============================================="
echo ""

# Build sisakulint command
CMD="sisakulint -remote \"$TARGET\" -D $DEPTH -l $LIMIT -p $PARALLEL"
[ -n "$RECURSIVE" ] && CMD="$CMD -r"

log_info "Running: $CMD"
echo ""

# Run sisakulint and capture output (don't fail on non-zero exit — findings cause exit 1)
eval "$CMD" 2>&1 | tee "$SCAN_RESULTS" || true

echo ""

# Generate summary
# Finding lines contain path:line:col: pattern
TOTAL=$(grep -cP '\.github/workflows/[^:]+:\d+:\d+:' "$SCAN_RESULTS" 2>/dev/null | tail -1 || echo "0")
TOTAL="${TOTAL##*:}"  # strip filename prefix if grep adds one
[ -z "$TOTAL" ] && TOTAL=0
{
    echo "============================================="
    echo "  CI/CD Scan Summary"
    echo "  Target: $TARGET"
    echo "  Date:   $(date)"
    echo "============================================="
    echo ""
    echo "Total findings: $TOTAL"
    echo ""

    if [ "$TOTAL" -gt 0 ]; then
        echo "--- By Rule ---"
        grep -oP '\[[-a-z0-9]+\]\s*$' "$SCAN_RESULTS" 2>/dev/null | tr -d '[]' | \
            sort | uniq -c | sort -rn || true
        echo ""
        echo "--- Affected Files ---"
        grep -oP '[^/]+/\.github/workflows/[^:]+' "$SCAN_RESULTS" 2>/dev/null | \
            sed 's|^[^/]*/||' | sort -u || true
    else
        echo "No findings detected."
    fi
} > "$SUMMARY"

echo ""
cat "$SUMMARY"

echo ""
echo "============================================="
echo "  Full results: $SCAN_RESULTS"
echo "  Summary:      $SUMMARY"
echo "============================================="
