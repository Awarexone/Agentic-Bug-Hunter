#!/bin/bash
# =============================================================================
# Tests for tools/cicd_scanner.sh
# Usage: bash tests/test_cicd_scanner.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CICD_SCANNER="$SCRIPT_DIR/tools/cicd_scanner.sh"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; ((FAIL++)) || true; }

echo "============================================="
echo "  cicd_scanner.sh tests"
echo "============================================="

# Test 1: Syntax check
echo ""
echo "[Test 1] bash -n syntax check"
if bash -n "$CICD_SCANNER" 2>/dev/null; then
    pass "No syntax errors"
else
    fail "Syntax errors detected"
fi

# Test 2: Help flag exits 0
echo ""
echo "[Test 2] --help exits 0"
"$CICD_SCANNER" --help &>/dev/null
if [ $? -eq 0 ]; then
    pass "--help exits 0"
else
    fail "--help should exit 0"
fi

# Test 3: No arguments shows error
echo ""
echo "[Test 3] No arguments shows error"
OUTPUT=$("$CICD_SCANNER" 2>&1) || true
if echo "$OUTPUT" | grep -q "No target specified"; then
    pass "Shows 'No target specified' error"
else
    fail "Should show 'No target specified' error"
fi

# Test 4: Usage mentions URL format
echo ""
echo "[Test 4] Usage mentions URL format"
HELP_OUTPUT=$("$CICD_SCANNER" --help 2>&1) || true
if echo "$HELP_OUTPUT" | grep -q "github.com"; then
    pass "Help mentions GitHub URL format"
else
    fail "Help should mention GitHub URL format"
fi

# Test 5: Unknown option handling
echo ""
echo "[Test 5] Unknown option shows error"
OUTPUT=$("$CICD_SCANNER" test/repo --invalid-flag 2>&1) || true
if echo "$OUTPUT" | grep -q "Unknown option"; then
    pass "Shows 'Unknown option' error"
else
    fail "Should show 'Unknown option' error"
fi

# Summary
echo ""
echo "============================================="
echo "  Results: $PASS passed, $FAIL failed"
echo "============================================="

[ "$FAIL" -eq 0 ] || exit 1
