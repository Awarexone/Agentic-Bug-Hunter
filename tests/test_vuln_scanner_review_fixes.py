"""Regression checks for the PR #7 review fixes in tools/vuln_scanner.sh."""

from pathlib import Path


SCANNER_PATH = Path(__file__).resolve().parents[1] / "tools" / "vuln_scanner.sh"


def test_saml_signature_stripping_is_opt_in_and_policy_gated():
    scanner = SCANNER_PATH.read_text()

    assert "SafeMethodPolicy" in scanner
    assert "ALLOW_UNSAFE_HTTP_TESTS" in scanner
    assert 'unsafe_method_guard "POST" "$BASE" "MFA rate-limit probe"' in scanner
    assert 'unsafe_method_guard "POST" "$BASE" "MFA response-manipulation canary"' in scanner
    assert 'unsafe_method_guard "POST" "$ACS_URL" "SAML signature-stripping probe"' in scanner


def test_scanner_uses_current_repo_paths():
    scanner = SCANNER_PATH.read_text()

    assert 'BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"' in scanner
    assert 'DEFAULT_FINDINGS_DIR="$BASE_DIR/findings/$TARGET"' in scanner
    assert 'head -20 "$RECON_DIR/live/urls.txt"' in scanner
    assert "httpx_live.txt" not in scanner
