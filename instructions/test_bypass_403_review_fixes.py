"""Regression checks for the response-normalization bypass probe."""

from pathlib import Path


BYPASS_PATH = Path(__file__).resolve().parents[1] / "tools" / "bypass_403.sh"


def test_bypass_probe_normalizes_dynamic_bodies_before_comparing():
    scanner = BYPASS_PATH.read_text()

    assert "_normalize_body()" in scanner
    assert "orig_norm" in scanner
    assert "bypass_norm" in scanner
    assert '[ "$bypass_norm" = "$orig_norm" ]' in scanner
    assert "baseline_code=$orig_code" in scanner


def test_bypass_probe_keeps_confidence_tiers():
    scanner = BYPASS_PATH.read_text()

    assert '[CONFIRMED]' in scanner
    assert '[POSSIBLE]' in scanner
    assert '[INFORMATIONAL]' in scanner
