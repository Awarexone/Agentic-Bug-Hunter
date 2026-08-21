"""Regression checks for the 403/401 bypass probe's confidence model.

PR #40 replaced the earlier token-normalizing body comparison
(`_normalize_body` + `[CONFIRMED]/[POSSIBLE]/[INFORMATIONAL]` tiers) with a
broader WAF-aware verdict pipeline: sample a block baseline, reject responses
that match a WAF block signature, require the body length to diverge from the
baseline, and split results into confirmed (`bypass_hits.txt`) vs needs-review
(`bypass_uncertain.txt`). These tests guard that newer mechanism so a future
rewrite can't silently drop the "is this a real bypass or still a block page?"
check that keeps false positives out of findings.
"""

from pathlib import Path


BYPASS_PATH = Path(__file__).resolve().parents[1] / "tools" / "bypass_403.sh"


def test_bypass_probe_baselines_and_compares_against_block_page():
    scanner = BYPASS_PATH.read_text()

    # A block baseline is sampled and reused for divergence comparison.
    assert "_sample_block_baseline()" in scanner
    assert ".block_baseline.len" in scanner
    # The verdict function gates on status, WAF signatures, and length divergence.
    assert "_is_real_bypass()" in scanner
    assert "_WAF_BLOCK_REGEX" in scanner
    # Body length must diverge from the block baseline (not just any 200).
    assert "body_len - bb_len" in scanner or "bb_len - body_len" in scanner


def test_bypass_probe_separates_confirmed_from_uncertain():
    scanner = BYPASS_PATH.read_text()

    # Confirmed bypasses and "200 body may still be a block page" are kept apart.
    assert "bypass_hits.txt" in scanner
    assert "bypass_uncertain.txt" in scanner
    # A per-response verdict is computed rather than trusting the status code alone.
    assert "_classify_with_analyzer" in scanner or "_is_real_bypass" in scanner
