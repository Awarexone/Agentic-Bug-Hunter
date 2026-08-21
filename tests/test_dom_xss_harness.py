"""Tests for tools/dom_xss_harness.py — pure payloads, URL injection, verdicts.

Never imports Playwright (that lives inside run()), so the suite needs no
browser installed.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.dom_xss_harness import (
    CONFIRMED,
    POSSIBLE,
    Payload,
    canary,
    classify,
    discover_params,
    dom_payloads,
    inject,
)


def test_canary_is_unique_and_greppable():
    a, b = canary(), canary()
    assert a != b
    assert a.startswith("cbbx") and len(a) > 8


def test_dom_payloads_cover_key_sinks_and_carry_marker():
    payloads = dom_payloads("q", "cbbxDEADBEEF")
    vectors = {p.vector for p in payloads}
    assert {"img-onerror", "svg-onload", "script-tag", "js-uri"} <= vectors
    assert all("cbbxDEADBEEF" in p.raw for p in payloads)
    assert all(p.param == "q" for p in payloads)


def test_discover_params_reads_query_and_fragment():
    names = discover_params("https://t.com/s?q=1&page=2#name=x&q=y")
    assert "q" in names and "page" in names and "name" in names
    assert names.count("q") == 1  # deduped across query + fragment


def test_inject_into_query_param():
    out = inject("https://t.com/s?q=test&p=1", "q", '"><svg onload=1>')
    assert "p=1" in out
    assert "q=" in out and "svg" in out
    assert out.startswith("https://t.com/s?")


def test_inject_preserves_fragment_sink():
    out = inject("https://t.com/app#name=test", "name", "PAYLOAD")
    assert "#name=" in out
    assert "PAYLOAD" in out
    assert "?" not in out.split("#")[0]  # payload stayed in the fragment, not the query


def test_classify_confirmed_when_marker_fires():
    p = Payload("cbbxAAAA", "q", "svg-onload", "x")
    f = classify("u", p, {"cbbxAAAA"}, "<html></html>")
    assert f is not None and f.severity == CONFIRMED


def test_classify_possible_when_reflected_not_executed():
    p = Payload("cbbxBBBB", "q", "img-onerror", "x")
    f = classify("u", p, set(), "<div>cbbxBBBB</div>")
    assert f is not None and f.severity == POSSIBLE


def test_classify_none_when_absent():
    p = Payload("cbbxCCCC", "q", "js-uri", "x")
    assert classify("u", p, set(), "<html>nothing</html>") is None


def test_classify_prefers_execution_over_reflection():
    # Marker both reflected AND executed -> CONFIRMED, not POSSIBLE.
    p = Payload("cbbxDDDD", "q", "script-tag", "x")
    f = classify("u", p, {"cbbxDDDD"}, "<div>cbbxDDDD</div>")
    assert f.severity == CONFIRMED
