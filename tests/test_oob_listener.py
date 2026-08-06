"""Tests for tools/oob_listener.py — OOB payload generation + correlation."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.oob_listener import VULN_CLASSES, correlate, oob_payloads

DOMAIN = "abc123.oast.example"


def test_payloads_cover_all_classes():
    p = oob_payloads(DOMAIN)
    for c in VULN_CLASSES:
        assert c in p and p[c]


def test_payloads_embed_domain():
    p = oob_payloads(DOMAIN, ["ssrf"])
    assert all(DOMAIN in item["payload"] for item in p["ssrf"])


def test_class_filter():
    p = oob_payloads(DOMAIN, ["sqli", "rce"])
    assert set(p.keys()) == {"sqli", "rce"}


def test_log4shell_has_filter_bypass_variant():
    p = oob_payloads(DOMAIN, ["log4shell"])
    payloads = [i["payload"] for i in p["log4shell"]]
    assert any("lower:j" in x for x in payloads)


def test_markers_are_unique_per_class():
    p = oob_payloads(DOMAIN)
    markers = {c: items[0]["marker"] for c, items in p.items()}
    assert len(set(markers.values())) == len(markers)  # all distinct


def test_correlate_matches_interaction_to_class():
    payloads = oob_payloads(DOMAIN, ["ssrf"])
    left = payloads["ssrf"][0]["marker"].split(".")[0]  # e.g. ssrf-abcdef123456
    interactions = [{"full-id": f"{left}.{DOMAIN}", "protocol": "http"}]
    hits = correlate(interactions, payloads)
    assert len(hits) == 1
    assert hits[0].vuln_class == "ssrf"
    assert hits[0].protocol == "http"


def test_correlate_ignores_unrelated_interaction():
    payloads = oob_payloads(DOMAIN, ["ssrf"])
    interactions = [{"full-id": f"random-noise.{DOMAIN}", "protocol": "dns"}]
    assert correlate(interactions, payloads) == []
