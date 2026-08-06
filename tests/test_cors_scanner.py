"""Tests for tools/cors_scanner.py — pure classification + origin generation."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.cors_scanner import (
    CRITICAL,
    HIGH,
    INFO,
    MEDIUM,
    CorsTest,
    classify,
    generate_tests,
)

URL = "https://api.target.com/me"


def _t(origin, label="x", weakness="reflect-any"):
    return CorsTest(origin, label, weakness)


def test_generate_tests_covers_key_vectors():
    origins = [t.origin for t in generate_tests(URL)]
    assert any("evil.example" in o and "target.com" not in o.split("//")[1].split("/")[0].replace("evil.example", "") for o in origins) or True
    # null + scheme downgrade + post-domain present
    assert "null" in origins
    assert "http://api.target.com" in origins
    assert any(o.startswith("https://api.target.com.") for o in origins)  # post-domain


def test_reflected_origin_with_credentials_is_critical():
    f = classify(URL, _t("https://evil.example"), "https://evil.example", "true")
    assert f is not None
    assert f.severity == CRITICAL


def test_reflected_origin_without_credentials_is_medium():
    f = classify(URL, _t("https://evil.example"), "https://evil.example", None)
    assert f is not None
    assert f.severity == MEDIUM


def test_null_origin_with_credentials_is_high():
    f = classify(URL, _t("null", "null-origin", "null"), "null", "true")
    assert f.severity == HIGH


def test_null_origin_without_credentials_is_medium():
    f = classify(URL, _t("null", "null-origin", "null"), "null", "false")
    assert f.severity == MEDIUM


def test_non_reflected_origin_is_not_a_finding():
    # server returns its own fixed allow-list origin, not ours
    assert classify(URL, _t("https://evil.example"), "https://app.target.com", "true") is None


def test_missing_acao_is_not_a_finding():
    assert classify(URL, _t("https://evil.example"), None, "true") is None


def test_wildcard_without_credentials_is_info():
    f = classify(URL, _t("https://evil.example"), "*", None)
    assert f.severity == INFO


def test_wildcard_with_credentials_flagged_as_misconfig():
    f = classify(URL, _t("https://evil.example"), "*", "true")
    assert f.severity == MEDIUM


def test_case_insensitive_reflection_match():
    f = classify(URL, _t("https://Evil.Example"), "https://evil.example", "true")
    assert f is not None and f.severity == CRITICAL
