"""Tests for tools/nosqli_scanner.py — payloads + differential/timing logic."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.nosqli_scanner import (
    auth_bypass_bodies,
    classify_differential,
    classify_timing,
    query_string_payloads,
    where_sleep_body,
)


def test_auth_bypass_bodies_use_operators():
    bodies = auth_bypass_bodies("email", "password")
    assert {"email": {"$ne": None}, "password": {"$ne": None}} in bodies
    # known-user + wildcard-pass variant present
    assert any(b.get("email") == "admin" for b in bodies)


def test_query_string_payloads_bracket_syntax():
    payloads = query_string_payloads("user")
    assert "user[$ne]=" in payloads
    assert "user[$regex]=.*" in payloads


def test_where_sleep_body_shape():
    body = where_sleep_body("u", "p", ms=5000)
    assert body["p"] == {"$where": "sleep(5000)"}


def test_differential_flips_from_403_to_200():
    assert classify_differential(403, 50, 200, 800) is True


def test_differential_same_status_big_length_change():
    assert classify_differential(200, 100, 200, 900) is True


def test_differential_no_change_is_negative():
    assert classify_differential(401, 50, 401, 52) is False


def test_timing_detects_sleep():
    assert classify_timing(120.0, 5200.0, sleep_ms=5000) is True


def test_timing_ignores_normal_jitter():
    assert classify_timing(120.0, 300.0, sleep_ms=5000) is False
