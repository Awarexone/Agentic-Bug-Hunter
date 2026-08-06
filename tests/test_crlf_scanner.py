"""Tests for tools/crlf_scanner.py — payloads, detection, host-header sets."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.crlf_scanner import (
    CANARY,
    crlf_payloads,
    detect_injection,
    host_header_payloads,
)


def test_payloads_include_encoded_and_utf8_bypass():
    payloads = crlf_payloads()
    joined = "\n".join(payloads)
    assert "%0d%0a" in joined           # encoded CRLF
    assert "%250d%250a" in joined       # double-encoded
    assert "%E5%98%8A%E5%98%8D" in joined  # UTF-8 overlong bypass
    assert all(CANARY in p for p in payloads)


def test_detect_injection_matches_canary_setcookie():
    headers = {"Set-Cookie": f"{CANARY}=1; Path=/", "Content-Type": "text/html"}
    assert detect_injection(headers) is not None


def test_detect_injection_case_insensitive_header():
    headers = {"set-cookie": f"{CANARY}=1"}
    assert detect_injection(headers) is not None


def test_detect_injection_ignores_unrelated_setcookie():
    headers = {"Set-Cookie": "session=abc123; HttpOnly"}
    assert detect_injection(headers) is None


def test_detect_injection_handles_spaces():
    headers = {"Set-Cookie": f"{CANARY} = 1"}
    assert detect_injection(headers) is not None


def test_host_header_payloads_include_forwarding_variants():
    sets = host_header_payloads("target.com")
    keys = [tuple(sorted(s.keys())) for s in sets]
    assert ("Host",) in keys
    assert any("X-Forwarded-Host" in s for s in sets)
    assert any("Forwarded" in s for s in sets)
