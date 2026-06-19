"""Tests for tools/jwt_scanner.py — offline JWT forging + analysis."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.jwt_scanner import (
    analyze,
    b64url_encode,
    crack_secret,
    decode,
    forge_alg_none,
    forge_hs256_with_key,
    _encode_segment,
)


def _make_hs256(payload, secret, header=None):
    """Build a valid HS256 token using the tool's own primitives."""
    return forge_hs256_with_key(
        f"{_encode_segment(header or {'alg': 'HS256', 'typ': 'JWT'})}."
        f"{_encode_segment(payload)}.",
        secret.encode(),
    )


def test_decode_roundtrip():
    tok = _make_hs256({"sub": "1", "role": "user"}, "s3cret")
    header, payload, sig = decode(tok)
    assert header["alg"] == "HS256"
    assert payload["role"] == "user"
    assert sig


def test_alg_none_strips_signature():
    tok = _make_hs256({"sub": "1"}, "k")
    forgeries = forge_alg_none(tok)
    assert len(forgeries) == 4  # none/None/NONE/nOnE
    for f in forgeries:
        assert f.endswith(".")  # empty signature
        h, _, _ = decode(f)
        assert h["alg"].lower() == "none"


def test_crack_secret_finds_weak_key():
    tok = _make_hs256({"sub": "1"}, "password")
    assert crack_secret(tok, ["admin", "letmein", "password", "x"]) == "password"


def test_crack_secret_miss_returns_none():
    tok = _make_hs256({"sub": "1"}, "super-rare-secret")
    assert crack_secret(tok, ["admin", "letmein"]) is None


def test_crack_only_for_hs256():
    # an RS256 header must not be brute-forced as HMAC
    rs = f"{_encode_segment({'alg': 'RS256'})}.{_encode_segment({'sub': '1'})}.AAAA"
    assert crack_secret(rs, ["anything"]) is None


def test_confusion_forge_is_valid_hs256_under_pubkey():
    tok = _make_hs256({"sub": "1", "role": "user"}, "orig")
    pub = b"-----BEGIN PUBLIC KEY-----\nMIIBfake\n-----END PUBLIC KEY-----\n"
    forged = forge_hs256_with_key(tok, pub, {"role": "admin"})
    # the forged token verifies when the pubkey bytes are used as the secret
    assert crack_secret(forged, [pub.decode()]) == pub.decode()
    _, payload, _ = decode(forged)
    assert payload["role"] == "admin"


def test_analyze_flags_alg_none():
    tok = f"{_encode_segment({'alg': 'none'})}.{_encode_segment({'sub': '1'})}."
    sevs = [i.severity for i in analyze(tok)]
    assert "CRITICAL" in sevs


def test_analyze_flags_missing_exp_and_role_claim():
    tok = _make_hs256({"sub": "1", "role": "admin"}, "k")
    titles = " ".join(i.title for i in analyze(tok))
    assert "exp" in titles
    assert "role" in titles
