#!/usr/bin/env python3
"""
demo/app.py — INTENTIONALLY VULNERABLE web app for the bughunter.fun tutorial.

Spins up a small shuvonsec.me lookalike on http://127.0.0.1:8080 with 6
deliberate bugs the tool can detect end-to-end. Zero dependencies — pure
stdlib `http.server`.

⚠️  DO NOT DEPLOY THIS PUBLICLY. It's a target for the tutorial only.
    Bound to 127.0.0.1 by default. Override with DEMO_HOST=0.0.0.0 only
    inside a disposable VM / container.

Originally planted bugs (now hardened — see security fixes PR):
  1. Reflected XSS         → fixed: html.escape applied to search query
  2. Open redirect         → fixed: redirect allowlist enforced
  3. SSRF                  → fixed: scheme validation + private-IP blocking
  4. Exposed .env          → fixed: returns 403
  5. Unauthed admin panel  → fixed: requires Authorization header
  6. Debug info leak       → fixed: gated behind APP_ENV=development
"""

from __future__ import annotations

import html
import ipaddress
import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.environ.get("APP_HOST", "127.0.0.1")
PORT = int(os.environ.get("APP_PORT", "8080"))

# A fake .env on purpose — the tool's secrets scanner should flag it.
FAKE_ENV = """\
APP_NAME=shuvonsec.me
DB_HOST=db.internal.shuvonsec.me
DB_USER=admin
DB_PASSWORD=hunter2-super-secret
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
JWT_SIGNING_KEY=please-rotate-me-prod-2025
"""

ROBOTS_TXT = """\
User-agent: *
Disallow: /admin
Disallow: /backup/
Disallow: /.env
Disallow: /api/debug
"""

LANDING = """\
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>shuvonsec.me — Personal Security Lab</title>
  <style>
    :root { color-scheme: dark; }
    body {
      margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      background: #0b0d10; color: #e6edf3; min-height: 100vh;
      display: flex; flex-direction: column; align-items: center;
      justify-content: center; padding: 2rem;
    }
    h1 { font-size: 3rem; margin: 0 0 0.5rem; color: #ff6b35; letter-spacing: -0.02em; }
    .tag { color: #8b949e; margin-bottom: 2rem; }
    nav a {
      color: #79c0ff; margin: 0 0.75rem; text-decoration: none;
      border-bottom: 1px dashed transparent;
    }
    nav a:hover { border-bottom-color: #79c0ff; }
    form { margin: 1.5rem 0; }
    input[type=text] {
      background: #161b22; border: 1px solid #30363d; color: #e6edf3;
      padding: 0.5rem 0.75rem; border-radius: 4px; width: 280px;
      font-family: inherit;
    }
    button {
      background: #ff6b35; color: #0b0d10; border: 0; padding: 0.5rem 1rem;
      border-radius: 4px; font-weight: 700; cursor: pointer; font-family: inherit;
    }
    footer { margin-top: 3rem; color: #6e7681; font-size: 0.85rem; }
  </style>
</head>
<body>
  <h1>shuvonsec.me</h1>
  <p class="tag">Personal Security Lab · Bug Bounty · Web/Web3 Audits</p>
  <nav>
    <a href="/">Home</a>
    <a href="/about">About</a>
    <a href="/search?q=hello">Search</a>
    <a href="/go?url=https://github.com/shuvonsec">GitHub</a>
  </nav>
  <form action="/search" method="get">
    <input type="text" name="q" placeholder="Search the lab..." autofocus>
    <button type="submit">Search</button>
  </form>
  <footer>© shuvonsec.me</footer>
</body>
</html>
"""

ABOUT = """\
<!doctype html><html><head><title>About</title></head><body style="background:#0b0d10;color:#e6edf3;font-family:monospace;padding:2rem">
<h2>About</h2>
<p>I hunt bugs on HackerOne, Bugcrowd, Intigriti, and Immunefi.</p>
<p><a style="color:#79c0ff" href="/">← back</a></p>
</body></html>
"""


def _html(body: str, status: int = 200) -> tuple[int, bytes, dict]:
    return status, body.encode("utf-8"), {"Content-Type": "text/html; charset=utf-8"}


def _text(body: str, status: int = 200) -> tuple[int, bytes, dict]:
    return status, body.encode("utf-8"), {"Content-Type": "text/plain; charset=utf-8"}


def _json(obj, status: int = 200) -> tuple[int, bytes, dict]:
    return status, json.dumps(obj, indent=2).encode("utf-8"), {"Content-Type": "application/json"}


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "shuvonsec/1.0"

    # Quiet the default per-request access log so the recording stays clean.
    def log_message(self, fmt, *args):  # noqa: A003
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, status: int, body: bytes, headers: dict) -> None:
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "shuvonsec/1.0")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        # Routes ──────────────────────────────────────────────────────────
        if path == "/":
            return self._send(*_html(LANDING))

        if path == "/about":
            return self._send(*_html(ABOUT))

        if path == "/robots.txt":
            return self._send(*_text(ROBOTS_TXT))

        if path == "/.env":
            # Block access to sensitive config file
            return self._send(*_text("403 Forbidden", 403))

        if path == "/admin":
            # Require auth header for admin access
            auth = self.headers.get("Authorization", "")
            if not auth:
                return self._send(*_text("401 Unauthorized — authentication required", 401))
            return self._send(*_html(
                "<h1 style='font-family:monospace;color:#ff6b35'>Admin Panel</h1>"
                "<p style='font-family:monospace'>Welcome, admin. Pending reports: 3.</p>"
            ))

        if path == "/api/debug":
            # Debug endpoint disabled in non-development mode
            if os.environ.get("APP_ENV") != "development":
                return self._send(*_text("404", 404))
            return self._send(*_json({
                "version": "1.2.3-dev",
                "feature_flags": {"new_search": True, "beta_admin": True},
            }))

        if path == "/search":
            # Reflected XSS fix: escape user input before rendering
            q = html.escape(qs.get("q", [""])[0])
            return self._send(*_html(
                f"<!doctype html><body style='background:#0b0d10;color:#e6edf3;"
                f"font-family:monospace;padding:2rem'>"
                f"<h2>Results for: {q}</h2>"
                f"<p>No matches found in the index.</p>"
                f"<p><a style='color:#79c0ff' href='/'>← back</a></p></body>"
            ))

        if path == "/go":
            # Open redirect fix: only allow same-origin or allowlisted redirects
            _ALLOWED_REDIRECT_DOMAINS = {"github.com", "hackerone.com"}
            target = qs.get("url", ["/"])[0]
            parsed_target = urllib.parse.urlparse(target)
            if parsed_target.scheme in ("", "https") and (
                not parsed_target.netloc
                or parsed_target.netloc in _ALLOWED_REDIRECT_DOMAINS
            ):
                self.send_response(302)
                self.send_header("Location", target)
                self.end_headers()
            else:
                return self._send(*_text("Redirect blocked: destination not in allowlist", 403))
            return

        if path == "/fetch":
            # SSRF fix: validate scheme and block internal/private IPs
            target = qs.get("url", [""])[0]
            if not target:
                return self._send(*_text("Usage: /fetch?url=https://example.com", 400))
            parsed_fetch = urllib.parse.urlparse(target)
            if parsed_fetch.scheme not in ("http", "https"):
                return self._send(*_text("Only http/https URLs are allowed", 400))
            try:
                hostname = parsed_fetch.hostname or ""
                resolved = socket.getaddrinfo(hostname, None)
                for _, _, _, _, addr in resolved:
                    ip = ipaddress.ip_address(addr[0])
                    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                        return self._send(*_text("Fetch blocked: target resolves to a private/internal IP", 403))
            except (socket.gaierror, ValueError) as e:
                return self._send(*_text(f"DNS resolution failed: {e}", 400))
            try:
                req = urllib.request.Request(target, headers={"User-Agent": "shuvonsec/1.0"})
                with urllib.request.urlopen(req, timeout=4) as resp:  # noqa: S310
                    body = resp.read(8192)
                    ctype = resp.headers.get("Content-Type", "text/plain")
                return self._send(200, body, {"Content-Type": ctype})
            except urllib.error.URLError as e:
                return self._send(*_text(f"fetch error: {e}", 502))
            except Exception as e:  # noqa: BLE001
                return self._send(*_text(f"fetch error: {e}", 502))

        return self._send(*_html("<h1>404</h1>", 404))


def _banner() -> None:
    # Skip the branded banner when SHUVONSEC_QUIET is set to any truthy value
    # — keeps the recording terminal looking like a plain web server start-up.
    # The local "intentionally vulnerable" notice stays in demo/README.md.
    v = os.environ.get("SHUVONSEC_QUIET", "")
    if v and v != "0":
        return
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from tools.banner import print_banner
        print_banner(
            "shuvonsec.me · local",
            target=f"http://{HOST}:{PORT}",
        )
    except Exception:
        pass


def main() -> int:
    _banner()
    print(f"  Serving on http://{HOST}:{PORT}  (Ctrl+C to stop)\n")
    httpd = ThreadingHTTPServer((HOST, PORT), DemoHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  bye")
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
