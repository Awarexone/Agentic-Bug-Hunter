#!/usr/bin/env python3
"""
CORS misconfiguration scanner.

Sends a battery of crafted `Origin` headers to a URL and inspects the
`Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials`
(ACAC) response headers to find origins the server wrongly trusts.

The classification logic (origin generation + verdict) is pure and unit-tested;
only `scan()` touches the network.

Severity model:
  CRITICAL  reflects an attacker origin AND allows credentials -> cookie-auth'd
            cross-origin reads. Full account-data exfil.
  HIGH      `null` origin trusted with credentials (sandboxed iframe / data: URI
            attack), OR sibling/suffix-domain trusted with credentials.
  MEDIUM    reflects attacker origin without credentials (token-auth data read),
            OR trusts http:// downgrade of an https origin.
  LOW       ACAO: * with no credentials (public CORS — usually intended).

Usage:
  tools/cors_scanner.py https://api.target.com/me
  tools/cors_scanner.py -l urls.txt --json
  tools/cors_scanner.py https://api.target.com/me --cookie "session=..."
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
from tools.safe_http import safe_urlopen  # noqa: E402

USER_AGENT = "agentic-bug-hunter/cors_scanner"

CRITICAL, HIGH, MEDIUM, LOW, INFO = "CRITICAL", "HIGH", "MEDIUM", "MEDIUM_LOW", "INFO"


@dataclass
class CorsTest:
    """A single Origin to send and the weakness it proves if reflected."""

    origin: str
    label: str
    weakness: str  # which misconfig class this origin probes


@dataclass
class CorsFinding:
    url: str
    origin_sent: str
    acao: str | None
    acac: bool
    severity: str
    title: str
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "origin_sent": self.origin_sent,
            "acao": self.acao,
            "acac": self.acac,
            "severity": self.severity,
            "title": self.title,
            "note": self.note,
        }


def _registrable(host: str) -> str:
    """Best-effort 'evil-attached' base for suffix/prefix tricks (no PSL dep)."""
    return host


def generate_tests(url: str, attacker: str = "evil.example") -> list[CorsTest]:
    """Generate the standard CORS probe origins for a target URL.

    Covers: arbitrary-origin reflection, null origin, pre/post-domain bypass,
    suffix/prefix regex weakness, scheme downgrade, and not-quite-target.
    """
    host = (urlparse(url).hostname or "").lower()
    scheme = urlparse(url).scheme or "https"
    tests: list[CorsTest] = [
        CorsTest(f"{scheme}://{attacker}", "arbitrary", "reflect-any"),
        CorsTest("null", "null-origin", "null"),
    ]
    if host:
        # post-domain: target.com.evil.example  (weak endsWith / startsWith)
        tests.append(
            CorsTest(f"{scheme}://{host}.{attacker}", "post-domain", "suffix-regex")
        )
        # pre-domain: eviltarget.com style — attacker registers <random>host
        tests.append(
            CorsTest(f"{scheme}://not{host}", "pre-domain", "prefix-regex")
        )
        # sibling subdomain an attacker might control via takeover
        tests.append(
            CorsTest(f"{scheme}://attacker.{host}", "subdomain", "subdomain-trust")
        )
        # scheme downgrade — trusting http:// of an https app
        if scheme == "https":
            tests.append(
                CorsTest(f"http://{host}", "scheme-downgrade", "http-downgrade")
            )
        # embedded-target trick: evil.example?target.com / evil.example#target.com
        tests.append(
            CorsTest(
                f"{scheme}://{attacker}.{host.split('.')[-1] if '.' in host else attacker}",
                "tld-suffix",
                "suffix-regex",
            )
        )
    return tests


def classify(
    url: str,
    test: CorsTest,
    acao: str | None,
    acac_raw: str | None,
) -> CorsFinding | None:
    """Decide whether an ACAO/ACAC response to `test` is a vuln. Pure function."""
    if acao is None:
        return None
    acac = (acac_raw or "").strip().lower() == "true"
    sent = test.origin

    # ACAO: * — wildcard. Browsers reject *+credentials, so creds case is moot.
    if acao.strip() == "*":
        if acac:
            return CorsFinding(
                url, sent, acao, acac, MEDIUM,
                "Wildcard ACAO with credentials (browser-rejected but misconfigured)",
                "ACAO:* + ACAC:true is invalid per spec; signals a broken CORS layer.",
            )
        return CorsFinding(
            url, sent, acao, acac, INFO,
            "Public wildcard CORS (ACAO: *)",
            "Only a finding if the endpoint returns sensitive data without a cookie.",
        )

    reflected = acao.strip().lower() == sent.strip().lower()
    if not reflected:
        return None  # server returned some fixed allow-list origin, not ours

    # From here: the server reflected exactly the attacker-chosen origin.
    if sent == "null":
        sev = HIGH if acac else MEDIUM
        return CorsFinding(
            url, sent, acao, acac, sev,
            "`null` origin reflected" + (" with credentials" if acac else ""),
            "Reachable from a sandboxed iframe / data: URI; "
            + ("cookies are sent cross-origin." if acac else "no credentials."),
        )

    if acac:
        return CorsFinding(
            url, sent, acao, acac, CRITICAL,
            f"Arbitrary origin reflected with credentials ({test.label})",
            "Attacker page can read authenticated responses cross-origin "
            "(full account-data exfil).",
        )
    sev = MEDIUM if test.weakness in {"reflect-any", "suffix-regex", "prefix-regex"} else MEDIUM
    return CorsFinding(
        url, sent, acao, acac, sev,
        f"Arbitrary origin reflected without credentials ({test.label})",
        "Exploitable if the endpoint is authorized by a non-cookie token "
        "the attacker page can supply, or returns sensitive data unauthenticated.",
    )


def _fetch_cors(url: str, origin: str, cookie: str | None, timeout: int) -> tuple[str | None, str | None]:
    """Send a GET with the given Origin; return (ACAO, ACAC) response headers."""
    headers = {"User-Agent": USER_AGENT, "Origin": origin}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with safe_urlopen(req, timeout=timeout) as resp:
            return (
                resp.headers.get("Access-Control-Allow-Origin"),
                resp.headers.get("Access-Control-Allow-Credentials"),
            )
    except urllib.error.HTTPError as e:  # still has CORS headers on 4xx/5xx
        return (
            e.headers.get("Access-Control-Allow-Origin") if e.headers else None,
            e.headers.get("Access-Control-Allow-Credentials") if e.headers else None,
        )
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return (None, None)


def scan(url: str, cookie: str | None = None, timeout: int = 15) -> list[CorsFinding]:
    findings: list[CorsFinding] = []
    for test in generate_tests(url):
        acao, acac = _fetch_cors(url, test.origin, cookie, timeout)
        f = classify(url, test, acao, acac)
        if f:
            findings.append(f)
    return findings


_SEV_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, INFO: 4}


def _print_human(url: str, findings: list[CorsFinding]) -> None:
    if not findings:
        print(f"[ok] {url} — no CORS misconfiguration detected")
        return
    real = [f for f in findings if f.severity != INFO]
    for f in sorted(findings, key=lambda x: _SEV_ORDER.get(x.severity, 3)):
        print(f"[{f.severity}] {f.title}")
        print(f"    url:    {f.url}")
        print(f"    origin: {f.origin_sent}  ->  ACAO: {f.acao}  ACAC: {f.acac}")
        if f.note:
            print(f"    note:   {f.note}")
    if real:
        print(f"\n{len(real)} actionable CORS finding(s) on {url}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CORS misconfiguration scanner")
    ap.add_argument("url", nargs="?", help="target URL")
    ap.add_argument("-l", "--list", help="file of URLs (one per line)")
    ap.add_argument("--cookie", help="Cookie header to send (test credentialed CORS)")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    urls: list[str] = []
    if args.list:
        urls += [l.strip() for l in Path(args.list).read_text().splitlines() if l.strip()]
    if args.url:
        urls.append(args.url)
    if not urls:
        ap.error("provide a URL or -l <file>")

    all_findings: list[CorsFinding] = []
    for u in urls:
        fs = scan(u, cookie=args.cookie, timeout=args.timeout)
        all_findings += fs
        if not args.json:
            _print_human(u, fs)

    if args.json:
        print(json.dumps([f.as_dict() for f in all_findings], indent=2))
    # exit 2 if any actionable (non-INFO) finding — useful in pipelines
    return 2 if any(f.severity != INFO for f in all_findings) else 0


if __name__ == "__main__":
    sys.exit(main())
