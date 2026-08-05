#!/usr/bin/env python3
"""
browser_recon.py — Browser Intelligence Layer.

Playwright-driven recon for modern SPA targets (React/Next/Angular), where a
crawler-based pipeline misses most of the real attack surface: endpoints that
only exist post-login inside a rendered app, minified bundles that hide their
original source, and route tables the crawler never triggers because nothing
links to them directly.

Playwright is an OPTIONAL dependency (same pattern as tools/hai_probe.py's
`requests` guard): this module imports fine and its non-browser features work
with only `requests` (already a hard dependency) when Playwright isn't
installed. Browser-driven features call require_playwright() first and raise
a clear, actionable error instead of crashing.

Implemented in this pass (source-map recovery + hidden-endpoint discovery —
the two highest-value, lowest-risk pieces; see module docstring bottom for
what's still to come):

  2. SOURCE MAP RECOVERY -> recon/<target>/browser/sources/
     For each JS bundle in recon/<target>/urls/js_files.txt: fetch it, find
     its source map (sourceMappingURL comment or the conventional `.map`
     guess), unpack sourcesContent to recover original TS/JSX. Pure HTTP
     (requests), no browser needed.

  5. HIDDEN ENDPOINT DISCOVERY -> recon/<target>/browser/never-called.json
     Diff: endpoints referenced in bundles (recon_engine.sh's js/endpoints.txt
     plus anything #2 recovered) MINUS endpoints actually crawled/called
     (urls/all.txt, urls/api_endpoints.txt, urls/with_params.txt, and
     browser/api-calls.json once feature #1 exists). Newly-found endpoints are
     appended to urls/api_endpoints.txt — the exact file tools/lead_board.py's
     gather_recon() already globs — so `lead_board.py ingest` routes them
     through the normal pipeline. No parallel storage mechanism.

NOT YET IMPLEMENTED (tracked for the next pass of this phase):
  1. Runtime API capture (fetch/XHR/WebSocket/EventSource hooking) -> browser/api-calls.json
  3. Framework route extraction (Next.js/React Router/Angular) -> browser/routes.json
  4. Client-side auth model analysis -> browser/auth-model.json
  These all require actually driving a browser; require_playwright() and the
  Fetcher safety chokepoint below are the scaffolding they'll build on.

SAFETY — every outbound request in this module goes through Fetcher, which is
the single choke point: scope_checker.is_in_scope() first (browsers/crawlers
follow links off-target — the #1 way to get banned from a program), then
memory/audit_log.py's AutopilotGuard (circuit breaker + safe-method policy)
and RateLimiter, then the request, then guard feedback + an audit log entry.
--no-mutate (default ON) blocks non-idempotent methods outright — there's no
human in a headless recon run to approve them. A global --max-requests cap
and a per-request --timeout bound total exposure.

Usage:
  python3 tools/browser_recon.py target.com --domain '*.target.com' \\
      --source-maps --hidden-endpoints
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.scope_checker import ScopeChecker  # noqa: E402
from tools.recon_adapter import ReconAdapter  # noqa: E402
from memory.audit_log import AutopilotGuard, RateLimiter, AuditLog  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover - exercised by CLI smoke checks
    sync_playwright = None

DEFAULT_TIMEOUT = 15.0
DEFAULT_MAX_REQUESTS = 200
DEFAULT_RECON_RPS = 5.0


# ─── errors ─────────────────────────────────────────────────────────────────

class BrowserReconError(RuntimeError):
    """Base class for every error this module raises deliberately (as opposed
    to letting requests/json exceptions propagate)."""


class ScopeViolation(BrowserReconError):
    """Raised when a fetch target fails tools/scope_checker.py's allowlist."""


class MutationBlocked(BrowserReconError):
    """Raised when --no-mutate (default ON) blocks a non-idempotent method."""


class RequestBlocked(BrowserReconError):
    """Raised when memory/audit_log.py's circuit breaker has tripped for a host."""


class RequestCapExceeded(BrowserReconError):
    """Raised when a run hits its global --max-requests cap."""


class BrowserUnavailable(BrowserReconError):
    """Raised by require_playwright() when Playwright isn't installed."""


def require_playwright():
    """Return the playwright.sync_api module, or raise BrowserUnavailable with
    an actionable install hint. Every browser-driving feature must call this
    before touching sync_playwright — it's what lets the rest of this module
    (source-map recovery, hidden-endpoint discovery) work with zero crash
    when Playwright isn't installed."""
    if sync_playwright is None:
        raise BrowserUnavailable(
            "Playwright is not installed — browser-driven recon (runtime API "
            "capture, route extraction, auth-model analysis) is unavailable. "
            "Install with: python3 -m pip install playwright && "
            "playwright install chromium. Source-map recovery and hidden-"
            "endpoint discovery do not need a browser and still work."
        )
    return sync_playwright


# ─── Fetcher: the single network choke point ───────────────────────────────

class Fetcher:
    """Every outbound HTTP request in this module goes through here.

    Order per request: global request cap -> scope check -> circuit breaker
    -> safe-method policy -> rate limiter wait -> the request -> guard
    feedback -> audit log entry (if configured).
    """

    def __init__(
        self,
        scope_checker: ScopeChecker,
        *,
        no_mutate: bool = True,
        recon_rps: float = DEFAULT_RECON_RPS,
        timeout: float = DEFAULT_TIMEOUT,
        max_requests: int = DEFAULT_MAX_REQUESTS,
        audit_log: AuditLog | None = None,
        guard: AutopilotGuard | None = None,
        limiter: RateLimiter | None = None,
        session: requests.Session | None = None,
    ):
        self.scope_checker = scope_checker
        self.no_mutate = no_mutate
        self.timeout = timeout
        self.max_requests = max_requests
        self.audit_log = audit_log
        self.guard = guard if guard is not None else AutopilotGuard(safe_methods_only=no_mutate)
        self.limiter = limiter if limiter is not None else RateLimiter(recon_rps=recon_rps)
        self.session = session if session is not None else requests.Session()
        self.request_count = 0

    def get(self, url: str) -> requests.Response:
        return self.request("GET", url)

    def request(self, method: str, url: str) -> requests.Response:
        method = method.upper()

        if self.request_count >= self.max_requests:
            raise RequestCapExceeded(
                f"global request cap ({self.max_requests}) reached — refusing to fetch {url}"
            )

        if not self.scope_checker.is_in_scope(url):
            raise ScopeViolation(f"refusing to fetch out-of-scope URL: {url}")

        decision = self.guard.check_request(method, url)
        if decision["decision"] == "block":
            raise RequestBlocked(
                f"{method} {url} blocked: {decision.get('reason', 'circuit breaker tripped')}"
            )
        if decision["decision"] == "require_approval":
            raise MutationBlocked(
                f"{method} {url} blocked by --no-mutate (default ON; pass --allow-mutate "
                f"to override): {decision.get('reason')}"
            )

        host = decision["host"]
        self.limiter.wait(host, is_recon=True)
        self.request_count += 1

        try:
            resp = self.session.request(method, url, timeout=self.timeout)
        except requests.RequestException as exc:
            self.guard.record_failure(host)
            if self.audit_log:
                self.audit_log.log_request(url=url, method=method, scope_check="pass", error=str(exc))
            raise

        self.guard.record_success(host)
        if self.audit_log:
            self.audit_log.log_request(
                url=url, method=method, scope_check="pass", response_status=resp.status_code
            )
        return resp


# ─── #2 Source map recovery — pure logic ───────────────────────────────────

_SOURCEMAP_COMMENT_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")

_STATIC_ASSET_EXT = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "css", "woff", "woff2",
    "ttf", "eot", "map", "mp4", "webm", "mp3", "avif", "bmp",
}


def find_source_map_url(js_url: str, js_content: str) -> str | None:
    """Return the resolved URL of a JS bundle's source map, or None.

    Uses the LAST `//# sourceMappingURL=` comment in the file (per the source
    map spec, a later comment overrides an earlier one), resolved against
    js_url if relative. Inline `data:` maps are returned as-is — the caller
    decodes them directly instead of fetching. Falls back to the conventional
    `<bundle>.js.map` guess when no comment is present at all.
    """
    matches = _SOURCEMAP_COMMENT_RE.findall(js_content or "")
    if matches:
        candidate = matches[-1].strip()
        if candidate.startswith("data:"):
            return candidate
        return urljoin(js_url, candidate)
    if js_url.split("?", 1)[0].endswith(".js"):
        return js_url + ".map"
    return None


def parse_source_map(map_json) -> dict:
    """Validate + normalize a parsed .map JSON payload.

    Raises ValueError if it doesn't look like a source map at all (e.g. a 404
    HTML error page fetched from the `.map` guess) — callers should catch
    this and skip the bundle rather than crash the whole run.
    """
    if not isinstance(map_json, dict):
        raise ValueError("source map must be a JSON object")
    sources = map_json.get("sources")
    if not isinstance(sources, list):
        raise ValueError("not a source map: missing or malformed 'sources' array")
    sources_content = map_json.get("sourcesContent")
    if sources_content is not None and not isinstance(sources_content, list):
        raise ValueError("'sourcesContent' must be a list when present")
    return {
        "version": map_json.get("version"),
        "sources": sources,
        "sourcesContent": sources_content or [],
    }


def _safe_relpath(raw: str) -> str:
    """Sanitize a source map 'sources' entry into a safe relative filesystem
    path. These strings come from the bundle (webpack://, ../../ segments,
    absolute paths) and are never trustworthy for a direct filesystem write —
    without this, a crafted map could write outside the recovery directory.
    """
    s = raw or "unnamed"
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:/+", "", s)  # webpack://, webpack-internal:///, http://
    parts = [seg for seg in s.replace("\\", "/").split("/") if seg not in ("", ".", "..")]
    return "/".join(parts) if parts else "unnamed"


def recover_sources(map_data: dict) -> list[dict]:
    """Pair sources[] with sourcesContent[] into [{"path", "content"}, ...],
    sanitizing paths and skipping entries with no recovered content (common —
    not every bundle inlines sourcesContent)."""
    sources = map_data.get("sources", [])
    contents = map_data.get("sourcesContent", [])
    out = []
    for i, src in enumerate(sources):
        content = contents[i] if i < len(contents) else None
        if not content:
            continue
        out.append({"path": _safe_relpath(src), "content": content})
    return out


def recover_source_maps_for_target(target: str, recon_dir: str, fetcher: Fetcher) -> dict:
    """Orchestrates #2 end to end: read urls/js_files.txt via ReconAdapter,
    fetch each bundle + its map through the safety-gated Fetcher, recover
    sources, write them under recon/<target>/browser/sources/<bundle>/...

    Returns a summary dict; never raises on a single bundle's failure (bad
    map, 404, non-JSON) — those are recorded per-bundle and skipped so one
    broken bundle doesn't abort the whole run.
    """
    adapter = ReconAdapter(recon_dir)
    js_urls = adapter.get_js_files()
    out_dir = Path(recon_dir) / "browser" / "sources"

    bundles = []
    maps_recovered = 0
    files_written = 0

    for js_url in js_urls:
        entry = {"js_url": js_url, "map_url": None, "files_written": 0, "skipped_reason": None}
        try:
            js_resp = fetcher.get(js_url)
        except BrowserReconError as exc:
            entry["skipped_reason"] = str(exc)
            bundles.append(entry)
            continue
        if not js_resp.ok:
            entry["skipped_reason"] = f"bundle fetch failed: HTTP {js_resp.status_code}"
            bundles.append(entry)
            continue

        map_url = find_source_map_url(js_url, js_resp.text)
        if not map_url:
            entry["skipped_reason"] = "no sourceMappingURL and no .map fallback"
            bundles.append(entry)
            continue
        entry["map_url"] = map_url

        if map_url.startswith("data:"):
            try:
                import base64
                b64 = map_url.split(",", 1)[1]
                map_text = base64.b64decode(b64).decode("utf-8", errors="replace")
            except (IndexError, ValueError) as exc:
                entry["skipped_reason"] = f"malformed inline data map: {exc}"
                bundles.append(entry)
                continue
        else:
            try:
                map_resp = fetcher.get(map_url)
            except BrowserReconError as exc:
                entry["skipped_reason"] = str(exc)
                bundles.append(entry)
                continue
            if not map_resp.ok:
                entry["skipped_reason"] = f"map fetch failed: HTTP {map_resp.status_code}"
                bundles.append(entry)
                continue
            map_text = map_resp.text

        try:
            map_data = parse_source_map(json.loads(map_text))
        except (ValueError, json.JSONDecodeError) as exc:
            entry["skipped_reason"] = f"invalid source map: {exc}"
            bundles.append(entry)
            continue

        recovered = recover_sources(map_data)
        if not recovered:
            entry["skipped_reason"] = "map has no sourcesContent to recover"
            bundles.append(entry)
            continue

        bundle_name = re.sub(r"[^\w.\-]", "_", Path(urlparse(js_url).path).stem or "bundle")
        bundle_dir = out_dir / bundle_name
        for item in recovered:
            dest = bundle_dir / item["path"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(item["content"], encoding="utf-8", errors="replace")
            files_written += 1
            entry["files_written"] += 1

        maps_recovered += 1
        bundles.append(entry)

    return {
        "target": target,
        "bundles_checked": len(js_urls),
        "maps_recovered": maps_recovered,
        "files_written": files_written,
        "output_dir": str(out_dir),
        "bundles": bundles,
    }


# ─── #5 Hidden endpoint discovery — pure logic ─────────────────────────────

_PATH_LITERAL_RE = re.compile(
    r"""["'](/[A-Za-z0-9_][A-Za-z0-9_\-./]*(?:/[A-Za-z0-9_][A-Za-z0-9_\-./]*)+)["']"""
)


def extract_endpoint_strings(text: str) -> set[str]:
    """Pull path-like string literals (leading '/', >= 2 segments) out of
    JS/TS source text. Deliberately permissive, in the same spirit as
    recon_engine.sh's existing sed extraction, but drops obvious static-asset
    paths (*.png, *.css, ...) and protocol-relative URLs so the never-called
    diff isn't dominated by asset noise."""
    found = set()
    for m in _PATH_LITERAL_RE.finditer(text or ""):
        path = m.group(1)
        if path.startswith("//"):
            continue
        last_segment = path.rsplit("/", 1)[-1]
        ext = last_segment.rsplit(".", 1)[-1].lower() if "." in last_segment else ""
        if ext in _STATIC_ASSET_EXT:
            continue
        found.add(path)
    return found


def _normalize_path(url_or_path: str) -> str:
    """Reduce a URL or bare path to just its path component (no scheme, host,
    query, or trailing slash) so bundle-referenced paths and full crawled
    URLs compare on equal footing."""
    if "://" in url_or_path:
        path = urlparse(url_or_path).path
    else:
        path = url_or_path.split("?", 1)[0]
    return path.rstrip("/") or "/"


def diff_never_called(referenced: set[str], called: set[str]) -> list[str]:
    """referenced MINUS called, compared by normalized path. Pure set diff —
    no I/O, no network."""
    called_norm = {_normalize_path(c) for c in called}
    return sorted({r for r in referenced if _normalize_path(r) not in called_norm})


def _read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    with path.open(errors="replace") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def _route_to_lead_board_file(recon_dir: str, never_called: list[str]) -> int:
    """Append newly-found endpoints to urls/api_endpoints.txt — the exact
    file tools/lead_board.py's gather_recon() already globs for the "url"
    source. This IS the existing ingest path; running
    `python3 tools/lead_board.py ingest <target>` afterwards routes each one
    to its hunt-* skill same as any other recon-discovered URL. Returns the
    number of genuinely new lines appended (dedup against what's already
    there, idempotent across reruns)."""
    path = Path(recon_dir) / "urls" / "api_endpoints.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = set(_read_lines(path))
    new_lines = [line for line in never_called if line not in existing]
    if new_lines:
        with path.open("a") as fh:
            for line in new_lines:
                fh.write(line + "\n")
    return len(new_lines)


def discover_hidden_endpoints(target: str, recon_dir: str) -> dict:
    """Orchestrates #5 end to end. referenced = recon_engine.sh's
    js/endpoints.txt plus anything #2 recovered under browser/sources/;
    called = urls/all.txt + urls/api_endpoints.txt + urls/with_params.txt
    (via ReconAdapter) plus browser/api-calls.json once feature #1 exists.
    Writes browser/never-called.json and routes new finds into the lead
    board's existing ingest path. No network I/O — this is pure file-diffing."""
    adapter = ReconAdapter(recon_dir)
    recon_path = Path(recon_dir)

    referenced: set[str] = set(_read_lines(recon_path / "js" / "endpoints.txt"))
    sources_dir = recon_path / "browser" / "sources"
    if sources_dir.is_dir():
        for f in sources_dir.rglob("*"):
            if f.is_file() and f.suffix.lower() in {".js", ".ts", ".jsx", ".tsx", ".mjs"}:
                referenced |= extract_endpoint_strings(f.read_text(errors="replace"))

    called: set[str] = set(adapter.get_urls()) | set(adapter.get_api_endpoints()) | set(
        adapter.get_parameterized_urls()
    )
    api_calls_path = recon_path / "browser" / "api-calls.json"
    if api_calls_path.exists():
        try:
            calls = json.loads(api_calls_path.read_text())
            called |= {c.get("url", "") for c in calls if isinstance(c, dict) and c.get("url")}
        except (ValueError, OSError):
            pass

    never_called = diff_never_called(referenced, called)

    out_dir = recon_path / "browser"
    out_dir.mkdir(parents=True, exist_ok=True)
    result = {
        "target": target,
        "referenced_count": len(referenced),
        "called_count": len(called),
        "never_called": never_called,
    }
    (out_dir / "never-called.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")

    result["routed_new_lines"] = _route_to_lead_board_file(recon_dir, never_called)
    return result


# ─── CLI ────────────────────────────────────────────────────────────────────

def _split_patterns(values: list[str]) -> list[str]:
    patterns: list[str] = []
    for value in values:
        for part in value.split(","):
            part = part.strip()
            if part:
                patterns.append(part)
    return patterns


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Browser intelligence layer — source-map recovery + hidden-endpoint discovery."
    )
    parser.add_argument("target", help="Target domain (e.g. example.com)")
    parser.add_argument("--recon-dir", default=None, help="default: recon/<target>")
    parser.add_argument("--domain", "-d", action="append", default=[],
                         help="Allowed domain pattern for the scope allowlist. Repeat or comma-separate.")
    parser.add_argument("--exclude-domain", "-x", action="append", default=[],
                         help="Excluded domain pattern. Repeat or comma-separate.")
    parser.add_argument("--source-maps", action="store_true", help="Run source-map recovery (#2)")
    parser.add_argument("--hidden-endpoints", action="store_true", help="Run hidden-endpoint discovery (#5)")
    parser.add_argument("--no-mutate", dest="no_mutate", action="store_true", default=True,
                         help="Block non-idempotent HTTP methods (default: ON)")
    parser.add_argument("--allow-mutate", dest="no_mutate", action="store_false",
                         help="Explicitly allow non-idempotent HTTP methods")
    parser.add_argument("--recon-rps", type=float, default=DEFAULT_RECON_RPS)
    parser.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = parser.parse_args(argv)

    if not args.source_maps and not args.hidden_endpoints:
        parser.error(
            "choose at least one of --source-maps / --hidden-endpoints "
            "(runtime API capture / route extraction / auth-model analysis are not implemented yet)"
        )

    domains = _split_patterns(args.domain)
    if args.source_maps and not domains:
        parser.error("--source-maps sends network requests and requires at least one --domain pattern")

    recon_dir = args.recon_dir or os.path.join("recon", args.target)
    result: dict = {"target": args.target, "recon_dir": recon_dir}

    if args.source_maps:
        checker = ScopeChecker(domains, _split_patterns(args.exclude_domain))
        fetcher = Fetcher(
            checker,
            no_mutate=args.no_mutate,
            recon_rps=args.recon_rps,
            timeout=args.timeout,
            max_requests=args.max_requests,
        )
        result["source_maps"] = recover_source_maps_for_target(args.target, recon_dir, fetcher)

    if args.hidden_endpoints:
        result["hidden_endpoints"] = discover_hidden_endpoints(args.target, recon_dir)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        if "source_maps" in result:
            sm = result["source_maps"]
            print(f"Source maps: {sm['maps_recovered']}/{sm['bundles_checked']} bundles recovered, "
                  f"{sm['files_written']} files written -> {sm['output_dir']}")
        if "hidden_endpoints" in result:
            he = result["hidden_endpoints"]
            print(f"Hidden endpoints: {len(he['never_called'])} never-called path(s) found "
                  f"({he['referenced_count']} referenced, {he['called_count']} called), "
                  f"{he['routed_new_lines']} routed to urls/api_endpoints.txt for lead_board ingest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
