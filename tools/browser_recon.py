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

Implemented so far (batch 1: #2 + #5; batch 2: #1 — see module docstring
bottom for what's still to come):

  1. RUNTIME API CAPTURE -> recon/<target>/browser/api-calls.json
     Headless Chromium session (optionally authenticated via the same
     AuthSession headers hunt.py uses). Visits a bounded, scope-checked set
     of entry URLs plus same-scope links discovered on those pages, and
     captures every fetch/XHR/navigation request the page itself makes via
     Playwright's page.route() interception — the ONE thing a crawler-based
     pipeline structurally cannot see, because it never executes the page's
     JS. Records method, URL, request/response body SHAPE (keys + types,
     never real values), which headers looked auth-related (names only,
     values redacted), and which page/link triggered each request.
     WebSocket connection URLs are recorded too (frame contents are not).
     Requires Playwright — see require_playwright() below.

  2. SOURCE MAP RECOVERY -> recon/<target>/browser/sources/
     For each JS bundle in recon/<target>/urls/js_files.txt: fetch it, find
     its source map (sourceMappingURL comment or the conventional `.map`
     guess), unpack sourcesContent to recover original TS/JSX. Pure HTTP
     (requests), no browser needed.

  5. HIDDEN ENDPOINT DISCOVERY -> recon/<target>/browser/never-called.json
     Diff: endpoints referenced in bundles (recon_engine.sh's js/endpoints.txt
     plus anything #2 recovered) MINUS endpoints actually crawled/called
     (urls/all.txt, urls/api_endpoints.txt, urls/with_params.txt, and
     browser/api-calls.json from #1). Newly-found endpoints are appended to
     urls/api_endpoints.txt — the exact file tools/lead_board.py's
     gather_recon() already globs — so `lead_board.py ingest` routes them
     through the normal pipeline. No parallel storage mechanism.

NOT YET IMPLEMENTED (tracked for the next pass of this phase):
  3. Framework route extraction (Next.js/React Router/Angular) -> browser/routes.json
  4. Client-side auth model analysis -> browser/auth-model.json
  Both will reuse the same Chromium session capture_runtime_api() launches.

SAFETY — every outbound request in this module goes through Fetcher, which is
the single choke point: scope_checker.is_in_scope() first (browsers/crawlers
follow links off-target — the #1 way to get banned from a program), then
memory/audit_log.py's AutopilotGuard (circuit breaker + safe-method policy)
and RateLimiter, then the request, then guard feedback + an audit log entry.
--no-mutate (default ON) blocks non-idempotent methods outright — there's no
human in a headless recon run to approve them. A global --max-requests cap
and a per-request --timeout bound total exposure. For #1 specifically:
Fetcher.check() (scope + circuit-breaker + safe-method + rate-limit, no
actual I/O) runs inside a page.route() handler for EVERY request the browser
tries to make — navigation, fetch, XHR, asset loads, all of it — and a
non-conforming request is route.abort()'d before Playwright ever sends it
over the wire. Only method/URL/header-name/body-shape are ever recorded;
tools/auth_session.py's AuthSession already guarantees raw credential values
never leave process memory, and this module never asks it for anything but
its redacted/shape views.

Usage:
  python3 tools/browser_recon.py target.com --domain '*.target.com' \\
      --source-maps --hidden-endpoints
  python3 tools/browser_recon.py target.com --domain '*.target.com' \\
      --api-capture --entry-url https://target.com/dashboard --bearer TOKEN
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

import requests

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.scope_checker import ScopeChecker  # noqa: E402
from tools.recon_adapter import ReconAdapter  # noqa: E402
from tools.auth_session import AuthSession, add_cli_args as add_auth_cli_args, session_from_args  # noqa: E402
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

    def _preflight(self, method: str, url: str) -> str:
        """Scope + request cap + circuit-breaker + safe-method checks, shared
        by request() and check(). Does not touch the rate limiter or the
        request counter — callers do that after a successful preflight, so
        check() (no actual I/O) and request() (real I/O) both pace/count
        correctly relative to each other on the same Fetcher instance."""
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
        return decision["host"]

    def check(self, method: str, url: str) -> str:
        """Preflight-only: the exact same scope/cap/circuit-breaker/safe-method
        checks as request(), plus the rate-limiter wait and request-count
        increment, but WITHOUT sending an HTTP request. For browser-driven
        features (Playwright route interception) where Playwright itself
        performs the actual network I/O — the same safety gates must still
        run before Playwright is allowed to send anything. Returns the host
        on success; raises a BrowserReconError subclass otherwise."""
        method = method.upper()
        host = self._preflight(method, url)
        self.limiter.wait(host, is_recon=True)
        self.request_count += 1
        return host

    def request(self, method: str, url: str) -> requests.Response:
        method = method.upper()
        host = self._preflight(method, url)
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
            payload = json.loads(api_calls_path.read_text())
            # capture_runtime_api() (#1) writes {"calls": [...], ...}; accept
            # a bare list too in case something else ever writes this file.
            calls = payload.get("calls", []) if isinstance(payload, dict) else payload
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


# ─── #1 Runtime API capture — pure logic ───────────────────────────────────

_AUTH_HEADER_NAMES = {
    "authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
    "x-access-token", "x-csrf-token", "x-xsrf-token", "proxy-authorization",
}

_MAX_SHAPE_DEPTH = 6
_MAX_RESPONSE_BODY_BYTES = 200_000  # never buffer a huge response just to shape it


def is_auth_header(name: str) -> bool:
    return (name or "").lower() in _AUTH_HEADER_NAMES


def shape_of(value, _depth: int = 0):
    """Pure: a JSON-decoded value -> its shape (keys + type names), never the
    real values. {"user": "bob", "id": 7} -> {"user": "string", "id": "number"}.
    Depth-capped so a pathological nested payload can't blow the stack."""
    if _depth > _MAX_SHAPE_DEPTH:
        return "..."
    if isinstance(value, dict):
        return {k: shape_of(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [shape_of(value[0], _depth + 1)] if value else []
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if value is None:
        return "null"
    return type(value).__name__


def shape_of_body(raw, content_type: str = ""):
    """Best-effort shape of a request/response body. Tries JSON first, then
    application/x-www-form-urlencoded, else records only a byte length —
    never the actual content. Returns None for an empty/absent body."""
    if not raw:
        return None
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            return {"_opaque_bytes": len(raw)}

    try:
        return shape_of(json.loads(raw))
    except (ValueError, TypeError):
        pass

    ct = (content_type or "").lower()
    if "form-urlencoded" in ct or ("=" in raw and "\n" not in raw and " " not in raw.strip("&=")):
        try:
            parsed = parse_qs(raw, strict_parsing=True)
            if parsed:
                return {k: ("string" if len(v) == 1 else "array") for k, v in parsed.items()}
        except ValueError:
            pass

    return {"_opaque_text_length": len(raw)}


class ApiCallRecorder:
    """Accumulates captured request/response entries during a browser
    session. Playwright's real Request/Response objects are fed in via
    on_request()/on_response()/on_websocket() (matched on their .method/
    .url/.headers/.post_data/.status surface); this class never imports
    playwright itself, so it's fully unit-testable with lightweight fakes
    exposing that same surface."""

    def __init__(self):
        self.calls: list[dict] = []
        self._by_key: dict[tuple[str, str], dict] = {}
        self.trigger: str = "page_load"

    def on_request(self, request) -> dict:
        headers = dict(getattr(request, "headers", {}) or {})
        entry = {
            "method": request.method,
            "url": request.url,
            "resource_type": getattr(request, "resource_type", None),
            "request_headers_auth": sorted(h for h in headers if is_auth_header(h)),
            "request_body_shape": shape_of_body(
                getattr(request, "post_data", None), headers.get("content-type", "")
            ),
            "trigger": self.trigger,
            "response_status": None,
            "response_shape": None,
            "blocked": False,
            "block_reason": None,
        }
        self.calls.append(entry)
        self._by_key[(request.url, request.method)] = entry
        return entry

    def on_blocked(self, request, reason: str) -> dict:
        entry = self.on_request(request)
        entry["blocked"] = True
        entry["block_reason"] = reason
        return entry

    def on_response(self, response) -> None:
        req = getattr(response, "request", None)
        key = (response.url, getattr(req, "method", "GET"))
        entry = self._by_key.get(key)
        if entry is None:
            return
        entry["response_status"] = response.status
        headers = dict(getattr(response, "headers", {}) or {})
        ct = headers.get("content-type", "")
        if "json" in ct.lower():
            try:
                body = response.body()
                if len(body) <= _MAX_RESPONSE_BODY_BYTES:
                    entry["response_shape"] = shape_of(json.loads(body))
                else:
                    entry["response_shape"] = {"_opaque_bytes": len(body)}
            except Exception:
                entry["response_shape"] = None
        elif ct:
            entry["response_shape"] = {"_content_type": ct}

    def on_websocket(self, ws) -> dict:
        entry = {
            "method": "WEBSOCKET",
            "url": ws.url,
            "resource_type": "websocket",
            "request_headers_auth": [],
            "request_body_shape": None,
            "trigger": self.trigger,
            "response_status": None,
            "response_shape": None,
            "blocked": False,
            "block_reason": None,
        }
        self.calls.append(entry)
        return entry

    def to_list(self) -> list[dict]:
        return self.calls


def _install_capture_hooks(page, fetcher: Fetcher, recorder: ApiCallRecorder) -> None:
    """Wires Playwright's route interception + response/websocket events to
    the safety-gated Fetcher and the recorder. This is the ONLY place in the
    module where a real network request is allowed to leave the machine
    without going through `requests` — Playwright sends it — so
    fetcher.check() (same scope/cap/circuit-breaker/safe-method/rate-limit
    gates as every other fetch in this module) has to run for every single
    one, and route.abort() is what actually stops a non-conforming request
    from ever being sent."""

    def handle_route(route):
        request = route.request
        try:
            fetcher.check(request.method, request.url)
        except BrowserReconError as exc:
            recorder.on_blocked(request, str(exc))
            route.abort()
            return
        recorder.on_request(request)
        route.continue_()

    page.route("**/*", handle_route)
    page.on("response", recorder.on_response)
    page.on("websocket", recorder.on_websocket)


def capture_runtime_api(
    target: str,
    recon_dir: str,
    fetcher: Fetcher,
    *,
    entry_urls: list[str],
    auth_session: AuthSession | None = None,
    max_pages: int = 20,
    page_timeout: float = 30.0,
    max_links_per_page: int = 5,
) -> dict:
    """Orchestrates #1 end to end. Requires Playwright — call
    require_playwright() first (raises BrowserUnavailable with a clear
    message if it's not installed).

    Launches one headless Chromium context (with auth_session's headers
    attached, if given — never logged, never written anywhere but sent as
    real request headers), visits entry_urls plus a small bounded set of
    same-scope links discovered on those pages (link-following only; no
    button/form interaction in this pass — clicking arbitrary buttons risks
    triggering account-mutating actions no --no-mutate check can fully
    predict, so it's deliberately deferred). Every request the page makes,
    including navigation itself, is gated by fetcher.check() inside
    page.route() before Playwright is allowed to send it.

    Writes recon/<target>/browser/api-calls.json. Never raises on a single
    page's navigation failure (bad link, timeout, blocked by our own
    guard) — that page is just skipped, same resilience pattern as
    recover_source_maps_for_target()."""
    sync_playwright = require_playwright()
    recorder = ApiCallRecorder()
    visited: set[str] = set()
    queue: list[str] = list(dict.fromkeys(entry_urls))[:max_pages]
    pages_visited = 0

    extra_headers = None
    if auth_session is not None and not auth_session.is_empty():
        extra_headers = auth_session.headers_dict()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            context = browser.new_context(extra_http_headers=extra_headers)
            page = context.new_page()
            page.set_default_timeout(page_timeout * 1000)
            _install_capture_hooks(page, fetcher, recorder)

            while queue and pages_visited < max_pages:
                url = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)
                recorder.trigger = f"page_load:{url}"
                try:
                    page.goto(url, wait_until="networkidle", timeout=page_timeout * 1000)
                except Exception:
                    # Real network failure, our own route.abort() causing a
                    # failed top-level navigation, or a plain timeout — this
                    # is a per-page outcome, not a reason to abort the run.
                    continue
                pages_visited += 1

                try:
                    hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                except Exception:
                    hrefs = []
                for href in hrefs[:max_links_per_page]:
                    if href not in visited and fetcher.scope_checker.is_in_scope(href):
                        queue.append(href)
        finally:
            browser.close()

    out_dir = Path(recon_dir) / "browser"
    out_dir.mkdir(parents=True, exist_ok=True)
    result = {
        "target": target,
        "pages_visited": pages_visited,
        "requests_captured": len(recorder.calls),
        "calls": recorder.to_list(),
    }
    (out_dir / "api-calls.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
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
        description="Browser intelligence layer — runtime API capture + source-map recovery + hidden-endpoint discovery."
    )
    parser.add_argument("target", help="Target domain (e.g. example.com)")
    parser.add_argument("--recon-dir", default=None, help="default: recon/<target>")
    parser.add_argument("--domain", "-d", action="append", default=[],
                         help="Allowed domain pattern for the scope allowlist. Repeat or comma-separate.")
    parser.add_argument("--exclude-domain", "-x", action="append", default=[],
                         help="Excluded domain pattern. Repeat or comma-separate.")
    parser.add_argument("--source-maps", action="store_true", help="Run source-map recovery (#2)")
    parser.add_argument("--hidden-endpoints", action="store_true", help="Run hidden-endpoint discovery (#5)")
    parser.add_argument("--api-capture", action="store_true",
                         help="Run runtime API capture (#1) — drives a real headless browser; requires Playwright")
    parser.add_argument("--entry-url", action="append", default=[],
                         help="Seed URL for --api-capture's browser walk. Repeatable. "
                              "Default: recon's live hosts (capped by --max-pages).")
    parser.add_argument("--max-pages", type=int, default=20,
                         help="Global cap on pages visited during --api-capture (default: 20)")
    parser.add_argument("--page-timeout", type=float, default=30.0,
                         help="Per-page navigation timeout in seconds for --api-capture (default: 30)")
    parser.add_argument("--max-links-per-page", type=int, default=5,
                         help="Same-scope links followed per page during --api-capture (default: 5)")
    parser.add_argument("--no-mutate", dest="no_mutate", action="store_true", default=True,
                         help="Block non-idempotent HTTP methods (default: ON)")
    parser.add_argument("--allow-mutate", dest="no_mutate", action="store_false",
                         help="Explicitly allow non-idempotent HTTP methods")
    parser.add_argument("--recon-rps", type=float, default=DEFAULT_RECON_RPS)
    parser.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    add_auth_cli_args(parser)
    args = parser.parse_args(argv)

    if not args.source_maps and not args.hidden_endpoints and not args.api_capture:
        parser.error(
            "choose at least one of --source-maps / --hidden-endpoints / --api-capture "
            "(route extraction / auth-model analysis are not implemented yet)"
        )

    domains = _split_patterns(args.domain)
    if (args.source_maps or args.api_capture) and not domains:
        parser.error(
            "--source-maps / --api-capture send network requests and require "
            "at least one --domain pattern"
        )

    if args.api_capture:
        try:
            require_playwright()
        except BrowserUnavailable as exc:
            parser.error(str(exc))

    recon_dir = args.recon_dir or os.path.join("recon", args.target)
    result: dict = {"target": args.target, "recon_dir": recon_dir}

    checker = None
    fetcher = None
    if args.source_maps or args.api_capture:
        checker = ScopeChecker(domains, _split_patterns(args.exclude_domain))
        fetcher = Fetcher(
            checker,
            no_mutate=args.no_mutate,
            recon_rps=args.recon_rps,
            timeout=args.timeout,
            max_requests=args.max_requests,
        )

    if args.source_maps:
        result["source_maps"] = recover_source_maps_for_target(args.target, recon_dir, fetcher)

    if args.api_capture:
        entry_urls = args.entry_url or ReconAdapter(recon_dir).get_live_hosts()
        if not entry_urls:
            parser.error(
                "--api-capture needs at least one entry URL — pass --entry-url or "
                "run recon first so recon/<target>/live/urls.txt has hosts"
            )
        auth_session = session_from_args(args)
        result["api_capture"] = capture_runtime_api(
            args.target, recon_dir, fetcher,
            entry_urls=entry_urls,
            auth_session=auth_session,
            max_pages=args.max_pages,
            page_timeout=args.page_timeout,
            max_links_per_page=args.max_links_per_page,
        )

    if args.hidden_endpoints:
        result["hidden_endpoints"] = discover_hidden_endpoints(args.target, recon_dir)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        if "source_maps" in result:
            sm = result["source_maps"]
            print(f"Source maps: {sm['maps_recovered']}/{sm['bundles_checked']} bundles recovered, "
                  f"{sm['files_written']} files written -> {sm['output_dir']}")
        if "api_capture" in result:
            ac = result["api_capture"]
            print(f"API capture: {ac['pages_visited']} page(s) visited, "
                  f"{ac['requests_captured']} request(s) captured -> "
                  f"{recon_dir}/browser/api-calls.json")
        if "hidden_endpoints" in result:
            he = result["hidden_endpoints"]
            print(f"Hidden endpoints: {len(he['never_called'])} never-called path(s) found "
                  f"({he['referenced_count']} referenced, {he['called_count']} called), "
                  f"{he['routed_new_lines']} routed to urls/api_endpoints.txt for lead_board ingest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
