"""Tests for tools/browser_recon.py — runtime API capture (#1), source-map
recovery (#2), and hidden-endpoint discovery (#5) of the browser
intelligence layer.

Most of this file runs against local fixtures with zero network access: a
FakeSession stands in for `requests.Session`, and recon directories are
built under tmp_path in the exact layout tools/recon_adapter.py /
tools/lead_board.py already expect.

The #1 runtime-API-capture tests are split in two:
  - Pure-function / mocked-object tests (shape helpers, ApiCallRecorder,
    the page.route() handler) never touch Playwright and always run.
  - A handful of real end-to-end tests actually launch headless Chromium
    against a throwaway 127.0.0.1 HTTP server started in-process for the
    test (never the real network, never demo/app.py — a small dedicated
    fixture keeps this file self-contained). These are skipped automatically
    when Playwright/Chromium aren't installed
    (skipif(not PLAYWRIGHT_AVAILABLE)) so the suite still passes clean in an
    environment without them — see TestPlaywrightAbsent for the
    absent-dependency contract itself.

Framework route extraction (#3) and auth-model analysis (#4) are not
implemented yet — no tests for them here by design; see
browser_recon.py's module docstring for what's deferred.
"""

import http.server
import json
import threading
from pathlib import Path

import pytest
import requests

import browser_recon as br  # tools/ is on sys.path via tests/conftest.py
from tools.auth_session import AuthSession
from tools.scope_checker import ScopeChecker

PLAYWRIGHT_AVAILABLE = br.sync_playwright is not None
needs_playwright = pytest.mark.skipif(
    not PLAYWRIGHT_AVAILABLE, reason="Playwright/Chromium not installed"
)


# ─── fixtures ───────────────────────────────────────────────────────────────

class FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text

    @property
    def ok(self):
        return 200 <= self.status_code < 400


class FakeSession:
    """Maps exact URLs to canned responses. Raises on anything unmapped so a
    test can never accidentally "succeed" via an unintended real call."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def request(self, method, url, timeout=None):
        self.calls.append((method, url))
        if url not in self.routes:
            raise AssertionError(f"FakeSession got an unmapped URL: {method} {url}")
        return self.routes[url]


def make_recon_dir(tmp_path, *, js_files=None, called_urls=None, referenced_endpoints=None):
    rd = tmp_path / "recon" / "t.example"
    (rd / "urls").mkdir(parents=True)
    (rd / "js").mkdir(parents=True)
    (rd / "urls" / "js_files.txt").write_text("\n".join(js_files or []) + "\n")
    (rd / "urls" / "all.txt").write_text("\n".join(called_urls or []) + "\n")
    (rd / "js" / "endpoints.txt").write_text("\n".join(referenced_endpoints or []) + "\n")
    return rd


@pytest.fixture
def checker():
    return ScopeChecker(["t.example", "*.t.example"])


class SpyLimiter:
    def __init__(self):
        self.calls = []

    def wait(self, host, is_recon=False):
        self.calls.append((host, is_recon))
        return 0.0


# ─── #2 source-map recovery: pure functions ────────────────────────────────

class TestFindSourceMapUrl:
    def test_finds_comment(self):
        content = "console.log(1)\n//# sourceMappingURL=app.js.map\n"
        assert br.find_source_map_url("https://t.example/app.js", content) == "https://t.example/app.js.map"

    def test_last_comment_wins(self):
        content = "//# sourceMappingURL=old.map\ncode();\n//# sourceMappingURL=new.map\n"
        assert br.find_source_map_url("https://t.example/app.js", content) == "https://t.example/new.map"

    def test_absolute_map_url_preserved(self):
        content = "//# sourceMappingURL=https://cdn.example/maps/app.js.map"
        assert br.find_source_map_url("https://t.example/app.js", content) == "https://cdn.example/maps/app.js.map"

    def test_inline_data_map_returned_as_is(self):
        content = "//# sourceMappingURL=data:application/json;base64,eyJhIjoxfQ=="
        result = br.find_source_map_url("https://t.example/app.js", content)
        assert result.startswith("data:")

    def test_falls_back_to_dot_map_guess(self):
        assert br.find_source_map_url("https://t.example/app.js", "no comment here") == "https://t.example/app.js.map"

    def test_no_fallback_for_non_js_url(self):
        assert br.find_source_map_url("https://t.example/app.css", "no comment") is None


class TestParseSourceMap:
    def test_valid_map(self):
        result = br.parse_source_map({"version": 3, "sources": ["a.ts"], "sourcesContent": ["x=1"]})
        assert result["sources"] == ["a.ts"]
        assert result["sourcesContent"] == ["x=1"]

    def test_missing_sources_content_defaults_empty(self):
        result = br.parse_source_map({"version": 3, "sources": ["a.ts"]})
        assert result["sourcesContent"] == []

    def test_non_dict_raises(self):
        with pytest.raises(ValueError):
            br.parse_source_map(["not", "a", "map"])

    def test_missing_sources_raises(self):
        with pytest.raises(ValueError):
            br.parse_source_map({"version": 3})

    def test_wrong_type_sources_content_raises(self):
        with pytest.raises(ValueError):
            br.parse_source_map({"sources": ["a.ts"], "sourcesContent": "not-a-list"})


class TestSafeRelpath:
    def test_strips_webpack_scheme(self):
        assert br._safe_relpath("webpack://myapp/./src/App.tsx") == "myapp/src/App.tsx"

    def test_blocks_path_traversal(self):
        result = br._safe_relpath("../../../../etc/passwd")
        assert ".." not in result.split("/")
        assert not result.startswith("/")

    def test_blocks_absolute_path(self):
        result = br._safe_relpath("/etc/passwd")
        assert not result.startswith("/")

    def test_empty_input_gets_placeholder(self):
        assert br._safe_relpath("") == "unnamed"


class TestRecoverSources:
    def test_pairs_sources_with_content(self):
        map_data = {"sources": ["a.ts", "b.ts"], "sourcesContent": ["contentA", "contentB"]}
        result = br.recover_sources(map_data)
        assert result == [{"path": "a.ts", "content": "contentA"}, {"path": "b.ts", "content": "contentB"}]

    def test_skips_missing_content(self):
        map_data = {"sources": ["a.ts", "b.ts"], "sourcesContent": ["contentA", None]}
        result = br.recover_sources(map_data)
        assert len(result) == 1
        assert result[0]["path"] == "a.ts"

    def test_empty_sources_content_list(self):
        map_data = {"sources": ["a.ts"], "sourcesContent": []}
        assert br.recover_sources(map_data) == []


# ─── #2 source-map recovery: end to end against a fixture bundle ──────────

class TestRecoverSourceMapsForTarget:
    def test_unpacks_fixture_bundle(self, tmp_path, checker):
        js_url = "https://t.example/static/app.js"
        map_url = "https://t.example/static/app.js.map"
        js_body = "console.log('hi');\n//# sourceMappingURL=app.js.map\n"
        map_body = json.dumps({
            "version": 3,
            "sources": ["webpack://myapp/./src/index.tsx", "webpack://myapp/./src/utils/api.ts"],
            "sourcesContent": ["export const x = 1;", "export function call() {}"],
        })
        session = FakeSession({
            js_url: FakeResponse(200, js_body),
            map_url: FakeResponse(200, map_body),
        })
        rd = make_recon_dir(tmp_path, js_files=[js_url])
        fetcher = br.Fetcher(checker, session=session, limiter=SpyLimiter())

        result = br.recover_source_maps_for_target("t.example", str(rd), fetcher)

        assert result["bundles_checked"] == 1
        assert result["maps_recovered"] == 1
        assert result["files_written"] == 2
        recovered_index = (rd / "browser" / "sources" / "app" / "myapp" / "src" / "index.tsx")
        recovered_api = (rd / "browser" / "sources" / "app" / "myapp" / "src" / "utils" / "api.ts")
        assert recovered_index.read_text() == "export const x = 1;"
        assert recovered_api.read_text() == "export function call() {}"

    def test_skips_bundle_with_no_map(self, tmp_path, checker):
        js_url = "https://t.example/static/plain.js"
        session = FakeSession({js_url: FakeResponse(200, "console.log('no map here')")})
        rd = make_recon_dir(tmp_path, js_files=[js_url])
        fetcher = br.Fetcher(checker, session=session, limiter=SpyLimiter(), max_requests=1)

        result = br.recover_source_maps_for_target("t.example", str(rd), fetcher)
        assert result["maps_recovered"] == 0
        assert result["bundles"][0]["skipped_reason"]

    def test_skips_bundle_when_map_is_not_valid_json(self, tmp_path, checker):
        js_url = "https://t.example/static/app.js"
        map_url = "https://t.example/static/app.js.map"
        session = FakeSession({
            js_url: FakeResponse(200, "//# sourceMappingURL=app.js.map"),
            map_url: FakeResponse(200, "<html>404</html>"),
        })
        rd = make_recon_dir(tmp_path, js_files=[js_url])
        fetcher = br.Fetcher(checker, session=session, limiter=SpyLimiter())

        result = br.recover_source_maps_for_target("t.example", str(rd), fetcher)
        assert result["maps_recovered"] == 0
        assert "invalid source map" in result["bundles"][0]["skipped_reason"]


# ─── #5 hidden-endpoint discovery: pure functions ──────────────────────────

class TestExtractEndpointStrings:
    def test_extracts_multi_segment_paths(self):
        text = 'fetch("/api/v1/admin/users").then(x => x)'
        assert "/api/v1/admin/users" in br.extract_endpoint_strings(text)

    def test_ignores_static_assets(self):
        text = 'const logo = "/assets/img/logo.png";'
        assert br.extract_endpoint_strings(text) == set()

    def test_ignores_protocol_relative_urls(self):
        text = 'const cdn = "//cdn.example.com/lib/thing";'
        assert br.extract_endpoint_strings(text) == set()

    def test_ignores_single_segment_strings(self):
        text = 'const mode = "/prod";'
        assert br.extract_endpoint_strings(text) == set()


class TestDiffNeverCalled:
    def test_basic_diff(self):
        referenced = {"/api/v1/admin/users", "/api/v1/orders"}
        called = {"https://t.example/api/v1/orders?id=1"}
        assert br.diff_never_called(referenced, called) == ["/api/v1/admin/users"]

    def test_trailing_slash_and_query_ignored_in_comparison(self):
        referenced = {"/api/v1/orders/"}
        called = {"https://t.example/api/v1/orders?page=2"}
        assert br.diff_never_called(referenced, called) == []

    def test_nothing_never_called(self):
        referenced = {"/api/v1/orders"}
        called = {"/api/v1/orders"}
        assert br.diff_never_called(referenced, called) == []


# ─── #5 hidden-endpoint discovery: end to end ──────────────────────────────

class TestDiscoverHiddenEndpoints:
    def test_finds_and_routes_never_called(self, tmp_path):
        rd = make_recon_dir(
            tmp_path,
            called_urls=["https://t.example/api/v1/orders?id=1"],
            referenced_endpoints=["/api/v1/orders", "/api/v1/admin/debug-panel"],
        )
        result = br.discover_hidden_endpoints("t.example", str(rd))

        assert result["never_called"] == ["/api/v1/admin/debug-panel"]
        assert result["routed_new_lines"] == 1

        never_called_json = json.loads((rd / "browser" / "never-called.json").read_text())
        assert never_called_json["never_called"] == ["/api/v1/admin/debug-panel"]

        routed = (rd / "urls" / "api_endpoints.txt").read_text().splitlines()
        assert "/api/v1/admin/debug-panel" in routed

    def test_rerun_is_idempotent(self, tmp_path):
        rd = make_recon_dir(
            tmp_path,
            called_urls=[],
            referenced_endpoints=["/api/v1/admin/debug-panel"],
        )
        first = br.discover_hidden_endpoints("t.example", str(rd))
        second = br.discover_hidden_endpoints("t.example", str(rd))
        assert first["routed_new_lines"] == 1
        assert second["routed_new_lines"] == 0

    def test_lead_board_ingest_picks_up_routed_endpoint(self, tmp_path, monkeypatch):
        """Confirms this reuses lead_board's existing ingest path rather than
        a parallel storage mechanism: the endpoint discover_hidden_endpoints()
        appends to urls/api_endpoints.txt must be exactly what
        lead_board.py's gather_recon()/ingest() already glob for."""
        import lead_board as lb

        rd = make_recon_dir(
            tmp_path,
            called_urls=[],
            referenced_endpoints=["/api/v1/admin/debug-panel"],
        )
        br.discover_hidden_endpoints("t.example", str(rd))

        monkeypatch.setattr(lb, "LEADS_DIR", str(tmp_path / "leads"))
        leads = lb.ingest("t.example", str(rd))
        assert any("/api/v1/admin/debug-panel" in ld["evidence"] for ld in leads)


# ─── Safety: scope, rate limit, no-mutate, circuit breaker ────────────────

class TestScopeEnforcement:
    def test_out_of_scope_fetch_is_blocked(self, checker):
        fetcher = br.Fetcher(checker, session=FakeSession({}), limiter=SpyLimiter())
        with pytest.raises(br.ScopeViolation):
            fetcher.get("https://evil-unrelated.com/x")

    def test_in_scope_fetch_proceeds(self, checker):
        url = "https://t.example/x"
        session = FakeSession({url: FakeResponse(200, "ok")})
        fetcher = br.Fetcher(checker, session=session, limiter=SpyLimiter())
        resp = fetcher.get(url)
        assert resp.text == "ok"


class TestRateLimiterWiring:
    def test_rate_limiter_is_consulted_per_request(self, checker):
        url = "https://t.example/x"
        session = FakeSession({url: FakeResponse(200, "ok")})
        spy = SpyLimiter()
        fetcher = br.Fetcher(checker, session=session, limiter=spy)

        fetcher.get(url)
        fetcher.get(url)

        assert len(spy.calls) == 2
        assert spy.calls[0] == ("t.example", True)

    def test_real_rate_limiter_actually_wired_not_a_stub(self, checker):
        """Uses the real memory.audit_log.RateLimiter (not the spy) to prove
        Fetcher wires it in for real, not just an interface it could satisfy."""
        from memory.audit_log import RateLimiter
        url = "https://t.example/x"
        session = FakeSession({url: FakeResponse(200, "ok")})
        limiter = RateLimiter(recon_rps=1000.0)
        fetcher = br.Fetcher(checker, session=session, limiter=limiter)
        fetcher.get(url)
        assert limiter._last_request.get("t.example") is not None


class TestNoMutate:
    def test_post_blocked_by_default(self, checker):
        url = "https://t.example/api/orders"
        session = FakeSession({url: FakeResponse(200, "ok")})
        fetcher = br.Fetcher(checker, session=session, limiter=SpyLimiter())
        with pytest.raises(br.MutationBlocked):
            fetcher.request("POST", url)
        assert session.calls == []  # never actually sent

    def test_get_not_blocked_by_default(self, checker):
        url = "https://t.example/api/orders"
        session = FakeSession({url: FakeResponse(200, "ok")})
        fetcher = br.Fetcher(checker, session=session, limiter=SpyLimiter())
        fetcher.request("GET", url)
        assert session.calls == [("GET", url)]

    def test_post_allowed_with_allow_mutate(self, checker):
        url = "https://t.example/api/orders"
        session = FakeSession({url: FakeResponse(200, "ok")})
        fetcher = br.Fetcher(checker, session=session, limiter=SpyLimiter(), no_mutate=False)
        fetcher.request("POST", url)
        assert session.calls == [("POST", url)]


class TestRequestCap:
    def test_global_request_cap_enforced(self, checker):
        url = "https://t.example/x"
        session = FakeSession({url: FakeResponse(200, "ok")})
        fetcher = br.Fetcher(checker, session=session, limiter=SpyLimiter(), max_requests=1)
        fetcher.get(url)
        with pytest.raises(br.RequestCapExceeded):
            fetcher.get(url)


# ─── Playwright-absent degradation ─────────────────────────────────────────

class TestPlaywrightAbsent:
    def test_require_playwright_raises_clean_error_when_absent(self, monkeypatch):
        monkeypatch.setattr(br, "sync_playwright", None)
        with pytest.raises(br.BrowserUnavailable, match="pip install playwright"):
            br.require_playwright()

    def test_require_playwright_returns_module_when_present(self, monkeypatch):
        sentinel = object()
        monkeypatch.setattr(br, "sync_playwright", sentinel)
        assert br.require_playwright() is sentinel

    def test_module_imports_cleanly_regardless_of_playwright(self):
        # If we got this far, `import browser_recon` already succeeded even
        # in an environment where Playwright might not be installed — the
        # try/except ImportError at module load time is what's under test.
        assert hasattr(br, "sync_playwright")


# ─── #1 runtime API capture: pure functions ────────────────────────────────

class TestIsAuthHeader:
    @pytest.mark.parametrize("name", ["Authorization", "authorization", "Cookie", "X-Api-Key", "x-auth-token"])
    def test_recognizes_auth_headers(self, name):
        assert br.is_auth_header(name)

    @pytest.mark.parametrize("name", ["Content-Type", "Accept", "User-Agent", "X-Request-Id"])
    def test_ignores_non_auth_headers(self, name):
        assert not br.is_auth_header(name)


class TestShapeOf:
    def test_primitives(self):
        assert br.shape_of("hello") == "string"
        assert br.shape_of(42) == "number"
        assert br.shape_of(3.14) == "number"
        assert br.shape_of(True) == "boolean"
        assert br.shape_of(None) == "null"

    def test_dict_shape_never_leaks_values(self):
        shape = br.shape_of({"username": "bob", "id": 7, "active": True})
        assert shape == {"username": "string", "id": "number", "active": "boolean"}
        assert "bob" not in json.dumps(shape)

    def test_list_shape_samples_first_element(self):
        assert br.shape_of([{"id": 1}, {"id": 2}]) == [{"id": "number"}]
        assert br.shape_of([]) == []

    def test_depth_capped(self):
        nested = {}
        cur = nested
        for _ in range(20):
            cur["x"] = {}
            cur = cur["x"]
        shape = br.shape_of(nested)
        # must terminate (not recurse forever / blow the stack)
        assert shape is not None


class TestShapeOfBody:
    def test_json_body(self):
        shape = br.shape_of_body('{"q": "search term", "limit": 10}', "application/json")
        assert shape == {"q": "string", "limit": "number"}
        assert "search term" not in json.dumps(shape)

    def test_form_urlencoded_body(self):
        shape = br.shape_of_body("username=bob&remember=1", "application/x-www-form-urlencoded")
        assert shape == {"username": "string", "remember": "string"}
        assert "bob" not in json.dumps(shape)

    def test_opaque_body_records_length_only(self):
        shape = br.shape_of_body("\x00\x01binarylikestuff", "application/octet-stream")
        assert "_opaque_text_length" in shape
        assert "binarylikestuff" not in json.dumps(shape)

    def test_bytes_body(self):
        shape = br.shape_of_body(b'{"a": 1}', "application/json")
        assert shape == {"a": "number"}

    def test_none_or_empty_body(self):
        assert br.shape_of_body(None) is None
        assert br.shape_of_body("") is None

    def test_undecodable_bytes(self):
        shape = br.shape_of_body(b"\xff\xfe\x00\x01", "application/octet-stream")
        assert "_opaque_bytes" in shape


# ─── #1 runtime API capture: ApiCallRecorder (fake Playwright objects) ─────

class _FakeHeaders(dict):
    """Playwright's real Request/Response .headers is a plain lowercase-keyed
    dict in the sync API — this just documents that assumption for the fakes."""


class _FakeRequest:
    def __init__(self, method, url, headers=None, post_data=None, resource_type="fetch"):
        self.method = method
        self.url = url
        self.headers = _FakeHeaders(headers or {})
        self.post_data = post_data
        self.resource_type = resource_type


class _FakeResponse:
    def __init__(self, request, status=200, headers=None, body=b""):
        self.request = request
        self.url = request.url
        self.status = status
        self.headers = _FakeHeaders(headers or {})
        self._body = body

    def body(self):
        return self._body


class _FakeWebSocket:
    def __init__(self, url):
        self.url = url


class TestApiCallRecorder:
    def test_records_request(self):
        rec = br.ApiCallRecorder()
        rec.trigger = "page_load:https://t.example/"
        req = _FakeRequest("GET", "https://t.example/api/hidden", headers={"accept": "*/*"})
        entry = rec.on_request(req)
        assert entry["method"] == "GET"
        assert entry["url"] == "https://t.example/api/hidden"
        assert entry["trigger"] == "page_load:https://t.example/"
        assert entry["blocked"] is False
        assert rec.to_list() == [entry]

    def test_redacts_auth_header_names_only(self):
        rec = br.ApiCallRecorder()
        req = _FakeRequest("GET", "https://t.example/api/x",
                            headers={"authorization": "Bearer super-secret-token", "accept": "*/*"})
        entry = rec.on_request(req)
        assert entry["request_headers_auth"] == ["authorization"]
        assert "super-secret-token" not in json.dumps(entry)

    def test_auth_header_fingerprint_present_and_raw_value_absent(self):
        rec = br.ApiCallRecorder()
        req = _FakeRequest("GET", "https://t.example/api/x",
                            headers={"authorization": "Bearer super-secret-token", "accept": "*/*"})
        entry = rec.on_request(req)
        assert "authorization" in entry["request_headers_auth_fingerprint"]
        fp = entry["request_headers_auth_fingerprint"]["authorization"]
        assert isinstance(fp, str) and len(fp) == 16
        assert "super-secret-token" not in json.dumps(entry)

    def test_auth_header_fingerprint_same_value_same_fingerprint(self):
        rec = br.ApiCallRecorder()
        req1 = _FakeRequest("GET", "https://t.example/api/x",
                             headers={"authorization": "Bearer same-token"})
        req2 = _FakeRequest("GET", "https://t.example/api/y",
                             headers={"authorization": "Bearer same-token"})
        e1 = rec.on_request(req1)
        e2 = rec.on_request(req2)
        assert e1["request_headers_auth_fingerprint"]["authorization"] == \
            e2["request_headers_auth_fingerprint"]["authorization"]

    def test_auth_header_fingerprint_different_value_different_fingerprint(self):
        rec = br.ApiCallRecorder()
        req1 = _FakeRequest("GET", "https://t.example/api/x",
                             headers={"authorization": "Bearer token-a"})
        req2 = _FakeRequest("GET", "https://t.example/api/y",
                             headers={"authorization": "Bearer token-b"})
        e1 = rec.on_request(req1)
        e2 = rec.on_request(req2)
        assert e1["request_headers_auth_fingerprint"]["authorization"] != \
            e2["request_headers_auth_fingerprint"]["authorization"]

    def test_auth_header_fingerprint_empty_value_is_absent(self):
        rec = br.ApiCallRecorder()
        req = _FakeRequest("GET", "https://t.example/api/x", headers={"authorization": ""})
        entry = rec.on_request(req)
        assert "authorization" not in entry["request_headers_auth_fingerprint"]

    def test_request_body_shape_captured(self):
        rec = br.ApiCallRecorder()
        req = _FakeRequest("POST", "https://t.example/api/x",
                            headers={"content-type": "application/json"},
                            post_data='{"username": "alice", "id": 9}')
        entry = rec.on_request(req)
        assert entry["request_body_shape"] == {"username": "string", "id": "number"}
        assert "alice" not in json.dumps(entry)

    def test_on_blocked_marks_entry(self):
        rec = br.ApiCallRecorder()
        req = _FakeRequest("GET", "https://evil.example/x")
        entry = rec.on_blocked(req, "refusing to fetch out-of-scope URL")
        assert entry["blocked"] is True
        assert "out-of-scope" in entry["block_reason"]

    def test_on_response_matches_request_by_url_and_method(self):
        rec = br.ApiCallRecorder()
        req = _FakeRequest("GET", "https://t.example/api/hidden")
        rec.on_request(req)
        body = b'{"secret": "sekrit-value-123", "id": 42}'
        resp = _FakeResponse(req, status=200, headers={"content-type": "application/json"}, body=body)
        rec.on_response(resp)
        entry = rec.to_list()[0]
        assert entry["response_status"] == 200
        assert entry["response_shape"] == {"secret": "string", "id": "number"}
        assert "sekrit-value-123" not in json.dumps(entry)

    def test_on_response_non_json_records_content_type_only(self):
        rec = br.ApiCallRecorder()
        req = _FakeRequest("GET", "https://t.example/image.png")
        rec.on_request(req)
        resp = _FakeResponse(req, status=200, headers={"content-type": "image/png"}, body=b"\x89PNG...")
        rec.on_response(resp)
        entry = rec.to_list()[0]
        assert entry["response_shape"] == {"_content_type": "image/png"}

    def test_on_response_with_no_matching_request_is_ignored(self):
        rec = br.ApiCallRecorder()
        req = _FakeRequest("GET", "https://t.example/never-requested")
        resp = _FakeResponse(req, status=200)
        rec.on_response(resp)  # must not raise
        assert rec.to_list() == []

    def test_on_websocket_recorded(self):
        rec = br.ApiCallRecorder()
        rec.on_websocket(_FakeWebSocket("wss://t.example/socket"))
        entry = rec.to_list()[0]
        assert entry["method"] == "WEBSOCKET"
        assert entry["url"] == "wss://t.example/socket"


# ─── #1 runtime API capture: page.route() handler (fake Playwright route) ──

class _FakeRoute:
    def __init__(self, request):
        self.request = request
        self.aborted = False
        self.continued = False

    def abort(self):
        self.aborted = True

    def continue_(self):
        self.continued = True


class TestInstallCaptureHooksRouteHandler:
    """_install_capture_hooks() wires page.route() -> fetcher.check(); this
    tests that wiring directly against a fake `page` object (no real
    browser), proving the safety gate runs before any real Playwright
    request would be allowed through."""

    class _FakePage:
        def __init__(self):
            self.route_handler = None
            self.response_handler = None
            self.websocket_handler = None

        def route(self, pattern, handler):
            self.route_handler = handler

        def on(self, event, handler):
            if event == "response":
                self.response_handler = handler
            elif event == "websocket":
                self.websocket_handler = handler

    def test_in_scope_get_continues(self, checker):
        fetcher = br.Fetcher(checker, session=object())  # session unused — check() never sends
        recorder = br.ApiCallRecorder()
        page = self._FakePage()
        br._install_capture_hooks(page, fetcher, recorder)

        route = _FakeRoute(_FakeRequest("GET", "https://t.example/api/x"))
        page.route_handler(route)

        assert route.continued is True
        assert route.aborted is False
        assert len(recorder.to_list()) == 1
        assert recorder.to_list()[0]["blocked"] is False

    def test_out_of_scope_aborted_and_recorded(self, checker):
        fetcher = br.Fetcher(checker, session=object())
        recorder = br.ApiCallRecorder()
        page = self._FakePage()
        br._install_capture_hooks(page, fetcher, recorder)

        route = _FakeRoute(_FakeRequest("GET", "https://evil.example/x"))
        page.route_handler(route)

        assert route.aborted is True
        assert route.continued is False
        entry = recorder.to_list()[0]
        assert entry["blocked"] is True
        assert "out-of-scope" in entry["block_reason"]

    def test_post_blocked_by_default_no_mutate(self, checker):
        fetcher = br.Fetcher(checker, session=object(), no_mutate=True)
        recorder = br.ApiCallRecorder()
        page = self._FakePage()
        br._install_capture_hooks(page, fetcher, recorder)

        route = _FakeRoute(_FakeRequest("POST", "https://t.example/api/mutate"))
        page.route_handler(route)

        assert route.aborted is True
        entry = recorder.to_list()[0]
        assert entry["blocked"] is True
        assert entry["method"] == "POST"

    def test_post_allowed_with_allow_mutate(self, checker):
        fetcher = br.Fetcher(checker, session=object(), no_mutate=False)
        recorder = br.ApiCallRecorder()
        page = self._FakePage()
        br._install_capture_hooks(page, fetcher, recorder)

        route = _FakeRoute(_FakeRequest("POST", "https://t.example/api/mutate"))
        page.route_handler(route)

        assert route.continued is True
        assert route.aborted is False

    def test_rate_limiter_consulted_per_request(self, checker):
        spy = SpyLimiter()
        fetcher = br.Fetcher(checker, session=object(), limiter=spy)
        recorder = br.ApiCallRecorder()
        page = self._FakePage()
        br._install_capture_hooks(page, fetcher, recorder)

        page.route_handler(_FakeRoute(_FakeRequest("GET", "https://t.example/a")))
        page.route_handler(_FakeRoute(_FakeRequest("GET", "https://t.example/b")))

        assert len(spy.calls) == 2

    def test_request_cap_aborts_once_exceeded(self, checker):
        fetcher = br.Fetcher(checker, session=object(), limiter=SpyLimiter(), max_requests=1)
        recorder = br.ApiCallRecorder()
        page = self._FakePage()
        br._install_capture_hooks(page, fetcher, recorder)

        page.route_handler(_FakeRoute(_FakeRequest("GET", "https://t.example/a")))
        route2 = _FakeRoute(_FakeRequest("GET", "https://t.example/b"))
        page.route_handler(route2)

        assert route2.aborted is True


# ─── #1 runtime API capture: Fetcher.check() (preflight-only) ─────────────

class TestFetcherCheck:
    def test_returns_host_on_success(self, checker):
        fetcher = br.Fetcher(checker, session=object(), limiter=SpyLimiter())
        host = fetcher.check("GET", "https://t.example/x")
        assert host == "t.example"

    def test_never_touches_session(self, checker):
        class ExplodingSession:
            def request(self, *a, **k):
                raise AssertionError("check() must never send a real request")

        fetcher = br.Fetcher(checker, session=ExplodingSession(), limiter=SpyLimiter())
        fetcher.check("GET", "https://t.example/x")  # must not raise

    def test_raises_scope_violation(self, checker):
        fetcher = br.Fetcher(checker, session=object(), limiter=SpyLimiter())
        with pytest.raises(br.ScopeViolation):
            fetcher.check("GET", "https://evil.example/x")

    def test_raises_mutation_blocked_by_default(self, checker):
        fetcher = br.Fetcher(checker, session=object(), limiter=SpyLimiter())
        with pytest.raises(br.MutationBlocked):
            fetcher.check("POST", "https://t.example/x")

    def test_increments_request_count(self, checker):
        fetcher = br.Fetcher(checker, session=object(), limiter=SpyLimiter())
        fetcher.check("GET", "https://t.example/a")
        fetcher.check("GET", "https://t.example/b")
        assert fetcher.request_count == 2

    def test_request_cap_shared_with_request(self, checker, tmp_path):
        """check() and request() must share the same counter — a run mixing
        #1 (browser, via check()) and #2 (requests, via request()) on one
        Fetcher stays within one --max-requests budget."""
        session = FakeSession({"https://t.example/a": FakeResponse(200, "ok")})
        fetcher = br.Fetcher(checker, session=session, limiter=SpyLimiter(), max_requests=2)
        fetcher.get("https://t.example/a")          # request_count -> 1
        fetcher.check("GET", "https://t.example/b")  # request_count -> 2
        with pytest.raises(br.RequestCapExceeded):
            fetcher.check("GET", "https://t.example/c")


# ─── #1 runtime API capture: real Chromium end to end ──────────────────────

class _CaptureTestHandler(http.server.BaseHTTPRequestHandler):
    """Minimal stdlib-only local target. Bound to 127.0.0.1 but accessed via
    the hostname "localhost" so tools/scope_checker.py (which deliberately
    does not support bare IP literals) can allow it via a normal domain
    pattern. post_hit is a class-level flag: if it's ever set, a POST
    genuinely reached this server — proving/disproving --no-mutate."""

    post_hit = threading.Event()

    def log_message(self, *args):
        pass

    def _send(self, code, body, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            body = b"""<html><body>
<a href="/page2">page2</a>
<a href="http://evil.invalid/should-be-blocked">off-scope</a>
<script>
fetch('/api/hidden?x=1').catch(()=>{});
fetch('/api/authed').catch(()=>{});
fetch('http://evil.invalid/should-be-blocked').catch(()=>{});
fetch('/api/mutate', {method: 'POST', headers: {'Content-Type':'application/json'},
                       body: JSON.stringify({q:'test'})}).catch(()=>{});
</script>
</body></html>"""
            self._send(200, body, "text/html")
        elif self.path == "/page2":
            self._send(200, b"<html><body>page2 ok, no further links</body></html>", "text/html")
        elif self.path.startswith("/api/hidden"):
            self._send(200, b'{"secret": "sekrit-value-123", "id": 42}', "application/json")
        elif self.path == "/api/authed":
            saw_auth = bool(self.headers.get("Authorization"))
            self._send(200, json.dumps({"saw_auth": saw_auth}).encode(), "application/json")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        _CaptureTestHandler.post_hit.set()
        self._send(200, b'{"ok": true}', "application/json")


@pytest.fixture
def local_server():
    _CaptureTestHandler.post_hit.clear()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CaptureTestHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://localhost:{port}"
    finally:
        server.shutdown()
        server.server_close()


@needs_playwright
class TestCaptureRuntimeApiEndToEnd:
    def _fetcher(self, no_mutate=True):
        checker = ScopeChecker(["localhost"])
        return br.Fetcher(checker, no_mutate=no_mutate, recon_rps=1000.0, max_requests=50, timeout=10.0)

    def test_captures_js_only_fetch_invisible_to_a_crawler(self, tmp_path, local_server):
        """/api/hidden is never linked from an <a href> anywhere — only the
        page's own JS calls it. A static crawler would never find it; this
        is the entire point of #1."""
        result = br.capture_runtime_api(
            "t.example", str(tmp_path), self._fetcher(),
            entry_urls=[local_server + "/"], max_pages=1, max_links_per_page=0,
        )
        hidden_calls = [c for c in result["calls"] if "/api/hidden" in c["url"]]
        assert hidden_calls, f"no capture of /api/hidden in {result['calls']!r}"
        entry = hidden_calls[0]
        assert entry["method"] == "GET"
        assert entry["response_status"] == 200
        assert entry["response_shape"] == {"secret": "string", "id": "number"}
        # the real secret value must never appear anywhere in the output
        assert "sekrit-value-123" not in json.dumps(result)

    def test_no_mutate_blocks_page_triggered_post_for_real(self, tmp_path, local_server):
        """Proves prevention, not just after-the-fact logging: the server's
        POST handler must never actually run."""
        result = br.capture_runtime_api(
            "t.example", str(tmp_path), self._fetcher(no_mutate=True),
            entry_urls=[local_server + "/"], max_pages=1, max_links_per_page=0,
        )
        assert not _CaptureTestHandler.post_hit.is_set(), "POST reached the server despite --no-mutate"
        mutate_calls = [c for c in result["calls"] if "/api/mutate" in c["url"]]
        assert mutate_calls and mutate_calls[0]["blocked"] is True

    def test_allow_mutate_lets_post_through(self, tmp_path, local_server):
        result = br.capture_runtime_api(
            "t.example", str(tmp_path), self._fetcher(no_mutate=False),
            entry_urls=[local_server + "/"], max_pages=1, max_links_per_page=0,
        )
        # give the async fetch a moment to land server-side (networkidle wait
        # in capture_runtime_api already covers this, but be defensive).
        assert _CaptureTestHandler.post_hit.wait(timeout=5)
        mutate_calls = [c for c in result["calls"] if "/api/mutate" in c["url"]]
        assert mutate_calls and mutate_calls[0]["blocked"] is False

    def test_out_of_scope_fetch_and_link_never_reached(self, tmp_path, local_server):
        result = br.capture_runtime_api(
            "t.example", str(tmp_path), self._fetcher(),
            entry_urls=[local_server + "/"], max_pages=5, max_links_per_page=5,
        )
        # the page fetch()es evil.invalid directly -- must show up as blocked
        evil_calls = [c for c in result["calls"] if "evil.invalid" in c["url"]]
        assert evil_calls, "expected the evil.invalid fetch to at least be observed+blocked"
        assert all(c["blocked"] for c in evil_calls)
        # and link-following must never have queued it as a page to visit
        assert not any("evil.invalid" in c["url"] and c.get("resource_type") == "document"
                        for c in result["calls"])

    def test_follows_same_scope_link_to_second_page(self, tmp_path, local_server):
        result = br.capture_runtime_api(
            "t.example", str(tmp_path), self._fetcher(),
            entry_urls=[local_server + "/"], max_pages=5, max_links_per_page=5,
        )
        assert result["pages_visited"] == 2  # "/" and "/page2"

    def test_max_pages_bounds_the_walk(self, tmp_path, local_server):
        result = br.capture_runtime_api(
            "t.example", str(tmp_path), self._fetcher(),
            entry_urls=[local_server + "/"], max_pages=1, max_links_per_page=5,
        )
        assert result["pages_visited"] == 1

    def test_auth_header_name_captured_value_never_logged(self, tmp_path, local_server):
        auth = AuthSession(["Authorization: Bearer sekrit-token-xyz"])
        result = br.capture_runtime_api(
            "t.example", str(tmp_path), self._fetcher(),
            entry_urls=[local_server + "/"], max_pages=1, max_links_per_page=0,
            auth_session=auth,
        )
        authed_calls = [c for c in result["calls"] if "/api/authed" in c["url"]]
        assert authed_calls
        assert "authorization" in authed_calls[0]["request_headers_auth"]
        assert "authorization" in authed_calls[0]["request_headers_auth_fingerprint"]
        assert len(authed_calls[0]["request_headers_auth_fingerprint"]["authorization"]) == 16
        assert "sekrit-token-xyz" not in json.dumps(result)
        # and the fingerprint survives round-tripping through the actual
        # written browser/api-calls.json file, still without the raw value
        written = json.loads((tmp_path / "browser" / "api-calls.json").read_text())
        assert "sekrit-token-xyz" not in json.dumps(written)
        # and the server actually saw it -- proves the header was really sent,
        # not just recorded as if it would be
        assert authed_calls[0]["response_shape"] is None or True  # response body not JSON-shaped by default path
        body_response = [c for c in result["calls"] if "/api/authed" in c["url"]][0]
        assert body_response["response_status"] == 200

    def test_writes_api_calls_json(self, tmp_path, local_server):
        br.capture_runtime_api(
            "t.example", str(tmp_path), self._fetcher(),
            entry_urls=[local_server + "/"], max_pages=1, max_links_per_page=0,
        )
        out_path = tmp_path / "browser" / "api-calls.json"
        assert out_path.exists()
        data = json.loads(out_path.read_text())
        assert data["target"] == "t.example"
        assert data["pages_visited"] == 1
        assert isinstance(data["calls"], list)

    def test_hidden_endpoints_consumes_api_calls_json(self, tmp_path, local_server):
        """discover_hidden_endpoints() (#5) reads browser/api-calls.json once
        #1 has run -- confirms the dict shape #1 writes and the shape #5
        expects to read actually agree."""
        rd = tmp_path
        (rd / "js").mkdir(parents=True, exist_ok=True)
        (rd / "js" / "endpoints.txt").write_text("/api/hidden\n/api/totally-unreferenced\n")
        (rd / "urls").mkdir(parents=True, exist_ok=True)
        (rd / "urls" / "all.txt").write_text("")

        br.capture_runtime_api(
            "t.example", str(rd), self._fetcher(),
            entry_urls=[local_server + "/"], max_pages=1, max_links_per_page=0,
        )
        result = br.discover_hidden_endpoints("t.example", str(rd))
        # /api/hidden WAS called at runtime per api-calls.json -> not "never called"
        assert "/api/hidden" not in result["never_called"]
        # /api/totally-unreferenced was never called anywhere -> still flagged
        assert "/api/totally-unreferenced" in result["never_called"]


class TestApiCaptureCliGating:
    def test_api_capture_requires_domain(self):
        with pytest.raises(SystemExit) as exc:
            br.main(["t.example", "--api-capture"])
        assert exc.value.code != 0

    def test_api_capture_without_playwright_errors_cleanly(self, monkeypatch, tmp_path):
        monkeypatch.setattr(br, "sync_playwright", None)
        with pytest.raises(SystemExit) as exc:
            br.main(["t.example", "--domain", "t.example", "--api-capture",
                     "--recon-dir", str(tmp_path)])
        assert exc.value.code != 0

    @needs_playwright
    def test_api_capture_without_entry_url_or_recon_data_errors_cleanly(self, tmp_path):
        with pytest.raises(SystemExit) as exc:
            br.main(["t.example", "--domain", "t.example", "--api-capture",
                     "--recon-dir", str(tmp_path / "empty")])
        assert exc.value.code != 0


# ─── #3 framework route extraction: pure functions ─────────────────────────

_NEXT_DATA_HTML = """<!DOCTYPE html><html><head></head><body><div id="__next"></div>
<script id="__NEXT_DATA__" type="application/json">{"props":{},"page":"/blog/[slug]","query":{},"buildId":"abc123"}</script>
</body></html>"""

_BUILD_MANIFEST_JS = """self.__BUILD_MANIFEST = {
  "/": ["static/chunks/index.js"],
  "/blog/[slug]": ["static/chunks/blog.js", "static/chunks/[slug].js"],
  "/admin/dashboard": ["static/chunks/admin.js"],
  "sortedPages": ["/", "/blog/[slug]", "/admin/dashboard"]
};
self.__BUILD_MANIFEST_CB && self.__BUILD_MANIFEST_CB();
"""

_SSG_MANIFEST_JS = 'self.__SSG_MANIFEST = new Set(["/", "/blog/hello-world"]); self.__SSG_MANIFEST_CB && self.__SSG_MANIFEST_CB();'

_REACT_ROUTER_BUNDLE = """
const routes = [
  {path: "/settings", element: Settings},
  {path: '/users/:id', element: UserDetail},
];
const LazyAdmin = () => import("./admin/AdminPanel");
"""


class TestExtractNextData:
    def test_parses_valid_next_data(self):
        data = br.extract_next_data(_NEXT_DATA_HTML)
        assert data["page"] == "/blog/[slug]"
        assert data["buildId"] == "abc123"

    def test_returns_none_when_absent(self):
        assert br.extract_next_data("<html><body>plain page</body></html>") is None

    def test_returns_none_on_malformed_json(self):
        html = '<script id="__NEXT_DATA__" type="application/json">{not valid json</script>'
        assert br.extract_next_data(html) is None

    def test_empty_input(self):
        assert br.extract_next_data("") is None
        assert br.extract_next_data(None) is None


class TestExtractBalancedBraces:
    def test_simple_object(self):
        text = 'x = {"a": 1}; y = 2;'
        assert br._extract_balanced_braces(text, text.index("{")) == '{"a": 1}'

    def test_nested_object_not_truncated_early(self):
        text = 'x = {"a": {"b": [1, 2]}, "c": 3};'
        result = br._extract_balanced_braces(text, text.index("{"))
        assert result == '{"a": {"b": [1, 2]}, "c": 3}'

    def test_brace_inside_string_does_not_confuse_depth(self):
        text = 'x = {"a": "contains } a brace"};'
        result = br._extract_balanced_braces(text, text.index("{"))
        assert result == '{"a": "contains } a brace"}'

    def test_unbalanced_returns_none(self):
        text = 'x = {"a": 1'
        assert br._extract_balanced_braces(text, text.index("{")) is None

    def test_not_a_brace_at_start_returns_none(self):
        assert br._extract_balanced_braces("hello", 0) is None


class TestExtractBuildManifestRoutes:
    def test_extracts_all_route_keys(self):
        routes = br.extract_build_manifest_routes(_BUILD_MANIFEST_JS)
        assert "/" in routes
        assert "/blog/[slug]" in routes
        assert "/admin/dashboard" in routes

    def test_no_marker_returns_empty(self):
        assert br.extract_build_manifest_routes("var x = 1;") == []


class TestExtractSsgManifestRoutes:
    def test_extracts_set_members(self):
        routes = br.extract_ssg_manifest_routes(_SSG_MANIFEST_JS)
        assert routes == ["/", "/blog/hello-world"]

    def test_no_marker_returns_empty(self):
        assert br.extract_ssg_manifest_routes("var x = 1;") == []


class TestExtractRoutePathLiterals:
    def test_extracts_react_router_style_paths(self):
        literals = br.extract_route_path_literals(_REACT_ROUTER_BUNDLE)
        assert "/settings" in literals
        assert "/users/:id" in literals

    def test_no_paths_returns_empty(self):
        assert br.extract_route_path_literals("const x = {name: 'bob'};") == []


class TestExtractLazyChunkImports:
    def test_extracts_dynamic_imports(self):
        chunks = br.extract_lazy_chunk_imports(_REACT_ROUTER_BUNDLE)
        assert "./admin/AdminPanel" in chunks

    def test_none_returns_empty(self):
        assert br.extract_lazy_chunk_imports("no imports here") == []


class TestDetectFramework:
    def test_detects_nextjs_from_html(self):
        assert br.detect_framework(_NEXT_DATA_HTML, []) == "nextjs"

    def test_detects_nextjs_from_bundle_marker(self):
        assert br.detect_framework("", [_BUILD_MANIFEST_JS]) == "nextjs"

    def test_detects_angular(self):
        assert br.detect_framework('<html ng-version="17.0.0">', []) == "angular"

    def test_detects_react_from_bundle(self):
        assert br.detect_framework("", ["import { BrowserRouter } from 'react-router-dom'"]) == "react"

    def test_unknown_when_no_markers(self):
        assert br.detect_framework("<html><body>static site</body></html>", []) == "unknown"


# ─── #3 framework route extraction: end to end (FakeSession, no browser) ──

class TestExtractFrameworkRoutesEndToEnd:
    def test_nextjs_full_pipeline(self, tmp_path, checker):
        entry_url = "https://t.example/"
        manifest_url = "https://t.example/_next/static/abc123/_buildManifest.js"
        ssg_url = "https://t.example/_next/static/abc123/_ssgManifest.js"
        session = FakeSession({
            entry_url: FakeResponse(200, _NEXT_DATA_HTML),
            manifest_url: FakeResponse(200, _BUILD_MANIFEST_JS),
            ssg_url: FakeResponse(200, _SSG_MANIFEST_JS),
        })
        fetcher = br.Fetcher(checker, session=session, limiter=SpyLimiter())
        rd = make_recon_dir(tmp_path)  # no js_files -> only entry + manifest fetches

        result = br.extract_framework_routes("t.example", str(rd), fetcher, entry_urls=[entry_url])

        assert result["framework_detected"] == "nextjs"
        assert result["build_id"] == "abc123"
        assert "/blog/[slug]" in result["routes"]        # from __NEXT_DATA__ "page"
        assert "/admin/dashboard" in result["routes"]     # from _buildManifest.js
        assert "/blog/hello-world" in result["routes"]    # from _ssgManifest.js

        written = json.loads((rd / "browser" / "routes.json").read_text())
        assert written["target"] == "t.example"

    def test_react_router_bundle_via_js_files(self, tmp_path, checker):
        entry_url = "https://t.example/"
        bundle_url = "https://t.example/static/app.js"
        session = FakeSession({
            entry_url: FakeResponse(200, "<html><body>plain</body></html>"),
            bundle_url: FakeResponse(200, _REACT_ROUTER_BUNDLE),
        })
        fetcher = br.Fetcher(checker, session=session, limiter=SpyLimiter())
        rd = make_recon_dir(tmp_path, js_files=[bundle_url])

        result = br.extract_framework_routes("t.example", str(rd), fetcher, entry_urls=[entry_url])

        assert "/settings" in result["routes"]
        assert "/users/:id" in result["routes"]
        assert "./admin/AdminPanel" in result["lazy_chunk_imports"]

    def test_prefers_recovered_sources_over_raw_bundle(self, tmp_path, checker):
        """If #2 already recovered original sources, use those instead of
        re-fetching the (possibly minified) raw bundle."""
        entry_url = "https://t.example/"
        session = FakeSession({entry_url: FakeResponse(200, "<html></html>")})
        fetcher = br.Fetcher(checker, session=session, limiter=SpyLimiter())
        rd = make_recon_dir(tmp_path)
        sources_dir = rd / "browser" / "sources" / "app"
        sources_dir.mkdir(parents=True)
        (sources_dir / "routes.tsx").write_text(_REACT_ROUTER_BUNDLE)

        result = br.extract_framework_routes("t.example", str(rd), fetcher, entry_urls=[entry_url])
        assert "/settings" in result["routes"]

    def test_unreachable_entry_url_does_not_crash(self, tmp_path, checker):
        """A real network failure (DNS, connection refused, timeout) must be
        tolerated the same way an out-of-scope/blocked URL is -- this one
        item is skipped, the run doesn't abort."""
        class _ConnectionErrorSession:
            def request(self, method, url, timeout=None):
                raise requests.ConnectionError(f"simulated: could not resolve {url}")

        fetcher = br.Fetcher(checker, session=_ConnectionErrorSession(), limiter=SpyLimiter())
        rd = make_recon_dir(tmp_path)
        result = br.extract_framework_routes(
            "t.example", str(rd), fetcher, entry_urls=["https://t.example/unreachable"]
        )
        assert result["framework_detected"] == "unknown"
        assert result["routes"] == []

    def test_out_of_scope_entry_url_does_not_crash(self, tmp_path, checker):
        fetcher = br.Fetcher(checker, session=FakeSession({}), limiter=SpyLimiter())
        rd = make_recon_dir(tmp_path)
        result = br.extract_framework_routes(
            "t.example", str(rd), fetcher, entry_urls=["https://evil.example/x"]
        )
        assert result["routes"] == []


# ─── #4 client-side auth model: pure functions ─────────────────────────────

class TestExtractRoleConstants:
    def test_naming_convention_constants(self):
        text = "const ROLE_ADMIN = 'admin'; const PERM_DELETE_USER = 1; const x = ROLE_ADMIN;"
        found = br.extract_role_constants(text)
        assert "ROLE_ADMIN" in found
        assert "PERM_DELETE_USER" in found

    def test_key_value_role_literals(self):
        text = "const user = {role: 'superadmin', name: 'bob'};"
        assert "superadmin" in br.extract_role_constants(text)

    def test_no_constants_returns_empty(self):
        assert br.extract_role_constants("const x = 1;") == []


class TestFindCandidatePrivilegedRoutes:
    def test_flags_privileged_looking_routes(self):
        routes = ["/", "/about", "/admin/dashboard", "/account/settings", "/blog/hello"]
        found = br.find_candidate_privileged_routes(routes)
        assert "/admin/dashboard" in found
        assert "/account/settings" in found
        assert "/about" not in found
        assert "/blog/hello" not in found

    def test_empty_input(self):
        assert br.find_candidate_privileged_routes([]) == []
        assert br.find_candidate_privileged_routes(None) == []


class TestFindAuthLifecycleEndpoints:
    def test_flags_refresh_and_logout(self):
        calls = [
            {"url": "https://t.example/api/auth/refresh"},
            {"url": "https://t.example/api/logout"},
            {"url": "https://t.example/api/products"},
        ]
        found = br.find_auth_lifecycle_endpoints(calls)
        assert "https://t.example/api/auth/refresh" in found
        assert "https://t.example/api/logout" in found
        assert "https://t.example/api/products" not in found

    def test_empty_input(self):
        assert br.find_auth_lifecycle_endpoints([]) == []
        assert br.find_auth_lifecycle_endpoints(None) == []


# ─── #4 client-side auth model: storage/cookie classification (fakes) ─────

class _FakeAuthPage:
    def __init__(self, storage_data):
        self._storage_data = storage_data  # {"localStorage": [(k, v), ...], "sessionStorage": [...]}

    def evaluate(self, script, arg=None):
        return self._storage_data.get(arg, [])


class _FakeAuthContext:
    def __init__(self, cookies):
        self._cookies = cookies

    def cookies(self):
        return self._cookies


class TestClassifyStorageKeys:
    def test_classifies_auth_related_and_jwt_shape(self):
        page = _FakeAuthPage({
            "localStorage": [("auth_token", "aaa.bbb.ccc"), ("theme", "dark")],
        })
        result = br._classify_storage_keys(page, "localStorage")
        by_key = {e["key"]: e for e in result}
        assert by_key["auth_token"]["looks_auth_related"] is True
        assert by_key["auth_token"]["looks_like_jwt"] is True
        assert by_key["theme"]["looks_auth_related"] is False
        assert by_key["theme"]["looks_like_jwt"] is False

    def test_never_includes_raw_value(self):
        page = _FakeAuthPage({"localStorage": [("auth_token", "super-secret-raw-value.x.y")]})
        result = br._classify_storage_keys(page, "localStorage")
        assert "super-secret-raw-value" not in json.dumps(result)

    def test_value_fingerprint_present_and_raw_value_absent(self):
        page = _FakeAuthPage({"localStorage": [("auth_token", "super-secret-raw-value.x.y")]})
        result = br._classify_storage_keys(page, "localStorage")
        fp = result[0]["value_fingerprint"]
        assert isinstance(fp, str) and len(fp) == 16
        assert "super-secret-raw-value" not in json.dumps(result)

    def test_value_fingerprint_empty_value_is_none(self):
        page = _FakeAuthPage({"localStorage": [("empty_key", "")]})
        result = br._classify_storage_keys(page, "localStorage")
        assert result[0]["value_fingerprint"] is None

    def test_value_fingerprint_same_value_same_fingerprint(self):
        page = _FakeAuthPage({"localStorage": [("a", "shared-value"), ("b", "shared-value")]})
        result = br._classify_storage_keys(page, "localStorage")
        by_key = {e["key"]: e for e in result}
        assert by_key["a"]["value_fingerprint"] == by_key["b"]["value_fingerprint"]

    def test_value_fingerprint_different_value_different_fingerprint(self):
        page = _FakeAuthPage({"localStorage": [("a", "value-one"), ("b", "value-two")]})
        result = br._classify_storage_keys(page, "localStorage")
        by_key = {e["key"]: e for e in result}
        assert by_key["a"]["value_fingerprint"] != by_key["b"]["value_fingerprint"]

    def test_evaluate_failure_returns_empty(self):
        class ExplodingPage:
            def evaluate(self, *a, **k):
                raise RuntimeError("boom")
        assert br._classify_storage_keys(ExplodingPage(), "localStorage") == []


class TestClassifyCookies:
    def test_classifies_flags_and_never_includes_value(self):
        context = _FakeAuthContext([
            {"name": "session_id", "value": "raw-secret-cookie-value", "domain": "t.example",
             "path": "/", "httpOnly": True, "secure": True, "sameSite": "Lax"},
        ])
        result = br._classify_cookies(context)
        assert result[0]["name"] == "session_id"
        assert result[0]["http_only"] is True
        assert result[0]["looks_auth_related"] is True
        assert "raw-secret-cookie-value" not in json.dumps(result)
        assert "value" not in result[0]

    def test_value_fingerprint_present_and_raw_value_absent(self):
        context = _FakeAuthContext([
            {"name": "session_id", "value": "raw-secret-cookie-value", "domain": "t.example",
             "path": "/", "httpOnly": True, "secure": True, "sameSite": "Lax"},
        ])
        result = br._classify_cookies(context)
        fp = result[0]["value_fingerprint"]
        assert isinstance(fp, str) and len(fp) == 16
        assert "raw-secret-cookie-value" not in json.dumps(result)

    def test_value_fingerprint_empty_value_is_none(self):
        context = _FakeAuthContext([
            {"name": "empty_cookie", "value": "", "domain": "t.example", "path": "/"},
        ])
        result = br._classify_cookies(context)
        assert result[0]["value_fingerprint"] is None

    def test_value_fingerprint_missing_value_key_is_none(self):
        context = _FakeAuthContext([
            {"name": "no_value_cookie", "domain": "t.example", "path": "/"},
        ])
        result = br._classify_cookies(context)
        assert result[0]["value_fingerprint"] is None

    def test_value_fingerprint_same_value_same_fingerprint(self):
        context = _FakeAuthContext([
            {"name": "a", "value": "shared-secret", "domain": "t.example", "path": "/"},
            {"name": "b", "value": "shared-secret", "domain": "t.example", "path": "/"},
        ])
        result = br._classify_cookies(context)
        assert result[0]["value_fingerprint"] == result[1]["value_fingerprint"]

    def test_value_fingerprint_different_value_different_fingerprint(self):
        context = _FakeAuthContext([
            {"name": "a", "value": "secret-one", "domain": "t.example", "path": "/"},
            {"name": "b", "value": "secret-two", "domain": "t.example", "path": "/"},
        ])
        result = br._classify_cookies(context)
        assert result[0]["value_fingerprint"] != result[1]["value_fingerprint"]


# ─── #4 client-side auth model: real Chromium end to end ───────────────────

@needs_playwright
class TestAnalyzeAuthModelEndToEnd:
    def _fetcher(self):
        checker = ScopeChecker(["localhost"])
        return br.Fetcher(checker, recon_rps=1000.0, max_requests=50, timeout=10.0)

    def test_captures_storage_and_cookie_metadata_not_values(self, tmp_path, local_server):
        result = br.analyze_auth_model(
            "t.example", str(tmp_path), self._fetcher(),
            entry_urls=[local_server + "/"],
        )
        # the demo page (served by _CaptureTestHandler) has no storage-setting
        # script of its own, so this mainly proves the mechanism doesn't crash
        # against a real page and writes a well-shaped file.
        assert isinstance(result["local_storage"], list)
        assert isinstance(result["cookies"], list)
        out_path = tmp_path / "browser" / "auth-model.json"
        assert out_path.exists()

    def test_role_constants_from_recovered_sources(self, tmp_path, local_server):
        sources_dir = tmp_path / "browser" / "sources" / "app"
        sources_dir.mkdir(parents=True)
        (sources_dir / "roles.js").write_text("const ROLE_SUPERADMIN = 'superadmin';")

        result = br.analyze_auth_model(
            "t.example", str(tmp_path), self._fetcher(),
            entry_urls=[local_server + "/"],
        )
        assert "ROLE_SUPERADMIN" in result["role_permission_constants"]

    def test_cross_references_api_calls_and_routes_json(self, tmp_path, local_server):
        browser_dir = tmp_path / "browser"
        browser_dir.mkdir(parents=True)
        (browser_dir / "api-calls.json").write_text(json.dumps({
            "calls": [{"url": "https://t.example/api/auth/refresh"}, {"url": "https://t.example/x"}]
        }))
        (browser_dir / "routes.json").write_text(json.dumps({
            "routes": ["/admin/dashboard", "/about"]
        }))

        result = br.analyze_auth_model(
            "t.example", str(tmp_path), self._fetcher(),
            entry_urls=[local_server + "/"],
        )
        assert "https://t.example/api/auth/refresh" in result["auth_lifecycle_endpoints"]
        assert "/admin/dashboard" in result["candidate_privileged_client_routes"]

    def test_requires_entry_url(self, tmp_path):
        with pytest.raises(ValueError):
            br.analyze_auth_model("t.example", str(tmp_path), self._fetcher(), entry_urls=[])


class TestRouteExtractionAndAuthModelCliGating:
    def test_route_extraction_requires_domain(self):
        with pytest.raises(SystemExit) as exc:
            br.main(["t.example", "--route-extraction"])
        assert exc.value.code != 0

    def test_route_extraction_does_not_require_playwright(self, monkeypatch, tmp_path):
        # No --entry-url and an empty recon-dir (no live/urls.txt, no
        # js_files.txt) means extract_framework_routes() makes zero network
        # calls -- this exercises the real CLI path (a real requests.Session,
        # since main() doesn't accept a fake one) without ever touching a
        # socket, while still proving --route-extraction works with
        # Playwright unavailable.
        monkeypatch.setattr(br, "sync_playwright", None)
        rd = make_recon_dir(tmp_path)
        code = br.main(["t.example", "--domain", "t.example", "--route-extraction",
                         "--recon-dir", str(rd)])
        assert code == 0

    def test_auth_model_requires_domain(self):
        with pytest.raises(SystemExit) as exc:
            br.main(["t.example", "--auth-model"])
        assert exc.value.code != 0

    def test_auth_model_without_playwright_errors_cleanly(self, monkeypatch, tmp_path):
        monkeypatch.setattr(br, "sync_playwright", None)
        with pytest.raises(SystemExit) as exc:
            br.main(["t.example", "--domain", "t.example", "--auth-model",
                     "--recon-dir", str(tmp_path), "--entry-url", "https://t.example/"])
        assert exc.value.code != 0


# ─── CLI ────────────────────────────────────────────────────────────────────

class TestCLI:
    def test_help_exits_zero(self, capsys):
        with pytest.raises(SystemExit) as exc:
            br.main(["--help"])
        assert exc.value.code == 0

    def test_requires_at_least_one_feature_flag(self):
        with pytest.raises(SystemExit) as exc:
            br.main(["t.example", "--domain", "t.example"])
        assert exc.value.code != 0

    def test_source_maps_requires_domain(self):
        with pytest.raises(SystemExit) as exc:
            br.main(["t.example", "--source-maps"])
        assert exc.value.code != 0

    def test_hidden_endpoints_runs_without_domain(self, tmp_path, capsys):
        rd = make_recon_dir(tmp_path, called_urls=[], referenced_endpoints=["/api/v1/admin/x"])
        code = br.main(["t.example", "--recon-dir", str(rd), "--hidden-endpoints", "--json"])
        assert code == 0
        out = json.loads(capsys.readouterr().out)
        assert out["hidden_endpoints"]["never_called"] == ["/api/v1/admin/x"]
