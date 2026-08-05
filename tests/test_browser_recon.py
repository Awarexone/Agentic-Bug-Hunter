"""Tests for tools/browser_recon.py — source-map recovery (#2) and hidden-
endpoint discovery (#5) of the browser intelligence layer.

Everything here runs against local fixtures: a FakeSession stands in for
`requests.Session` (no sockets touched, ever) and recon directories are
built under tmp_path in the exact layout tools/recon_adapter.py /
tools/lead_board.py already expect. No test depends on Playwright, network
access, or host tooling.

Framework route extraction (#3), auth-model analysis (#4), and runtime API
capture (#1) are not implemented yet — there are no tests for them here by
design; see browser_recon.py's module docstring for what's deferred.
"""

import json
from pathlib import Path

import pytest

import browser_recon as br  # tools/ is on sys.path via tests/conftest.py
from tools.scope_checker import ScopeChecker


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
