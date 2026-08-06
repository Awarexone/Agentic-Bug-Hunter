"""Tests for tools/fingerprint.py — Phase 3 Target Intelligence.

Covers: golden-file fingerprints for 6 fixture stacks, graceful degradation
on an unrecognized stack, version-range CVE matching (including boundary
conditions), Phase 1 data taking priority over re-derivation, the
tech_stack -> memory_dir/targets/<target>.json -> director.load_tech_stack()
wiring, and tech_attack_matrix.json weights actually reaching
priority_score()'s technology_match component. No network access anywhere.
"""

import json

import pytest

from tools import fingerprint as fp
from tools import director
from memory.vuln_intelligence import priority_score


# ─── fixture helpers ────────────────────────────────────────────────────────


def _write_routes(recon_dir, framework, build_id=None, routes=None):
    d = recon_dir / "browser"
    d.mkdir(parents=True, exist_ok=True)
    (d / "routes.json").write_text(json.dumps({
        "target": "t.example",
        "framework_detected": framework,
        "build_id": build_id,
        "routes": routes or [],
        "lazy_chunk_imports": [],
        "heuristic_path_literal_count": 0,
    }))


def _write_auth_model(recon_dir, cookies=None):
    d = recon_dir / "browser"
    d.mkdir(parents=True, exist_ok=True)
    (d / "auth-model.json").write_text(json.dumps({
        "target": "t.example",
        "local_storage": [],
        "session_storage": [],
        "cookies": cookies or [],
        "role_permission_constants": [],
        "auth_lifecycle_endpoints": [],
        "candidate_privileged_client_routes": [],
    }))


def _write_api_calls(recon_dir, calls=None):
    d = recon_dir / "browser"
    d.mkdir(parents=True, exist_ok=True)
    (d / "api-calls.json").write_text(json.dumps({
        "target": "t.example",
        "pages_visited": 1,
        "requests_captured": len(calls or []),
        "calls": calls or [],
    }))


def _write_httpx(recon_dir, lines):
    d = recon_dir / "live"
    d.mkdir(parents=True, exist_ok=True)
    (d / "httpx_full.txt").write_text("\n".join(lines) + "\n")


def _cookie(name):
    return {"name": name, "domain": "t.example", "path": "/", "http_only": True,
            "secure": True, "same_site": "Lax", "looks_auth_related": True}


# ─── golden-file fixtures: 6 stacks ────────────────────────────────────────


class TestGoldenFixtures:
    def test_nextjs(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_routes(rd, "nextjs", build_id="abc123")
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "nextjs"
        assert result["confidence"] == 0.85
        assert result["spa_framework"] == "nextjs"
        assert result["router_type"] == "pages-router"
        assert "browser/routes.json" in result["sources"]

    def test_rails(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_httpx(rd, ["https://t.example [200] [Home] [Ruby on Rails,nginx]"])
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "rails"
        assert result["confidence"] == 0.6
        assert result["spa_framework"] is None

    def test_django(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_httpx(rd, ["https://t.example [200] [Home] [Django,gunicorn]"])
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "django"
        assert result["confidence"] == 0.6

    def test_laravel(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_httpx(rd, ["https://t.example [200] [Home] [Laravel,PHP]"])
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "laravel"
        assert result["confidence"] == 0.6

    def test_express(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_httpx(rd, ["https://t.example [200] [API] [Express,Node.js]"])
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "express"
        assert result["confidence"] == 0.6

    def test_wordpress(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_httpx(rd, ["https://t.example [200] [Blog] [WordPress,PHP]"])
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "wordpress"
        assert result["confidence"] == 0.6


# ─── unknown stack degrades gracefully ─────────────────────────────────────


class TestUnknownStack:
    def test_no_recon_data_at_all(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        rd.mkdir(parents=True)
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "unknown"
        assert result["version"] is None
        assert result["confidence"] == 0.0
        assert result["sources"] == []
        assert result["cves"] == []
        # no crash, well-formed dict either way
        assert result["target"] == "t.example"

    def test_unrecognized_stack_still_populates_independent_signals(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_auth_model(rd, cookies=[_cookie("some_random_cookie_name")])
        _write_api_calls(rd, calls=[{
            "method": "GET", "url": "https://t.example/api/widgets",
            "response_shape": {"id": "number", "name": "string"},
        }])
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "unknown"
        assert result["confidence"] == 0.0
        # framework detection failing does NOT blank out unrelated signals
        assert result["auth_model"] is not None
        assert result["auth_model"]["cookies"][0]["name"] == "some_random_cookie_name"
        assert "json" in result["api_style"]


# ─── version-range CVE matching, including boundary conditions ────────────


class TestVersionInRange:
    def test_wildcard_matches_anything_including_unknown_version(self):
        assert fp.version_in_range(None, "*") is True
        assert fp.version_in_range("9.9.9", "*") is True

    def test_unknown_version_fails_closed_on_concrete_range(self):
        assert fp.version_in_range(None, ">=1.0.0,<2.0.0") is False

    def test_lower_bound_inclusive_boundary(self):
        assert fp.version_in_range("11.1.4", ">=11.1.4,<13.5.9") is True

    def test_upper_bound_exclusive_boundary(self):
        assert fp.version_in_range("13.5.9", ">=11.1.4,<13.5.9") is False
        assert fp.version_in_range("13.5.8", ">=11.1.4,<13.5.9") is True

    def test_below_lower_bound(self):
        assert fp.version_in_range("11.1.3", ">=11.1.4,<13.5.9") is False

    def test_malformed_range_fails_closed(self):
        assert fp.version_in_range("1.0.0", "not-a-range") is False

    def test_match_cves_only_surfaces_entries_with_real_cve_id(self):
        matrix = {
            "nextjs": {"version_ranges": [
                {"range": "*", "vulns": [{"class": "ssrf", "weight": 50, "cve": None, "citation": "x"}]},
                {"range": ">=11.1.4,<13.5.9", "vulns": [
                    {"class": "auth-bypass", "weight": 90, "cve": "CVE-2025-29927", "citation": "y"}
                ]},
            ]}
        }
        hits = fp._match_cves("nextjs", "12.0.0", matrix)
        assert hits == [{"id": "CVE-2025-29927", "severity": "critical", "affected_versions": [">=11.1.4,<13.5.9"]}]

        # Version outside the CVE's range -> no hit, even though the "*" entry matches (but has no cve).
        assert fp._match_cves("nextjs", "14.0.0", matrix) == []


# ─── Phase 1 data wins over re-derivation ──────────────────────────────────


class TestPhase1Priority:
    def test_routes_json_wins_over_contradicting_httpx_signal(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_routes(rd, "nextjs", build_id="abc123")
        # httpx signal disagrees (points at Django) -- routes.json must still win.
        _write_httpx(rd, ["https://t.example [200] [Django Admin Login] [gunicorn]"])
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "nextjs"
        # both tiers fired and agree on nothing, but tier 2 always wins regardless
        assert "browser/routes.json" in result["sources"]
        assert "live/httpx_full.txt" in result["sources"]

    def test_corroboration_boosts_confidence(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_httpx(rd, ["https://t.example [200] [Home] [Laravel,PHP]"])
        _write_auth_model(rd, cookies=[_cookie("laravel_session")])
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "laravel"
        # tier 3 base (0.6) + 0.1 corroboration from tier 4 cookie match
        assert result["confidence"] == 0.7


# ─── infra / api_style / spa_framework — reuse, not reimplementation ──────


class TestInfraAndApiStyle:
    def test_cdn_waf_detected_from_httpx_tech_tags(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_httpx(rd, ["https://t.example [200] [Home] [cloudflare,nginx]"])
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["infra"]["cdn"] == "cloudflare"
        assert result["infra"]["waf"] == "cloudflare"

    def test_graphql_api_style_from_api_calls(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_api_calls(rd, calls=[{
            "method": "POST", "url": "https://t.example/graphql",
            "response_shape": {"data": {"user": "string"}},
        }])
        result = fp.build_fingerprint("t.example", str(rd))
        assert "graphql" in result["api_style"]
        assert "json" in result["api_style"]


# ─── tech_stack -> memory_dir/targets/<target>.json -> director wiring ────


class TestSyncTechStack:
    def test_sync_then_director_load_tech_stack_reads_it(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_routes(rd, "nextjs", build_id="abc123")
        _write_api_calls(rd, calls=[{
            "method": "POST", "url": "https://t.example/graphql",
            "response_shape": {"data": {}},
        }])
        result = fp.build_fingerprint("t.example", str(rd))

        mem_dir = tmp_path / "hunt-memory"
        fp.sync_tech_stack("t.example", str(mem_dir), result)

        stack = director.load_tech_stack("t.example", str(mem_dir))
        assert "nextjs" in stack
        assert "graphql" in stack

    def test_sync_preserves_existing_profile_fields(self, tmp_path):
        mem_dir = tmp_path / "hunt-memory"
        (mem_dir / "targets").mkdir(parents=True)
        (mem_dir / "targets" / "t.example.json").write_text(json.dumps({
            "target": "t.example", "first_hunted": "2026-01-01T00:00:00Z",
            "last_hunted": "2026-01-01T00:00:00Z", "schema_version": 1,
            "tech_stack": ["manual-tag"], "hunt_sessions": 3,
        }))
        result = {"framework": "nextjs", "spa_framework": "nextjs", "api_style": []}
        profile = fp.sync_tech_stack("t.example", str(mem_dir), result)
        assert profile["hunt_sessions"] == 3
        assert "manual-tag" in profile["tech_stack"]
        assert "nextjs" in profile["tech_stack"]


# ─── tech_attack_matrix.json weights reach priority_score() ───────────────


class TestMatrixReachesPriorityScore:
    def test_default_behavior_unchanged_without_matrix(self):
        result = priority_score("auth-bypass", ["nextjs"], "t.example",
                                 patterns=[], failed_patterns=[])
        assert result["components"]["technology_match"] == 20

    def test_matrix_weight_replaces_floor_for_matching_class(self):
        matrix = fp.load_tech_attack_matrix()
        result = priority_score("auth-bypass", ["nextjs"], "t.example",
                                 patterns=[], failed_patterns=[],
                                 tech_attack_matrix=matrix)
        assert result["components"]["technology_match"] == 90

    def test_matrix_no_matching_class_keeps_floor(self):
        matrix = fp.load_tech_attack_matrix()
        result = priority_score("sqli", ["nextjs"], "t.example",
                                 patterns=[], failed_patterns=[],
                                 tech_attack_matrix=matrix)
        assert result["components"]["technology_match"] == 20

    def test_real_affinity_data_still_wins_over_matrix(self):
        matrix = fp.load_tech_attack_matrix()
        patterns = [{"target": "other", "vuln_class": "auth-bypass",
                     "tech_stack": ["nextjs"], "technique": "x"}]
        result = priority_score("auth-bypass", ["nextjs"], "t.example",
                                 patterns=patterns, failed_patterns=[],
                                 tech_attack_matrix=matrix)
        # Real win/loss experience exists -> affinity confidence path used,
        # not the matrix floor-replacement branch at all.
        assert result["components"]["technology_match"] != 90
