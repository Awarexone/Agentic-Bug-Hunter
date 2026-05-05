"""Tests for recon_to_json.py — parser, CDN detection, source attribution, builder."""

import json
import sys
from pathlib import Path

import pytest

# tools/ is added to path by conftest.py; we still import the script's top-level functions
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from recon_to_json import (  # noqa: E402
    build_inventory,
    detect_cdn,
    discovery_methods_for,
    load_sources,
    parse_httpx_line,
)
from memory.schemas import SchemaError, validate_recon_inventory  # noqa: E402


# ─── parse_httpx_line ─────────────────────────────────────────────────────

class TestParseHttpxLine:
    def test_full_line(self):
        line = "https://api.example.com [200] [API Gateway] [nginx,Express] [1234]"
        result = parse_httpx_line(line)
        assert result["hostname"] == "api.example.com"
        assert result["status"] == 200
        assert result["title"] == "API Gateway"
        assert result["tech"] == ["nginx", "Express"]

    def test_empty_title(self):
        line = "https://x.example.com [403] [] [nginx] [180]"
        result = parse_httpx_line(line)
        assert result["title"] == ""
        assert result["tech"] == ["nginx"]
        assert result["status"] == 403

    def test_empty_tech(self):
        line = "https://x.example.com [200] [Title] [] [99]"
        result = parse_httpx_line(line)
        assert result["tech"] == []

    def test_status_only(self):
        line = "https://x.example.com [200]"
        result = parse_httpx_line(line)
        assert result["status"] == 200
        assert result["title"] == ""
        assert result["tech"] == []

    def test_url_with_port(self):
        line = "https://api.example.com:8443 [200] [API] [nginx] [100]"
        result = parse_httpx_line(line)
        assert result["hostname"] == "api.example.com"

    def test_url_with_path(self):
        line = "https://api.example.com/v1/health [200] [Healthy] [] [10]"
        result = parse_httpx_line(line)
        assert result["hostname"] == "api.example.com"

    def test_blank_line_returns_none(self):
        assert parse_httpx_line("") is None
        assert parse_httpx_line("   ") is None

    def test_whitespace_strips_correctly(self):
        line = "  https://x.example.com [200] [T] [t] [1]  "
        assert parse_httpx_line(line)["hostname"] == "x.example.com"


# ─── detect_cdn ──────────────────────────────────────────────────────────

class TestDetectCdn:
    def test_cloudfront(self):
        assert detect_cdn("54.192.248.67") == "CloudFront"

    def test_cloudflare(self):
        assert detect_cdn("104.16.1.1") == "Cloudflare"
        assert detect_cdn("172.64.1.1") == "Cloudflare"

    def test_fastly(self):
        assert detect_cdn("151.101.1.1") == "Fastly"

    def test_akamai(self):
        assert detect_cdn("23.32.1.1") == "Akamai"

    def test_unknown_ip_returns_none(self):
        assert detect_cdn("8.8.8.8") is None

    def test_none_input(self):
        assert detect_cdn(None) is None
        assert detect_cdn("") is None


# ─── load_sources & discovery_methods_for ────────────────────────────────

@pytest.fixture
def fake_recon_dir(tmp_path):
    """Build a minimal fake recon dir matching recon_engine.sh layout."""
    recon = tmp_path / "recon" / "example.com"
    (recon / "subdomains").mkdir(parents=True)
    (recon / "live").mkdir()

    (recon / "subdomains" / "subfinder.txt").write_text(
        "api.example.com\napp.example.com\nwww.example.com\n"
    )
    (recon / "subdomains" / "crtsh.txt").write_text(
        "api.example.com\nmail.example.com\n"
    )
    (recon / "subdomains" / "amass.txt").write_text("app.example.com\n")
    (recon / "subdomains" / "wayback_subs.txt").write_text("www.example.com\n")
    (recon / "subdomains" / "all.txt").write_text(
        "api.example.com\napp.example.com\nmail.example.com\nwww.example.com\n"
    )
    (recon / "live" / "httpx_full.txt").write_text(
        "https://www.example.com [200] [Welcome] [nginx] [100]\n"
        "https://api.example.com [403] [] [nginx] [50]\n"
    )
    return recon


class TestLoadSources:
    def test_loads_all_present(self, fake_recon_dir):
        sources = load_sources(fake_recon_dir)
        assert "api.example.com" in sources["subfinder"]
        assert "api.example.com" in sources["crtsh"]
        assert "app.example.com" in sources["amass"]
        assert "www.example.com" in sources["wayback"]

    def test_missing_source_returns_empty_set(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        sources = load_sources(empty)
        for source_name in ("subfinder", "amass", "crtsh", "wayback"):
            assert sources[source_name] == set()


class TestDiscoveryMethodsFor:
    def test_attributes_to_multiple_sources(self, fake_recon_dir):
        sources = load_sources(fake_recon_dir)
        methods = discovery_methods_for("api.example.com", sources)
        assert methods == ["crtsh", "subfinder"]  # alphabetical

    def test_attributes_to_single_source(self, fake_recon_dir):
        sources = load_sources(fake_recon_dir)
        assert discovery_methods_for("mail.example.com", sources) == ["crtsh"]

    def test_unknown_host_returns_empty(self, fake_recon_dir):
        sources = load_sources(fake_recon_dir)
        assert discovery_methods_for("nope.example.com", sources) == []

    def test_case_insensitive(self, fake_recon_dir):
        sources = load_sources(fake_recon_dir)
        # All sources stored as lowercase; lookup also lowercases
        assert "subfinder" in discovery_methods_for("API.EXAMPLE.COM", sources)


# ─── build_inventory ─────────────────────────────────────────────────────

class TestBuildInventory:
    def test_produces_valid_schema(self, fake_recon_dir):
        inv = build_inventory(fake_recon_dir, "example.com", do_dns=False)
        validate_recon_inventory(inv)  # should not raise

    def test_summary_counts(self, fake_recon_dir):
        inv = build_inventory(fake_recon_dir, "example.com", do_dns=False)
        assert inv["summary"]["total_discovered"] == 4
        assert inv["summary"]["live_resolved"] == 2
        assert set(inv["summary"]["sources"]) == {"subfinder", "amass", "crtsh", "wayback"}

    def test_live_subdomains_have_required_fields(self, fake_recon_dir):
        inv = build_inventory(fake_recon_dir, "example.com", do_dns=False)
        for asset in inv["live_subdomains"]:
            assert "hostname" in asset
            assert "status" in asset
            assert isinstance(asset["status"], int)

    def test_discovery_method_attached(self, fake_recon_dir):
        inv = build_inventory(fake_recon_dir, "example.com", do_dns=False)
        api = next(a for a in inv["live_subdomains"] if a["hostname"] == "api.example.com")
        assert api["discovery_method"] == ["crtsh", "subfinder"]

    def test_empty_dir_produces_valid_empty_inventory(self, tmp_path):
        empty = tmp_path / "empty_target"
        empty.mkdir()
        inv = build_inventory(empty, "empty_target", do_dns=False)
        validate_recon_inventory(inv)
        assert inv["summary"]["total_discovered"] == 0
        assert inv["summary"]["live_resolved"] == 0
        assert inv["live_subdomains"] == []
        assert inv["all_discovered"] == []

    def test_no_dns_skips_ip_and_cname(self, fake_recon_dir):
        inv = build_inventory(fake_recon_dir, "example.com", do_dns=False)
        for asset in inv["live_subdomains"]:
            assert "ip" not in asset
            assert "cname" not in asset
            assert "cdn" not in asset

    def test_target_passed_through(self, fake_recon_dir):
        inv = build_inventory(fake_recon_dir, "myorg.io", do_dns=False)
        assert inv["target"] == "myorg.io"

    def test_sources_only_lists_non_empty(self, tmp_path):
        recon = tmp_path / "partial"
        (recon / "subdomains").mkdir(parents=True)
        (recon / "subdomains" / "subfinder.txt").write_text("a.example.com\n")
        # crtsh.txt absent — should not appear in sources
        inv = build_inventory(recon, "example.com", do_dns=False)
        assert inv["summary"]["sources"] == ["subfinder"]


# ─── Schema validation for recon inventory ───────────────────────────────

class TestReconInventorySchema:
    def _valid_inventory(self):
        return {
            "target": "example.com",
            "scan_date": "2026-05-05T12:00:00Z",
            "summary": {"total_discovered": 1, "live_resolved": 1, "sources": ["subfinder"]},
            "live_subdomains": [
                {"hostname": "api.example.com", "status": 200, "tech": ["nginx"]}
            ],
            "all_discovered": ["api.example.com"],
            "schema_version": 1,
        }

    def test_minimal_valid(self):
        validate_recon_inventory(self._valid_inventory())

    def test_missing_target_fails(self):
        inv = self._valid_inventory()
        del inv["target"]
        with pytest.raises(SchemaError, match="missing required"):
            validate_recon_inventory(inv)

    def test_unknown_field_fails(self):
        inv = self._valid_inventory()
        inv["bogus_field"] = "x"
        with pytest.raises(SchemaError, match="unknown fields"):
            validate_recon_inventory(inv)

    def test_invalid_status_type_fails(self):
        inv = self._valid_inventory()
        inv["live_subdomains"][0]["status"] = "200"  # string instead of int
        with pytest.raises(SchemaError, match="status"):
            validate_recon_inventory(inv)

    def test_tech_must_be_list_of_strings(self):
        inv = self._valid_inventory()
        inv["live_subdomains"][0]["tech"] = "nginx"  # string instead of list
        with pytest.raises(SchemaError, match="tech"):
            validate_recon_inventory(inv)

    def test_negative_total_discovered_fails(self):
        inv = self._valid_inventory()
        inv["summary"]["total_discovered"] = -1
        with pytest.raises(SchemaError, match="total_discovered"):
            validate_recon_inventory(inv)
