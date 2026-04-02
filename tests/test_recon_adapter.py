"""Tests for ReconAdapter — normalizes recon output across formats."""

import json
import pytest

from tools.recon_adapter import ReconAdapter


@pytest.fixture
def recon_dir(tmp_path):
    """Create a recon directory with the nested format from recon_engine.sh."""
    d = tmp_path / "recon" / "target.com"
    for sub in ("subdomains", "live", "ports", "urls", "js", "dirs", "params", "exposure"):
        (d / sub).mkdir(parents=True)
    return d


@pytest.fixture
def populated_recon(recon_dir):
    """Recon dir with sample data matching recon_engine.sh output."""
    (recon_dir / "subdomains" / "all.txt").write_text(
        "api.target.com\nwww.target.com\nstaging.target.com\n"
    )
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [application/json]\n"
        "https://www.target.com [200] [text/html]\n"
    )
    (recon_dir / "live" / "urls.txt").write_text(
        "https://api.target.com\nhttps://www.target.com\n"
    )
    (recon_dir / "urls" / "all.txt").write_text(
        "https://api.target.com/v1/users\n"
        "https://api.target.com/graphql\n"
        "https://www.target.com/login\n"
        "https://api.target.com/v1/users?id=1&role=admin\n"
    )
    (recon_dir / "urls" / "with_params.txt").write_text(
        "https://api.target.com/v1/users?id=1&role=admin\n"
    )
    (recon_dir / "urls" / "api_endpoints.txt").write_text(
        "https://api.target.com/v1/users\nhttps://api.target.com/v1/orders\n"
    )
    (recon_dir / "urls" / "js_files.txt").write_text(
        "https://www.target.com/static/app.js\nhttps://www.target.com/static/vendor.js\n"
    )
    (recon_dir / "urls" / "sensitive_paths.txt").write_text(
        "https://www.target.com/.env\nhttps://api.target.com/.git/config\n"
    )
    (recon_dir / "js" / "potential_secrets.txt").write_text(
        "api.target.com/static/app.js: AWS_KEY=AKIA...\n"
    )
    (recon_dir / "params" / "interesting_params.txt").write_text(
        "redirect_url\ncallback\nnext\n"
    )
    (recon_dir / "exposure" / "config_files.txt").write_text(
        "https://www.target.com/.env [200]\n"
    )
    return recon_dir


# ── Reading data ──────────────────────────────────────────────────────────


class TestReconAdapterRead:
    """Reading recon data from nested directory format."""

    def test_get_subdomains(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        subs = adapter.get_subdomains()
        assert "api.target.com" in subs
        assert "www.target.com" in subs
        assert len(subs) == 3

    def test_get_live_hosts(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        hosts = adapter.get_live_hosts()
        assert "https://api.target.com" in hosts
        assert "https://www.target.com" in hosts

    def test_get_urls(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        urls = adapter.get_urls()
        assert len(urls) == 4
        assert "https://api.target.com/graphql" in urls

    def test_get_parameterized_urls(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        urls = adapter.get_parameterized_urls()
        assert len(urls) == 1
        assert "id=1" in urls[0]

    def test_get_js_files(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        js = adapter.get_js_files()
        assert len(js) == 2
        assert any("app.js" in f for f in js)

    def test_get_api_endpoints(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        apis = adapter.get_api_endpoints()
        assert len(apis) == 2

    def test_get_sensitive_paths(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        paths = adapter.get_sensitive_paths()
        assert len(paths) == 2
        assert any(".env" in p for p in paths)

    def test_get_js_secrets(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        secrets = adapter.get_js_secrets()
        assert len(secrets) == 1
        assert "AWS_KEY" in secrets[0]

    def test_get_interesting_params(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        params = adapter.get_interesting_params()
        assert "redirect_url" in params
        assert "callback" in params

    def test_get_config_exposure(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        exposed = adapter.get_config_exposure()
        assert len(exposed) == 1
        assert ".env" in exposed[0]


# ── GraphQL extraction ───────────────────────────────────────────────────


class TestReconAdapterGraphQL:
    """Extracting GraphQL endpoints from URL lists."""

    def test_get_graphql_endpoints_from_urls(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        gql = adapter.get_graphql_endpoints()
        assert len(gql) == 1
        assert "graphql" in gql[0]

    def test_get_graphql_from_dedicated_file(self, populated_recon):
        """If urls/graphql.txt exists, prefer it."""
        (populated_recon / "urls" / "graphql.txt").write_text(
            "https://api.target.com/graphql\nhttps://api.target.com/gql\n"
        )
        adapter = ReconAdapter(populated_recon)
        gql = adapter.get_graphql_endpoints()
        assert len(gql) == 2

    def test_get_graphql_empty_when_none(self, recon_dir):
        (recon_dir / "urls" / "all.txt").write_text("https://target.com/login\n")
        adapter = ReconAdapter(recon_dir)
        gql = adapter.get_graphql_endpoints()
        assert gql == []


# ── Fallback path resolution ─────────────────────────────────────────────


class TestReconAdapterFallbacks:
    """Fallback paths for agent.py compatibility."""

    def test_live_hosts_fallback_to_root_httpx(self, recon_dir):
        """If live/httpx_full.txt missing but httpx_full.txt at root, use that."""
        (recon_dir / "httpx_full.txt").write_text(
            "https://api.target.com [200] [json]\n"
        )
        adapter = ReconAdapter(recon_dir)
        hosts = adapter.get_live_hosts()
        assert len(hosts) == 1

    def test_returns_empty_for_missing_files(self, recon_dir):
        """Missing files return empty lists, not errors."""
        adapter = ReconAdapter(recon_dir)
        assert adapter.get_subdomains() == []
        assert adapter.get_live_hosts() == []
        assert adapter.get_urls() == []
        assert adapter.get_parameterized_urls() == []

    def test_resolved_subdomains_fallback(self, recon_dir):
        """get_resolved_subdomains tries resolved.txt then falls back to all.txt."""
        (recon_dir / "subdomains" / "all.txt").write_text("a.target.com\nb.target.com\n")
        adapter = ReconAdapter(recon_dir)
        resolved = adapter.get_resolved_subdomains()
        assert len(resolved) == 2

    def test_resolved_subdomains_prefers_resolved_file(self, recon_dir):
        (recon_dir / "subdomains" / "resolved.txt").write_text("a.target.com\n")
        (recon_dir / "subdomains" / "all.txt").write_text("a.target.com\nb.target.com\n")
        adapter = ReconAdapter(recon_dir)
        resolved = adapter.get_resolved_subdomains()
        assert len(resolved) == 1


# ── Normalize (create missing stubs) ─────────────────────────────────────


class TestReconAdapterNormalize:
    """normalize() ensures all expected files exist for brain.py."""

    def test_normalize_creates_priority_dir(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        adapter.normalize()
        assert (populated_recon / "priority").is_dir()

    def test_normalize_creates_graphql_file(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        adapter.normalize()
        gql_file = populated_recon / "urls" / "graphql.txt"
        assert gql_file.exists()
        content = gql_file.read_text()
        assert "graphql" in content

    def test_normalize_creates_resolved_txt(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        adapter.normalize()
        resolved = populated_recon / "subdomains" / "resolved.txt"
        assert resolved.exists()

    def test_normalize_creates_prioritized_hosts_json(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        adapter.normalize()
        pj = populated_recon / "priority" / "prioritized_hosts.json"
        assert pj.exists()
        data = json.loads(pj.read_text())
        assert isinstance(data, dict)
        assert "hosts" in data

    def test_normalize_creates_attack_surface_md(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        adapter.normalize()
        md = populated_recon / "priority" / "attack_surface.md"
        assert md.exists()
        assert "target.com" in md.read_text().lower() or "Attack Surface" in md.read_text()

    def test_normalize_does_not_overwrite_existing(self, populated_recon):
        """Existing files are preserved, not overwritten."""
        (populated_recon / "urls" / "graphql.txt").write_text("https://custom.com/gql\n")
        adapter = ReconAdapter(populated_recon)
        adapter.normalize()
        content = (populated_recon / "urls" / "graphql.txt").read_text()
        assert "custom.com" in content

    def test_normalize_creates_api_specs_dir(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        adapter.normalize()
        assert (populated_recon / "api_specs").is_dir()

    def test_normalize_idempotent(self, populated_recon):
        """Running normalize twice doesn't break anything."""
        adapter = ReconAdapter(populated_recon)
        adapter.normalize()
        adapter.normalize()
        assert (populated_recon / "priority" / "prioritized_hosts.json").exists()


# ── Summary ──────────────────────────────────────────────────────────────


class TestReconAdapterSummary:
    """summary() returns a quick overview dict."""

    def test_summary_counts(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        s = adapter.summary()
        assert s["subdomains"] == 3
        assert s["live_hosts"] == 2
        assert s["urls"] == 4
        assert s["parameterized_urls"] == 1
        assert s["js_files"] == 2
        assert s["api_endpoints"] == 2

    def test_summary_empty_recon(self, recon_dir):
        adapter = ReconAdapter(recon_dir)
        s = adapter.summary()
        assert s["subdomains"] == 0
        assert s["live_hosts"] == 0


# ── Edge cases ───────────────────────────────────────────────────────────


class TestReconAdapterEdgeCases:
    """Edge cases and error handling."""

    def test_nonexistent_recon_dir(self, tmp_path):
        adapter = ReconAdapter(tmp_path / "nonexistent")
        assert adapter.get_subdomains() == []
        assert adapter.get_urls() == []

    def test_empty_files(self, recon_dir):
        (recon_dir / "subdomains" / "all.txt").write_text("")
        adapter = ReconAdapter(recon_dir)
        assert adapter.get_subdomains() == []

    def test_files_with_blank_lines(self, recon_dir):
        (recon_dir / "subdomains" / "all.txt").write_text("\n\na.target.com\n\n\nb.target.com\n\n")
        adapter = ReconAdapter(recon_dir)
        subs = adapter.get_subdomains()
        assert len(subs) == 2

    def test_duplicate_entries_deduplicated(self, recon_dir):
        (recon_dir / "subdomains" / "all.txt").write_text("a.target.com\na.target.com\nb.target.com\n")
        adapter = ReconAdapter(recon_dir)
        subs = adapter.get_subdomains()
        assert len(subs) == 2
