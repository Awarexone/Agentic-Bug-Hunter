"""Tests for tools/mindmap.py — Mermaid generation and checklist building."""

import os
import pytest

from tools.mindmap import (
    build_mermaid,
    build_checklist,
    WEBSITE_CHECKS,
    OPENSRC_CHECKS,
    API_CHECKS,
    AI_CHECKS,
    MOBILE_CHECKS,
    TECH_CHECKS,
)


class TestBuildMermaid:
    def test_website_type(self):
        result = build_mermaid("target.com", "website", [])
        assert "```mermaid" in result
        assert "mindmap" in result
        assert "target.com" in result
        assert "WEBSITE" in result
        assert "IDOR" in result
        assert "XSS" in result

    def test_opensrc_type(self):
        result = build_mermaid("repo.git", "opensrc", [])
        assert "OPENSRC" in result
        assert "Timing side-channel" in result

    def test_api_type(self):
        result = build_mermaid("api.example.com", "api", [])
        assert "API" in result
        assert "IDOR" in result
        assert "SSRF" in result

    def test_mobile_type(self):
        result = build_mermaid("app.mobile", "mobile", [])
        assert "MOBILE" in result
        assert "WebView" in result

    def test_tech_additions(self):
        result = build_mermaid("t.com", "website", ["graphql", "jwt"])
        assert "GRAPHQL" in result
        assert "JWT" in result

    def test_unknown_tech_ignored(self):
        result = build_mermaid("t.com", "website", ["unknown_tech_xyz"])
        assert "UNKNOWN_TECH_XYZ" not in result

    def test_ends_with_code_fence(self):
        result = build_mermaid("t.com", "api", [])
        assert result.strip().endswith("```")

    def test_empty_techs(self):
        result = build_mermaid("t.com", "website", [])
        # Should work without tech additions
        assert "```mermaid" in result


class TestBuildChecklist:
    def test_website_includes_base_checks(self):
        result = build_checklist("website", [])
        assert "IDOR" in result
        assert "Priority" in result
        assert "Check" in result

    def test_api_type(self):
        result = build_checklist("api", [])
        assert "Auth bypass" in result

    def test_opensrc_type(self):
        result = build_checklist("opensrc", [])
        assert "Timing" in result

    def test_mobile_type(self):
        result = build_checklist("mobile", [])
        assert "WebView" in result

    def test_always_includes_ai_checks(self):
        result = build_checklist("website", [])
        assert "AI-assisted" in result

    def test_tech_specific_additions(self):
        result = build_checklist("website", ["graphql"])
        assert "GraphQL" in result
        assert "Introspection" in result

    def test_sorted_by_priority(self):
        result = build_checklist("website", [])
        lines = result.split("\n")
        table_lines = [l for l in lines if l.startswith("|") and "HIGH" in l or "MED" in l or "LOW" in l]
        # HIGH should appear before LOW
        high_indices = [i for i, l in enumerate(table_lines) if "HIGH" in l]
        low_indices = [i for i, l in enumerate(table_lines) if "LOW" in l]
        if high_indices and low_indices:
            assert max(high_indices) < min(low_indices)

    def test_unknown_type_defaults_to_website(self):
        result = build_checklist("unknown_type", [])
        # Should fall back to WEBSITE_CHECKS
        assert "IDOR" in result

    def test_multiple_techs(self):
        result = build_checklist("api", ["jwt", "oauth", "aws"])
        assert "alg:none" in result
        assert "redirect_uri" in result
        assert "SSRF to IMDSv1" in result


class TestChecklistData:
    def test_website_checks_format(self):
        for impact, desc, ref in WEBSITE_CHECKS:
            assert impact in ("HIGH", "MED", "LOW")
            assert len(desc) > 0
            assert len(ref) > 0

    def test_opensrc_checks_format(self):
        for impact, desc, ref in OPENSRC_CHECKS:
            assert impact in ("HIGH", "MED", "LOW")

    def test_api_checks_format(self):
        for impact, desc, ref in API_CHECKS:
            assert impact in ("HIGH", "MED", "LOW")

    def test_mobile_checks_format(self):
        for impact, desc, ref in MOBILE_CHECKS:
            assert impact in ("HIGH", "MED", "LOW")

    def test_ai_checks_format(self):
        for impact, desc, ref in AI_CHECKS:
            assert impact in ("HIGH", "MED", "LOW")

    def test_tech_checks_all_valid(self):
        for tech, checks in TECH_CHECKS.items():
            assert isinstance(tech, str)
            for impact, desc, ref in checks:
                assert impact in ("HIGH", "MED", "LOW")
                assert len(desc) > 0
