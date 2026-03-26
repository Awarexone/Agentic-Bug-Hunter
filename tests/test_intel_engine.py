"""Tests for intel_engine.py — memory-aware intel prioritization."""

import json
import os
import pytest

from intel_engine import load_memory_context, prioritize_intel


@pytest.fixture
def memory_dir(tmp_path):
    """Create a mock hunt-memory directory with test data."""
    targets_dir = tmp_path / "targets"
    targets_dir.mkdir()

    # Target profile
    profile = {
        "target": "target.com",
        "tech_stack": ["nextjs", "graphql", "postgresql"],
        "tested_endpoints": ["/api/v1/users", "/api/v1/login"],
        "findings": [{"vuln_class": "idor", "severity": "high"}],
        "last_hunted": "2026-03-24",
        "hunt_sessions": 3,
    }
    (targets_dir / "target-com.json").write_text(json.dumps(profile))

    # Journal with tested CVE
    journal_entries = [
        {
            "ts": "2026-03-24T10:00:00Z",
            "target": "target.com",
            "action": "test",
            "vuln_class": "ssrf",
            "endpoint": "/api/v1/proxy",
            "result": "rejected",
            "tags": ["CVE-2026-1234"],
            "schema_version": 1,
        },
        {
            "ts": "2026-03-24T11:00:00Z",
            "target": "other.com",
            "action": "test",
            "vuln_class": "xss",
            "endpoint": "/search",
            "result": "confirmed",
            "tags": [],
            "schema_version": 1,
        },
    ]
    journal_path = tmp_path / "journal.jsonl"
    with open(journal_path, "w") as f:
        for entry in journal_entries:
            f.write(json.dumps(entry) + "\n")

    # Patterns
    patterns = [
        {
            "target": "alpha.com",
            "vuln_class": "idor",
            "technique": "numeric_id_swap_put",
            "tech_stack": ["nextjs", "express"],
            "payout": 800,
            "schema_version": 1,
        },
        {
            "target": "beta.com",
            "vuln_class": "ssrf",
            "technique": "dns_rebinding",
            "tech_stack": ["django", "celery"],
            "payout": 1500,
            "schema_version": 1,
        },
    ]
    patterns_path = tmp_path / "patterns.jsonl"
    with open(patterns_path, "w") as f:
        for p in patterns:
            f.write(json.dumps(p) + "\n")

    return tmp_path


class TestLoadMemoryContext:

    def test_loads_target_profile(self, memory_dir):
        ctx = load_memory_context(str(memory_dir), "target.com")
        assert ctx["tech_stack"] == ["nextjs", "graphql", "postgresql"]
        assert ctx["last_hunted"] == "2026-03-24"
        assert ctx["hunt_sessions"] == 3
        assert "/api/v1/users" in ctx["tested_endpoints"]

    def test_loads_tested_cves(self, memory_dir):
        ctx = load_memory_context(str(memory_dir), "target.com")
        assert "CVE-2026-1234" in ctx["tested_cves"]

    def test_loads_patterns(self, memory_dir):
        ctx = load_memory_context(str(memory_dir), "target.com")
        assert len(ctx["patterns"]) == 2

    def test_nonexistent_target(self, memory_dir):
        ctx = load_memory_context(str(memory_dir), "unknown.com")
        assert ctx["tested_endpoints"] == []
        assert ctx["tech_stack"] == []

    def test_nonexistent_directory(self):
        ctx = load_memory_context("/nonexistent/path", "target.com")
        assert ctx["tested_endpoints"] == []

    def test_empty_memory_dir(self):
        ctx = load_memory_context("", "target.com")
        assert ctx["tested_endpoints"] == []

    def test_corrupted_journal(self, memory_dir):
        journal_path = memory_dir / "journal.jsonl"
        with open(journal_path, "a") as f:
            f.write("not valid json\n")
        ctx = load_memory_context(str(memory_dir), "target.com")
        # Should still load the valid entries
        assert "CVE-2026-1234" in ctx["tested_cves"]


class TestPrioritizeIntel:

    def test_critical_untested(self):
        results = [
            {"id": "CVE-2026-9999", "severity": "CRITICAL", "summary": "RCE in Next.js"},
        ]
        memory = {"tested_cves": [], "tested_endpoints": [], "patterns": []}
        intel = prioritize_intel(results, memory)
        assert len(intel["critical"]) == 1
        assert intel["critical"][0]["note"] == "Untested critical vulnerability. Hunt candidate."

    def test_already_tested_cve(self):
        results = [
            {"id": "CVE-2026-1234", "severity": "CRITICAL", "summary": "Old vuln"},
        ]
        memory = {"tested_cves": ["CVE-2026-1234"], "tested_endpoints": [], "patterns": []}
        intel = prioritize_intel(results, memory)
        assert len(intel["critical"]) == 0
        assert len(intel["info"]) == 1
        assert intel["info"][0]["already_tested"] is True

    def test_high_severity(self):
        results = [
            {"id": "CVE-2026-5555", "severity": "HIGH", "summary": "Auth bypass"},
        ]
        memory = {"tested_cves": [], "tested_endpoints": [], "patterns": []}
        intel = prioritize_intel(results, memory)
        assert len(intel["high"]) == 1

    def test_medium_goes_to_info(self):
        results = [
            {"id": "CVE-2026-3333", "severity": "MEDIUM", "summary": "Info leak"},
        ]
        memory = {"tested_cves": [], "tested_endpoints": [], "patterns": []}
        intel = prioritize_intel(results, memory)
        assert len(intel["info"]) == 1

    def test_matching_patterns(self, memory_dir):
        results = []
        memory = load_memory_context(str(memory_dir), "target.com")
        intel = prioritize_intel(results, memory)
        # alpha.com pattern has nextjs overlap with target.com
        patterns = intel["memory_context"].get("matching_patterns", [])
        assert len(patterns) >= 1
        assert any(p["target"] == "alpha.com" for p in patterns)

    def test_memory_context_fields(self):
        results = []
        memory = {
            "tested_cves": ["CVE-1", "CVE-2"],
            "tested_endpoints": ["/a", "/b", "/c"],
            "patterns": [],
            "last_hunted": "2026-03-20",
            "hunt_sessions": 5,
            "tech_stack": ["react"],
        }
        intel = prioritize_intel(results, memory)
        mc = intel["memory_context"]
        assert mc["tested_endpoints_count"] == 3
        assert mc["tested_cves_count"] == 2
        assert mc["last_hunted"] == "2026-03-20"

    def test_total_count(self):
        results = [
            {"id": "1", "severity": "CRITICAL", "summary": "a"},
            {"id": "2", "severity": "HIGH", "summary": "b"},
            {"id": "3", "severity": "LOW", "summary": "c"},
        ]
        memory = {"tested_cves": [], "tested_endpoints": [], "patterns": []}
        intel = prioritize_intel(results, memory)
        assert intel["total"] == 3
