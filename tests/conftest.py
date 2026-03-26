"""Shared fixtures for hunt memory and scope checker tests."""

import json
import os
import sys
import pytest

# Add tools/ to path so tests can import scope_checker, intel_engine, etc.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from memory.schemas import CURRENT_SCHEMA_VERSION


@pytest.fixture
def tmp_hunt_dir(tmp_path):
    """Create a temporary hunt-memory directory structure."""
    hunt_dir = tmp_path / "hunt-memory"
    hunt_dir.mkdir()
    (hunt_dir / "targets").mkdir()
    return hunt_dir


@pytest.fixture
def journal_path(tmp_hunt_dir):
    """Path to a temporary journal.jsonl file."""
    return tmp_hunt_dir / "journal.jsonl"


@pytest.fixture
def patterns_path(tmp_hunt_dir):
    """Path to a temporary patterns.jsonl file."""
    return tmp_hunt_dir / "patterns.jsonl"


@pytest.fixture
def sample_journal_entry():
    """A valid journal entry dict."""
    return {
        "ts": "2026-03-24T21:00:00Z",
        "target": "target.com",
        "action": "hunt",
        "vuln_class": "idor",
        "endpoint": "/api/v2/users/{id}/orders",
        "result": "confirmed",
        "severity": "high",
        "payout": 1500,
        "technique": "numeric_id_swap_with_put_method",
        "notes": "v1 had auth, v2 missing ownership check on PUT",
        "tags": ["api_version_diff", "method_swap"],
        "schema_version": CURRENT_SCHEMA_VERSION,
    }


@pytest.fixture
def sample_pattern_entry():
    """A valid pattern entry dict."""
    return {
        "ts": "2026-03-24T21:00:00Z",
        "target": "target.com",
        "vuln_class": "idor",
        "technique": "numeric_id_swap_with_put_method",
        "tech_stack": ["express", "postgresql"],
        "endpoint": "/api/v2/users/{id}/orders",
        "payout": 1500,
        "schema_version": CURRENT_SCHEMA_VERSION,
    }


@pytest.fixture
def sample_target_profile():
    """A valid target profile dict."""
    return {
        "target": "target.com",
        "first_hunted": "2026-03-01T10:00:00Z",
        "last_hunted": "2026-03-24T21:00:00Z",
        "tech_stack": ["next.js", "graphql", "postgresql", "aws"],
        "scope_snapshot": {
            "in_scope": ["*.target.com", "api.target.com"],
            "out_of_scope": ["blog.target.com"],
            "excluded_classes": ["dos"],
            "fetched_at": "2026-03-24T20:00:00Z",
        },
        "tested_endpoints": [],
        "untested_endpoints": ["/api/v2/users/{id}/export"],
        "findings": [],
        "hunt_sessions": 3,
        "total_time_minutes": 120,
        "schema_version": CURRENT_SCHEMA_VERSION,
    }


@pytest.fixture
def scope_domains():
    """Standard scope allowlist for testing."""
    return ["*.target.com", "api.target.com", "target.com"]


@pytest.fixture
def scope_excluded():
    """Standard scope exclusion list for testing."""
    return ["blog.target.com", "status.target.com"]
