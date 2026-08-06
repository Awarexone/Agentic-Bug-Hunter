"""Tests for tools/target_selector.py — parsing, scoring, domain extraction."""

import json
import os
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

import pytest

from tools.target_selector import (
    extract_scope_domains,
    get_curated_programs,
    parse_bounty_targets_program,
    parse_h1_program,
    save_targets,
    score_program,
    select_targets,
)


class TestParseH1Program:
    def test_basic_fields(self):
        prog = {
            "name": "Acme Corp",
            "handle": "acme",
            "triage_active": True,
            "minimum_bounty_table_value": 100,
            "maximum_bounty_table_value": 10000,
            "response_efficiency_percentage": 95,
            "scopes": [{"asset_identifier": "*.acme.com"}],
            "started_accepting_at": "2025-01-01T00:00:00Z",
        }
        result = parse_h1_program(prog)
        assert result["name"] == "Acme Corp"
        assert result["handle"] == "acme"
        assert result["url"] == "https://hackerone.com/acme"
        assert result["managed"] is True
        assert result["bounty_min"] == 100
        assert result["bounty_max"] == 10000
        assert result["response_efficiency"] == 95
        assert result["has_wildcard"] is True
        assert result["source"] == "hackerone_directory"

    def test_no_wildcard(self):
        prog = {
            "name": "Test",
            "handle": "test",
            "scopes": [{"asset_identifier": "app.test.com"}],
        }
        result = parse_h1_program(prog)
        assert result["has_wildcard"] is False

    def test_missing_fields_defaults(self):
        result = parse_h1_program({})
        assert result["name"] == "Unknown"
        assert result["handle"] == ""
        assert result["managed"] is False
        assert result["bounty_min"] == 0
        assert result["bounty_max"] == 0
        assert result["assets"] == []

    def test_scopes_as_strings(self):
        prog = {"scopes": ["*.example.com", "api.example.com"]}
        result = parse_h1_program(prog)
        assert result["has_wildcard"] is True


class TestParseBountyTargetsProgram:
    def test_parses_in_scope_domains(self):
        prog = {
            "name": "BugCo",
            "handle": "bugco",
            "managed": True,
            "targets": {
                "in_scope": [
                    {"asset_identifier": "*.bugco.io", "asset_type": "WILDCARD", "eligible_for_bounty": True},
                    {"asset_identifier": "api.bugco.io", "asset_type": "URL", "eligible_for_bounty": True},
                ]
            },
        }
        result = parse_bounty_targets_program(prog)
        assert result["name"] == "BugCo"
        assert result["managed"] is True
        assert result["has_wildcard"] is True
        assert len(result["assets"]) == 2
        assert result["source"] == "bounty_targets_data"

    def test_no_wildcard_domains(self):
        prog = {
            "targets": {
                "in_scope": [
                    {"asset_identifier": "app.example.com", "asset_type": "URL"},
                ]
            }
        }
        result = parse_bounty_targets_program(prog)
        assert result["has_wildcard"] is False

    def test_empty_targets(self):
        result = parse_bounty_targets_program({})
        assert result["assets"] == []
        assert result["has_wildcard"] is False

    def test_dot_in_identifier_non_typed(self):
        """Identifiers with '.' are included even without standard asset_type."""
        prog = {
            "targets": {
                "in_scope": [
                    {"asset_identifier": "custom.domain.org", "asset_type": "OTHER"},
                ]
            }
        }
        result = parse_bounty_targets_program(prog)
        assert len(result["assets"]) == 1


class TestGetCuratedPrograms:
    def test_returns_nonempty_list(self):
        programs = get_curated_programs()
        assert len(programs) > 0

    def test_each_program_has_required_keys(self):
        programs = get_curated_programs()
        for p in programs:
            assert "name" in p
            assert "handle" in p
            assert "url" in p
            assert "source" in p
            assert p["source"] == "curated_fallback"


class TestScoreProgram:
    def test_wildcard_bonus(self):
        base = {"has_wildcard": False, "assets": [], "bounty_max": 0, "response_efficiency": 0}
        wild = {**base, "has_wildcard": True}
        assert score_program(wild) > score_program(base)
        assert score_program(wild) - score_program(base) == 30

    def test_asset_count_bonus(self):
        few = {"has_wildcard": False, "assets": [1, 2], "bounty_max": 0, "response_efficiency": 0}
        many = {"has_wildcard": False, "assets": list(range(15)), "bounty_max": 0, "response_efficiency": 0}
        assert score_program(many) > score_program(few)

    def test_asset_bonus_capped_at_20(self):
        huge = {"has_wildcard": False, "assets": list(range(100)), "bounty_max": 0, "response_efficiency": 0}
        # 100 * 2 = 200, but capped at 20
        score = score_program(huge)
        # Without other bonuses, score is just 20 (capped asset bonus)
        assert score == 20

    def test_high_bounty_bonus(self):
        prog = {"has_wildcard": False, "assets": [], "bounty_max": 15000, "response_efficiency": 0}
        assert score_program(prog) == 25

    def test_medium_bounty_bonus(self):
        prog = {"has_wildcard": False, "assets": [], "bounty_max": 5000, "response_efficiency": 0}
        assert score_program(prog) == 20

    def test_low_bounty_bonus(self):
        prog = {"has_wildcard": False, "assets": [], "bounty_max": 1000, "response_efficiency": 0}
        assert score_program(prog) == 15

    def test_tiny_bounty_bonus(self):
        prog = {"has_wildcard": False, "assets": [], "bounty_max": 50, "response_efficiency": 0}
        assert score_program(prog) == 10

    def test_response_efficiency_high(self):
        prog = {"has_wildcard": False, "assets": [], "bounty_max": 0, "response_efficiency": 95}
        assert score_program(prog) == 15

    def test_response_efficiency_medium(self):
        prog = {"has_wildcard": False, "assets": [], "bounty_max": 0, "response_efficiency": 75}
        assert score_program(prog) == 10

    def test_response_efficiency_low(self):
        prog = {"has_wildcard": False, "assets": [], "bounty_max": 0, "response_efficiency": 55}
        assert score_program(prog) == 5

    def test_new_program_bonus(self):
        recent = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        prog = {"has_wildcard": False, "assets": [], "bounty_max": 0, "response_efficiency": 0,
                "started_accepting_at": recent}
        assert score_program(prog) >= 20

    def test_medium_age_bonus(self):
        medium = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        prog = {"has_wildcard": False, "assets": [], "bounty_max": 0, "response_efficiency": 0,
                "started_accepting_at": medium}
        assert score_program(prog) == 10

    def test_old_program_no_age_bonus(self):
        old = (datetime.now(timezone.utc) - timedelta(days=500)).isoformat()
        prog = {"has_wildcard": False, "assets": [], "bounty_max": 0, "response_efficiency": 0,
                "started_accepting_at": old}
        assert score_program(prog) == 0

    def test_managed_bonus(self):
        prog = {"has_wildcard": False, "assets": [], "bounty_max": 0, "response_efficiency": 0,
                "managed": True}
        assert score_program(prog) == 5

    def test_invalid_date_no_crash(self):
        prog = {"has_wildcard": False, "assets": [], "bounty_max": 0, "response_efficiency": 0,
                "started_accepting_at": "not-a-date"}
        # Should not raise
        score_program(prog)


class TestExtractScopeDomains:
    def test_dict_assets(self):
        prog = {"assets": [
            {"asset_identifier": "https://app.example.com/api"},
            {"asset_identifier": "*.example.com"},
        ]}
        domains = extract_scope_domains(prog)
        assert "app.example.com" in domains
        assert "example.com" in domains

    def test_string_assets(self):
        prog = {"assets": ["http://test.io/path", "api.test.io"]}
        domains = extract_scope_domains(prog)
        assert "test.io" in domains
        assert "api.test.io" in domains

    def test_deduplicates(self):
        prog = {"assets": [
            {"asset_identifier": "https://app.example.com"},
            {"asset_identifier": "http://app.example.com"},
        ]}
        domains = extract_scope_domains(prog)
        assert domains.count("app.example.com") == 1

    def test_skips_empty_and_no_dot(self):
        prog = {"assets": [
            {"asset_identifier": ""},
            {"asset_identifier": "localhost"},
        ]}
        domains = extract_scope_domains(prog)
        assert domains == []

    def test_strips_wildcard_prefix(self):
        prog = {"assets": [{"asset_identifier": "*.sub.example.com"}]}
        domains = extract_scope_domains(prog)
        assert "sub.example.com" in domains


class TestSelectTargets:
    def test_returns_top_n(self):
        programs = [
            {"name": f"Prog{i}", "handle": f"prog{i}", "url": f"https://hackerone.com/prog{i}",
             "has_wildcard": i % 2 == 0, "assets": list(range(i)),
             "bounty_max": i * 1000, "bounty_min": 0, "response_efficiency": 50, "managed": False}
            for i in range(20)
        ]
        selected = select_targets(programs, top_n=5)
        assert len(selected) == 5

    def test_sorted_by_score_desc(self):
        programs = [
            {"name": "Low", "handle": "low", "url": "https://hackerone.com/low",
             "has_wildcard": False, "assets": [], "bounty_max": 0, "bounty_min": 0, "response_efficiency": 0},
            {"name": "High", "handle": "high", "url": "https://hackerone.com/high",
             "has_wildcard": True, "assets": list(range(10)), "bounty_max": 15000, "bounty_min": 100,
             "response_efficiency": 95, "managed": True},
        ]
        selected = select_targets(programs, top_n=2)
        assert selected[0]["name"] == "High"
        assert selected[1]["name"] == "Low"

    def test_adds_score_and_domains(self):
        programs = [{"name": "T", "handle": "t", "url": "https://hackerone.com/t",
                     "has_wildcard": False, "assets": [{"asset_identifier": "t.com"}],
                     "bounty_max": 0, "bounty_min": 0, "response_efficiency": 0}]
        selected = select_targets(programs, top_n=1)
        assert "score" in selected[0]
        assert "scope_domains" in selected[0]


class TestSaveTargets:
    def test_saves_json(self, tmp_path):
        output_file = str(tmp_path / "subdir" / "targets.json")
        targets = [{"name": "Test", "score": 50}]
        save_targets(targets, output_file)

        with open(output_file) as f:
            data = json.load(f)
        assert data["total_targets"] == 1
        assert data["targets"][0]["name"] == "Test"
        assert "generated_at" in data
        assert "scope_checklist" in data
