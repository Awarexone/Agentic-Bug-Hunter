"""Tests for memory/schemas.py — validation happy path + error paths."""

import pytest
from memory.schemas import (
    validate_journal_entry,
    validate_pattern_entry,
    validate_target_profile,
    make_journal_entry,
    make_pattern_entry,
    SchemaError,
    CURRENT_SCHEMA_VERSION,
)


class TestJournalValidation:

    def test_valid_full_entry(self, sample_journal_entry):
        result = validate_journal_entry(sample_journal_entry)
        assert result == sample_journal_entry

    def test_valid_minimal_entry(self):
        entry = {
            "ts": "2026-03-24T21:00:00Z",
            "target": "target.com",
            "action": "hunt",
            "vuln_class": "idor",
            "endpoint": "/api/users/1",
            "result": "confirmed",
            "schema_version": CURRENT_SCHEMA_VERSION,
        }
        assert validate_journal_entry(entry) == entry

    def test_missing_required_field(self, sample_journal_entry):
        del sample_journal_entry["target"]
        with pytest.raises(SchemaError, match="missing required fields.*target"):
            validate_journal_entry(sample_journal_entry)

    def test_invalid_result_value(self, sample_journal_entry):
        sample_journal_entry["result"] = "maybe"
        with pytest.raises(SchemaError, match="'result' must be one of"):
            validate_journal_entry(sample_journal_entry)

    def test_invalid_severity(self, sample_journal_entry):
        sample_journal_entry["severity"] = "super_critical"
        with pytest.raises(SchemaError, match="'severity' must be one of"):
            validate_journal_entry(sample_journal_entry)

    def test_invalid_timestamp(self, sample_journal_entry):
        sample_journal_entry["ts"] = "not-a-timestamp"
        with pytest.raises(SchemaError, match="Invalid timestamp"):
            validate_journal_entry(sample_journal_entry)

    def test_negative_payout(self, sample_journal_entry):
        sample_journal_entry["payout"] = -100
        with pytest.raises(SchemaError, match="'payout' must be a non-negative"):
            validate_journal_entry(sample_journal_entry)

    def test_unknown_field_rejected(self, sample_journal_entry):
        sample_journal_entry["extra_field"] = "oops"
        with pytest.raises(SchemaError, match="unknown fields"):
            validate_journal_entry(sample_journal_entry)

    def test_schema_version_zero_rejected(self, sample_journal_entry):
        sample_journal_entry["schema_version"] = 0
        with pytest.raises(SchemaError, match="schema_version must be a positive"):
            validate_journal_entry(sample_journal_entry)

    def test_not_a_dict(self):
        with pytest.raises(SchemaError, match="must be a dict"):
            validate_journal_entry("not a dict")

    def test_empty_target_rejected(self, sample_journal_entry):
        sample_journal_entry["target"] = ""
        with pytest.raises(SchemaError, match="'target' must be a non-empty"):
            validate_journal_entry(sample_journal_entry)

    def test_tags_must_be_list_of_strings(self, sample_journal_entry):
        sample_journal_entry["tags"] = [1, 2, 3]
        with pytest.raises(SchemaError, match="'tags' must be a list of strings"):
            validate_journal_entry(sample_journal_entry)

    def test_invalid_action(self, sample_journal_entry):
        sample_journal_entry["action"] = "destroy"
        with pytest.raises(SchemaError, match="'action' must be one of"):
            validate_journal_entry(sample_journal_entry)


class TestPatternValidation:

    def test_valid_pattern(self, sample_pattern_entry):
        result = validate_pattern_entry(sample_pattern_entry)
        assert result == sample_pattern_entry

    def test_missing_tech_stack(self, sample_pattern_entry):
        del sample_pattern_entry["tech_stack"]
        with pytest.raises(SchemaError, match="missing required fields"):
            validate_pattern_entry(sample_pattern_entry)

    def test_tech_stack_not_list(self, sample_pattern_entry):
        sample_pattern_entry["tech_stack"] = "express"
        with pytest.raises(SchemaError, match="'tech_stack' must be a list"):
            validate_pattern_entry(sample_pattern_entry)

    def test_empty_technique(self, sample_pattern_entry):
        sample_pattern_entry["technique"] = "  "
        with pytest.raises(SchemaError, match="'technique' must be a non-empty"):
            validate_pattern_entry(sample_pattern_entry)


class TestTargetProfileValidation:

    def test_valid_profile(self, sample_target_profile):
        result = validate_target_profile(sample_target_profile)
        assert result == sample_target_profile

    def test_missing_target(self, sample_target_profile):
        del sample_target_profile["target"]
        with pytest.raises(SchemaError, match="missing required fields"):
            validate_target_profile(sample_target_profile)

    def test_negative_hunt_sessions(self, sample_target_profile):
        sample_target_profile["hunt_sessions"] = -1
        with pytest.raises(SchemaError, match="'hunt_sessions' must be a non-negative"):
            validate_target_profile(sample_target_profile)

    def test_invalid_first_hunted(self, sample_target_profile):
        sample_target_profile["first_hunted"] = "invalid"
        with pytest.raises(SchemaError, match="Invalid timestamp"):
            validate_target_profile(sample_target_profile)


class TestFactoryFunctions:

    def test_make_journal_entry(self):
        entry = make_journal_entry(
            target="target.com",
            action="hunt",
            vuln_class="xss",
            endpoint="/search",
            result="confirmed",
            severity="medium",
        )
        assert entry["target"] == "target.com"
        assert entry["schema_version"] == CURRENT_SCHEMA_VERSION
        assert "ts" in entry

    def test_make_pattern_entry(self):
        entry = make_pattern_entry(
            target="target.com",
            vuln_class="idor",
            technique="id_swap",
            tech_stack=["express", "mongodb"],
        )
        assert entry["tech_stack"] == ["express", "mongodb"]
        assert entry["schema_version"] == CURRENT_SCHEMA_VERSION
