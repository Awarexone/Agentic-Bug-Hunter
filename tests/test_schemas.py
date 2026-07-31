"""Tests for memory/schemas.py — validation happy path + error paths."""

import pytest
from memory.schemas import (
    validate_journal_entry,
    validate_pattern_entry,
    validate_failed_pattern_entry,
    validate_chain_entry,
    validate_report_outcome_entry,
    validate_experiment_entry,
    validate_hypothesis_entry,
    validate_target_profile,
    make_journal_entry,
    make_pattern_entry,
    make_failed_pattern_entry,
    make_chain_entry,
    make_report_outcome_entry,
    make_experiment_entry,
    make_hypothesis_entry,
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


class TestFailedPatternValidation:

    def test_valid_failed_pattern(self, sample_failed_pattern_entry):
        result = validate_failed_pattern_entry(sample_failed_pattern_entry)
        assert result == sample_failed_pattern_entry

    def test_valid_minimal_failed_pattern(self):
        entry = {
            "ts": "2026-03-24T21:00:00Z",
            "target": "target.com",
            "vuln_class": "ssrf",
            "technique": "webhook_url_param",
            "tech_stack": ["express"],
            "schema_version": CURRENT_SCHEMA_VERSION,
        }
        assert validate_failed_pattern_entry(entry) == entry

    def test_missing_technique(self, sample_failed_pattern_entry):
        del sample_failed_pattern_entry["technique"]
        with pytest.raises(SchemaError, match="missing required fields"):
            validate_failed_pattern_entry(sample_failed_pattern_entry)

    def test_tech_stack_not_list(self, sample_failed_pattern_entry):
        sample_failed_pattern_entry["tech_stack"] = "express"
        with pytest.raises(SchemaError, match="'tech_stack' must be a list"):
            validate_failed_pattern_entry(sample_failed_pattern_entry)

    def test_empty_reason_rejected(self, sample_failed_pattern_entry):
        sample_failed_pattern_entry["reason"] = "   "
        with pytest.raises(SchemaError, match="'reason' must be a non-empty"):
            validate_failed_pattern_entry(sample_failed_pattern_entry)

    def test_unknown_field_rejected(self, sample_failed_pattern_entry):
        sample_failed_pattern_entry["extra"] = "oops"
        with pytest.raises(SchemaError, match="unknown fields"):
            validate_failed_pattern_entry(sample_failed_pattern_entry)


class TestChainValidation:

    def test_valid_chain(self, sample_chain_entry):
        result = validate_chain_entry(sample_chain_entry)
        assert result == sample_chain_entry

    def test_valid_minimal_chain(self):
        entry = {
            "ts": "2026-03-24T21:00:00Z",
            "target": "target.com",
            "chain_name": "secret_plus_api",
            "steps": ["step one", "step two"],
            "schema_version": CURRENT_SCHEMA_VERSION,
        }
        assert validate_chain_entry(entry) == entry

    def test_missing_chain_name(self, sample_chain_entry):
        del sample_chain_entry["chain_name"]
        with pytest.raises(SchemaError, match="missing required fields"):
            validate_chain_entry(sample_chain_entry)

    def test_steps_needs_at_least_two(self, sample_chain_entry):
        sample_chain_entry["steps"] = ["only one step"]
        with pytest.raises(SchemaError, match="at least 2 entries"):
            validate_chain_entry(sample_chain_entry)

    def test_steps_must_be_non_empty_strings(self, sample_chain_entry):
        sample_chain_entry["steps"] = ["real step", "  "]
        with pytest.raises(SchemaError, match="'steps' must be a list of non-empty strings"):
            validate_chain_entry(sample_chain_entry)

    def test_empty_chain_name_rejected(self, sample_chain_entry):
        sample_chain_entry["chain_name"] = ""
        with pytest.raises(SchemaError, match="'chain_name' must be a non-empty"):
            validate_chain_entry(sample_chain_entry)

    def test_invalid_severity(self, sample_chain_entry):
        sample_chain_entry["severity"] = "super_critical"
        with pytest.raises(SchemaError, match="'severity' must be one of"):
            validate_chain_entry(sample_chain_entry)

    def test_negative_payout(self, sample_chain_entry):
        sample_chain_entry["payout"] = -1
        with pytest.raises(SchemaError, match="'payout' must be a non-negative"):
            validate_chain_entry(sample_chain_entry)


class TestReportOutcomeValidation:

    def test_valid_report_outcome(self, sample_report_outcome_entry):
        result = validate_report_outcome_entry(sample_report_outcome_entry)
        assert result == sample_report_outcome_entry

    def test_valid_minimal_report_outcome(self):
        entry = {
            "ts": "2026-03-24T21:00:00Z",
            "target": "target.com",
            "vuln_class": "idor",
            "outcome": "accepted",
            "schema_version": CURRENT_SCHEMA_VERSION,
        }
        assert validate_report_outcome_entry(entry) == entry

    def test_missing_outcome(self, sample_report_outcome_entry):
        del sample_report_outcome_entry["outcome"]
        with pytest.raises(SchemaError, match="missing required fields"):
            validate_report_outcome_entry(sample_report_outcome_entry)

    def test_invalid_outcome_value(self, sample_report_outcome_entry):
        sample_report_outcome_entry["outcome"] = "maybe_paid"
        with pytest.raises(SchemaError, match="'outcome' must be one of"):
            validate_report_outcome_entry(sample_report_outcome_entry)

    def test_all_valid_outcomes_accepted(self):
        for outcome in ("accepted", "triaged", "duplicate", "informative", "not_applicable", "resolved"):
            entry = {
                "ts": "2026-03-24T21:00:00Z",
                "target": "target.com",
                "vuln_class": "idor",
                "outcome": outcome,
                "schema_version": CURRENT_SCHEMA_VERSION,
            }
            assert validate_report_outcome_entry(entry)["outcome"] == outcome

    def test_invalid_severity(self, sample_report_outcome_entry):
        sample_report_outcome_entry["severity"] = "super_critical"
        with pytest.raises(SchemaError, match="'severity' must be one of"):
            validate_report_outcome_entry(sample_report_outcome_entry)

    def test_negative_payout(self, sample_report_outcome_entry):
        sample_report_outcome_entry["payout"] = -1
        with pytest.raises(SchemaError, match="'payout' must be a non-negative"):
            validate_report_outcome_entry(sample_report_outcome_entry)

    def test_empty_target_rejected(self, sample_report_outcome_entry):
        sample_report_outcome_entry["target"] = ""
        with pytest.raises(SchemaError, match="'target' must be a non-empty"):
            validate_report_outcome_entry(sample_report_outcome_entry)

    def test_unknown_field_rejected(self, sample_report_outcome_entry):
        sample_report_outcome_entry["extra"] = "oops"
        with pytest.raises(SchemaError, match="unknown fields"):
            validate_report_outcome_entry(sample_report_outcome_entry)


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

    def test_make_failed_pattern_entry(self):
        entry = make_failed_pattern_entry(
            target="target.com",
            vuln_class="ssrf",
            technique="webhook_url_param",
            tech_stack=["express"],
            reason="egress filtered",
        )
        assert entry["reason"] == "egress filtered"
        assert entry["schema_version"] == CURRENT_SCHEMA_VERSION

    def test_make_chain_entry(self):
        entry = make_chain_entry(
            target="target.com",
            chain_name="secret_plus_api",
            steps=["leaked key in JS bundle", "key authenticates to internal API"],
            tech_stack=["express"],
            payout=4000,
            severity="critical",
        )
        assert entry["chain_name"] == "secret_plus_api"
        assert len(entry["steps"]) == 2
        assert entry["schema_version"] == CURRENT_SCHEMA_VERSION

    def test_make_report_outcome_entry(self):
        entry = make_report_outcome_entry(
            target="target.com",
            vuln_class="idor",
            outcome="accepted",
            payout=1500,
            platform="hackerone",
        )
        assert entry["outcome"] == "accepted"
        assert entry["platform"] == "hackerone"
        assert entry["schema_version"] == CURRENT_SCHEMA_VERSION

    def test_make_experiment_entry(self):
        entry = make_experiment_entry(
            target="target.com",
            endpoint="/api/v2/users/{id}/orders",
            vuln_class="idor",
            payload_category="numeric_id_swap",
            result="success",
            tech_stack=["express"],
            time_spent_minutes=8,
        )
        assert entry["payload_category"] == "numeric_id_swap"
        assert entry["result"] == "success"
        assert entry["schema_version"] == CURRENT_SCHEMA_VERSION

    def test_make_hypothesis_entry(self):
        entry = make_hypothesis_entry(
            target="target.com",
            vuln_class="idor",
            endpoint="/api/v2/users/{id}/orders",
            confidence=91,
            hypothesis_name="bola",
            tech_stack=["express"],
            signals=["numeric object id"],
            source="hypothesis-engine",
        )
        assert entry["confidence"] == 91
        assert entry["hypothesis_name"] == "bola"
        assert entry["schema_version"] == CURRENT_SCHEMA_VERSION

    def test_make_hypothesis_entry_with_advanced_fields(self):
        entry = make_hypothesis_entry(
            target="target.com", vuln_class="idor", endpoint="/api/v2/users/{id}", confidence=87,
            attack_chain=["JS Secret", "API Access", "Weak Authentication", "Privilege Escalation", "Account Takeover"],
            impact="critical", probability=65, effort="medium",
        )
        assert len(entry["attack_chain"]) == 5
        assert entry["impact"] == "critical"
        assert entry["probability"] == 65
        assert entry["effort"] == "medium"

    def test_make_hypothesis_entry_without_advanced_fields_omits_them(self):
        entry = make_hypothesis_entry(target="target.com", vuln_class="idor", endpoint="/x", confidence=50)
        assert "attack_chain" not in entry
        assert "impact" not in entry
        assert "probability" not in entry
        assert "effort" not in entry


class TestExperimentValidation:

    def test_valid_full_entry(self, sample_experiment_entry):
        result = validate_experiment_entry(sample_experiment_entry)
        assert result == sample_experiment_entry

    def test_valid_minimal_entry(self):
        entry = {
            "ts": "2026-03-24T21:00:00Z",
            "target": "target.com",
            "endpoint": "/api/v2/users/1",
            "vuln_class": "idor",
            "payload_category": "numeric_id_swap",
            "result": "fail",
            "schema_version": CURRENT_SCHEMA_VERSION,
        }
        assert validate_experiment_entry(entry) == entry

    def test_missing_required_field(self, sample_experiment_entry):
        del sample_experiment_entry["payload_category"]
        with pytest.raises(SchemaError, match="missing required fields.*payload_category"):
            validate_experiment_entry(sample_experiment_entry)

    def test_invalid_result_value(self, sample_experiment_entry):
        sample_experiment_entry["result"] = "maybe"
        with pytest.raises(SchemaError, match="'result' must be one of"):
            validate_experiment_entry(sample_experiment_entry)

    def test_empty_endpoint_rejected(self, sample_experiment_entry):
        sample_experiment_entry["endpoint"] = "  "
        with pytest.raises(SchemaError, match="'endpoint' must be a non-empty"):
            validate_experiment_entry(sample_experiment_entry)

    def test_empty_payload_category_rejected(self, sample_experiment_entry):
        sample_experiment_entry["payload_category"] = ""
        with pytest.raises(SchemaError, match="'payload_category' must be a non-empty"):
            validate_experiment_entry(sample_experiment_entry)

    def test_negative_time_spent_rejected(self, sample_experiment_entry):
        sample_experiment_entry["time_spent_minutes"] = -5
        with pytest.raises(SchemaError, match="'time_spent_minutes' must be a non-negative"):
            validate_experiment_entry(sample_experiment_entry)

    def test_tech_stack_not_list_rejected(self, sample_experiment_entry):
        sample_experiment_entry["tech_stack"] = "express"
        with pytest.raises(SchemaError, match="'tech_stack' must be a list"):
            validate_experiment_entry(sample_experiment_entry)

    def test_unknown_field_rejected(self, sample_experiment_entry):
        sample_experiment_entry["extra_field"] = "oops"
        with pytest.raises(SchemaError, match="unknown fields"):
            validate_experiment_entry(sample_experiment_entry)

    def test_not_a_dict(self):
        with pytest.raises(SchemaError, match="must be a dict"):
            validate_experiment_entry("not a dict")


class TestHypothesisValidation:

    def test_valid_full_entry(self, sample_hypothesis_entry):
        result = validate_hypothesis_entry(sample_hypothesis_entry)
        assert result == sample_hypothesis_entry

    def test_valid_minimal_entry(self):
        entry = {
            "ts": "2026-03-24T21:00:00Z",
            "target": "target.com",
            "vuln_class": "idor",
            "endpoint": "/api/v2/users/1",
            "confidence": 50,
            "schema_version": CURRENT_SCHEMA_VERSION,
        }
        assert validate_hypothesis_entry(entry) == entry

    def test_missing_confidence(self, sample_hypothesis_entry):
        del sample_hypothesis_entry["confidence"]
        with pytest.raises(SchemaError, match="missing required fields.*confidence"):
            validate_hypothesis_entry(sample_hypothesis_entry)

    def test_confidence_above_100_rejected(self, sample_hypothesis_entry):
        sample_hypothesis_entry["confidence"] = 101
        with pytest.raises(SchemaError, match="'confidence' must be a number 0-100"):
            validate_hypothesis_entry(sample_hypothesis_entry)

    def test_confidence_below_0_rejected(self, sample_hypothesis_entry):
        sample_hypothesis_entry["confidence"] = -1
        with pytest.raises(SchemaError, match="'confidence' must be a number 0-100"):
            validate_hypothesis_entry(sample_hypothesis_entry)

    def test_confidence_boundary_values_accepted(self, sample_hypothesis_entry):
        sample_hypothesis_entry["confidence"] = 0
        assert validate_hypothesis_entry(sample_hypothesis_entry)["confidence"] == 0
        sample_hypothesis_entry["confidence"] = 100
        assert validate_hypothesis_entry(sample_hypothesis_entry)["confidence"] == 100

    def test_confidence_bool_rejected(self, sample_hypothesis_entry):
        sample_hypothesis_entry["confidence"] = True
        with pytest.raises(SchemaError, match="'confidence' must be a number 0-100"):
            validate_hypothesis_entry(sample_hypothesis_entry)

    def test_confidence_non_numeric_rejected(self, sample_hypothesis_entry):
        sample_hypothesis_entry["confidence"] = "high"
        with pytest.raises(SchemaError, match="'confidence' must be a number 0-100"):
            validate_hypothesis_entry(sample_hypothesis_entry)

    def test_empty_endpoint_rejected(self, sample_hypothesis_entry):
        sample_hypothesis_entry["endpoint"] = "  "
        with pytest.raises(SchemaError, match="'endpoint' must be a non-empty"):
            validate_hypothesis_entry(sample_hypothesis_entry)

    def test_signals_not_list_rejected(self, sample_hypothesis_entry):
        sample_hypothesis_entry["signals"] = "one big signal"
        with pytest.raises(SchemaError, match="'signals' must be a list of strings"):
            validate_hypothesis_entry(sample_hypothesis_entry)

    def test_tech_stack_not_list_rejected(self, sample_hypothesis_entry):
        sample_hypothesis_entry["tech_stack"] = "express"
        with pytest.raises(SchemaError, match="'tech_stack' must be a list"):
            validate_hypothesis_entry(sample_hypothesis_entry)

    def test_empty_hypothesis_name_rejected(self, sample_hypothesis_entry):
        sample_hypothesis_entry["hypothesis_name"] = ""
        with pytest.raises(SchemaError, match="'hypothesis_name' must be a non-empty"):
            validate_hypothesis_entry(sample_hypothesis_entry)

    def test_unknown_field_rejected(self, sample_hypothesis_entry):
        sample_hypothesis_entry["extra_field"] = "oops"
        with pytest.raises(SchemaError, match="unknown fields"):
            validate_hypothesis_entry(sample_hypothesis_entry)

    def test_not_a_dict(self):
        with pytest.raises(SchemaError, match="must be a dict"):
            validate_hypothesis_entry("not a dict")

    # ── Phase 2: advanced fields (attack_chain/impact/probability/effort) ──

    def test_old_style_entry_without_advanced_fields_still_valid(self):
        # Backward compatibility: entries written before Phase 2 have none
        # of these fields and must keep validating exactly as before.
        entry = {
            "ts": "2026-01-01T00:00:00Z", "target": "a.com", "vuln_class": "idor",
            "endpoint": "/x", "confidence": 80, "schema_version": CURRENT_SCHEMA_VERSION,
        }
        assert validate_hypothesis_entry(entry) == entry

    def test_valid_attack_chain_accepted(self, sample_hypothesis_entry):
        sample_hypothesis_entry["attack_chain"] = [
            "JS Secret", "API Access", "Weak Authentication", "Privilege Escalation", "Account Takeover",
        ]
        result = validate_hypothesis_entry(sample_hypothesis_entry)
        assert len(result["attack_chain"]) == 5

    def test_attack_chain_single_step_rejected(self, sample_hypothesis_entry):
        sample_hypothesis_entry["attack_chain"] = ["only one step"]
        with pytest.raises(SchemaError, match="at least 2 steps"):
            validate_hypothesis_entry(sample_hypothesis_entry)

    def test_attack_chain_not_list_rejected(self, sample_hypothesis_entry):
        sample_hypothesis_entry["attack_chain"] = "not a list"
        with pytest.raises(SchemaError, match="'attack_chain' must be a list"):
            validate_hypothesis_entry(sample_hypothesis_entry)

    def test_attack_chain_empty_step_rejected(self, sample_hypothesis_entry):
        sample_hypothesis_entry["attack_chain"] = ["real step", "  "]
        with pytest.raises(SchemaError, match="'attack_chain' must be a list of non-empty strings"):
            validate_hypothesis_entry(sample_hypothesis_entry)

    def test_valid_impact_accepted(self, sample_hypothesis_entry):
        sample_hypothesis_entry["impact"] = "critical"
        assert validate_hypothesis_entry(sample_hypothesis_entry)["impact"] == "critical"

    def test_empty_impact_rejected(self, sample_hypothesis_entry):
        sample_hypothesis_entry["impact"] = ""
        with pytest.raises(SchemaError, match="'impact' must be a non-empty"):
            validate_hypothesis_entry(sample_hypothesis_entry)

    def test_valid_probability_accepted(self, sample_hypothesis_entry):
        sample_hypothesis_entry["probability"] = 65
        assert validate_hypothesis_entry(sample_hypothesis_entry)["probability"] == 65

    def test_probability_out_of_range_rejected(self, sample_hypothesis_entry):
        sample_hypothesis_entry["probability"] = 150
        with pytest.raises(SchemaError, match="'probability' must be a number 0-100"):
            validate_hypothesis_entry(sample_hypothesis_entry)

    def test_valid_effort_accepted(self, sample_hypothesis_entry):
        sample_hypothesis_entry["effort"] = "medium"
        assert validate_hypothesis_entry(sample_hypothesis_entry)["effort"] == "medium"

    def test_empty_effort_rejected(self, sample_hypothesis_entry):
        sample_hypothesis_entry["effort"] = ""
        with pytest.raises(SchemaError, match="'effort' must be a non-empty"):
            validate_hypothesis_entry(sample_hypothesis_entry)
