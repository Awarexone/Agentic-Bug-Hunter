"""Tests for memory/vuln_intelligence.py — failed patterns, chains, affinity, endpoint shapes."""

import pytest

from memory.vuln_intelligence import (
    ChainDB,
    FailedPatternDB,
    HypothesisDB,
    ReportOutcomeDB,
    duplicate_or_noise_check,
    endpoint_shape_stats,
    expected_value_per_hour,
    hypothesis_calibration,
    normalize_endpoint,
    priority_score,
    tech_vuln_affinity,
)


class TestNormalizeEndpoint:

    def test_numeric_id_collapsed(self):
        assert normalize_endpoint("/api/v2/users/482/orders") == "/api/v2/users/{id}/orders"

    def test_uuid_collapsed(self):
        url = "https://t.example/api/v2/users/3fa85f64-5717-4562-b3fc-2c963f66afa6/orders"
        assert normalize_endpoint(url) == "/api/v2/users/{uuid}/orders"

    def test_query_string_stripped(self):
        assert normalize_endpoint("/search?q=admin&page=2") == "/search"

    def test_full_url_reduces_to_path(self):
        assert normalize_endpoint("https://api.target.com/graphql") == "/graphql"

    def test_two_different_ids_same_shape(self):
        a = normalize_endpoint("/api/v2/users/12/orders")
        b = normalize_endpoint("/api/v2/users/9107/orders")
        assert a == b

    def test_empty_input(self):
        assert normalize_endpoint("") == ""

    def test_static_path_untouched(self):
        assert normalize_endpoint("/graphql") == "/graphql"


class TestFailedPatternDB:

    def test_save_and_read(self, failed_patterns_path, sample_failed_pattern_entry):
        db = FailedPatternDB(failed_patterns_path)
        assert db.save(sample_failed_pattern_entry) is True
        assert failed_patterns_path.exists()
        entries = db.read_all()
        assert len(entries) == 1
        assert entries[0]["technique"] == "webhook_url_param"

    def test_duplicate_rejected(self, failed_patterns_path, sample_failed_pattern_entry):
        db = FailedPatternDB(failed_patterns_path)
        assert db.save(sample_failed_pattern_entry) is True
        assert db.save(sample_failed_pattern_entry) is False

    def test_same_technique_different_target_allowed(self, failed_patterns_path, sample_failed_pattern_entry):
        db = FailedPatternDB(failed_patterns_path)
        db.save(sample_failed_pattern_entry)
        entry2 = dict(sample_failed_pattern_entry)
        entry2["target"] = "other.com"
        assert db.save(entry2) is True

    def test_has_failed_true_for_known_pair(self, failed_patterns_path, sample_failed_pattern_entry):
        db = FailedPatternDB(failed_patterns_path)
        db.save(sample_failed_pattern_entry)
        hit = db.has_failed("target.com", "webhook_url_param")
        assert hit is not None
        assert hit["reason"] == "egress filtered, no callback"

    def test_has_failed_false_for_unknown_pair(self, failed_patterns_path, sample_failed_pattern_entry):
        db = FailedPatternDB(failed_patterns_path)
        db.save(sample_failed_pattern_entry)
        assert db.has_failed("target.com", "some_other_technique") is None

    def test_read_all_on_missing_file(self, failed_patterns_path):
        db = FailedPatternDB(failed_patterns_path)
        assert db.read_all() == []


class TestChainDB:

    def test_save_and_read(self, chains_path, sample_chain_entry):
        db = ChainDB(chains_path)
        assert db.save(sample_chain_entry) is True
        entries = db.read_all()
        assert len(entries) == 1
        assert entries[0]["chain_name"] == "secret_plus_api"

    def test_duplicate_same_target_and_chain_rejected(self, chains_path, sample_chain_entry):
        db = ChainDB(chains_path)
        assert db.save(sample_chain_entry) is True
        assert db.save(sample_chain_entry) is False

    def test_same_chain_different_target_allowed(self, chains_path, sample_chain_entry):
        db = ChainDB(chains_path)
        db.save(sample_chain_entry)
        entry2 = dict(sample_chain_entry)
        entry2["target"] = "other.com"
        assert db.save(entry2) is True

    def test_match_filters_by_tech_overlap(self, chains_path, sample_chain_entry):
        db = ChainDB(chains_path)
        db.save(sample_chain_entry)
        assert len(db.match(["express"])) == 1
        assert len(db.match(["django"])) == 0

    def test_match_no_filter_returns_all(self, chains_path, sample_chain_entry):
        db = ChainDB(chains_path)
        db.save(sample_chain_entry)
        assert len(db.match()) == 1

    def test_match_sorted_by_payout_desc(self, chains_path, sample_chain_entry):
        db = ChainDB(chains_path)
        db.save(sample_chain_entry)
        entry2 = dict(sample_chain_entry)
        entry2["target"] = "other.com"
        entry2["payout"] = 9000
        db.save(entry2)
        results = db.match(["express"])
        assert results[0]["payout"] == 9000


class TestTechVulnAffinity:

    def test_wins_and_losses_counted(self):
        patterns = [
            {"vuln_class": "idor", "tech_stack": ["express", "postgresql"], "payout": 1500, "target": "a.com"},
        ]
        failed = [
            {"vuln_class": "ssrf", "tech_stack": ["express"], "target": "b.com"},
        ]
        result = tech_vuln_affinity(["express", "postgresql"], patterns, failed)
        by_vc = {r["vuln_class"]: r for r in result}
        assert by_vc["idor"]["wins"] == 1
        assert by_vc["idor"]["losses"] == 0
        assert by_vc["ssrf"]["wins"] == 0
        assert by_vc["ssrf"]["losses"] == 1

    def test_no_overlap_excluded(self):
        patterns = [{"vuln_class": "idor", "tech_stack": ["django"], "payout": 500, "target": "a.com"}]
        result = tech_vuln_affinity(["express"], patterns, [])
        assert result == []

    def test_sorted_by_net_score_desc(self):
        patterns = [
            {"vuln_class": "idor", "tech_stack": ["express"], "payout": 100, "target": "a.com"},
            {"vuln_class": "idor", "tech_stack": ["express"], "payout": 100, "target": "b.com"},
            {"vuln_class": "xss", "tech_stack": ["express"], "payout": 100, "target": "a.com"},
        ]
        result = tech_vuln_affinity(["express"], patterns, [])
        assert result[0]["vuln_class"] == "idor"
        assert result[0]["wins"] == 2

    def test_cross_target_flag(self):
        patterns = [
            {"vuln_class": "idor", "tech_stack": ["express"], "payout": 100, "target": "a.com"},
            {"vuln_class": "idor", "tech_stack": ["express"], "payout": 100, "target": "b.com"},
        ]
        result = tech_vuln_affinity(["express"], patterns, [])
        assert result[0]["cross_target"] is True

    def test_avg_payout_zero_when_no_wins(self):
        failed = [{"vuln_class": "ssrf", "tech_stack": ["express"], "target": "a.com"}]
        result = tech_vuln_affinity(["express"], [], failed)
        assert result[0]["avg_payout"] == 0

    def test_top_limits_results(self):
        patterns = [
            {"vuln_class": "idor", "tech_stack": ["express"], "payout": 100, "target": "a.com"},
            {"vuln_class": "xss", "tech_stack": ["express"], "payout": 100, "target": "a.com"},
        ]
        result = tech_vuln_affinity(["express"], patterns, [], top=1)
        assert len(result) == 1


class TestEndpointShapeStats:

    def test_matches_same_shape_across_targets(self):
        patterns = [
            {"vuln_class": "idor", "endpoint": "/api/v2/users/12/orders", "tech_stack": ["express"], "target": "a.com"},
        ]
        result = endpoint_shape_stats("/api/v2/users/9107/orders", patterns, [])
        assert result["wins"] == 1
        assert result["shape"] == "/api/v2/users/{id}/orders"

    def test_journal_entries_counted(self):
        journal = [
            {"endpoint": "/api/v2/users/12/orders", "result": "rejected", "vuln_class": "idor"},
            {"endpoint": "/api/v2/users/55/orders", "result": "confirmed", "vuln_class": "idor"},
            {"endpoint": "/api/v2/users/9/orders", "result": "informational", "vuln_class": "idor"},
        ]
        result = endpoint_shape_stats("/api/v2/users/1/orders", [], [], journal)
        assert result["wins"] == 1
        assert result["losses"] == 1

    def test_no_matches_gives_zero_confidence(self):
        result = endpoint_shape_stats("/nowhere/{id}", [], [])
        assert result["wins"] == 0
        assert result["losses"] == 0
        assert result["confidence"] == 0

    def test_by_vuln_class_breakdown(self):
        patterns = [
            {"vuln_class": "idor", "endpoint": "/api/orders/1", "tech_stack": ["express"], "target": "a.com"},
        ]
        result = endpoint_shape_stats("/api/orders/2", patterns, [])
        assert result["by_vuln_class"]["idor"]["wins"] == 1


class TestReportOutcomeDB:

    def test_save_and_read(self, report_outcomes_path, sample_report_outcome_entry):
        db = ReportOutcomeDB(report_outcomes_path)
        assert db.save(sample_report_outcome_entry) is True
        entries = db.read_all()
        assert len(entries) == 1
        assert entries[0]["outcome"] == "accepted"

    def test_accumulates_multiple_outcomes_same_target_class(self, report_outcomes_path, sample_report_outcome_entry):
        # Report outcomes are NOT deduped like patterns/chains -- the same
        # vuln_class should accumulate many data points over time.
        db = ReportOutcomeDB(report_outcomes_path)
        db.save(sample_report_outcome_entry)
        entry2 = dict(sample_report_outcome_entry)
        entry2["ts"] = "2026-04-01T10:00:00Z"
        entry2["outcome"] = "duplicate"
        assert db.save(entry2) is True
        assert len(db.read_all()) == 2

    def test_exact_duplicate_save_rejected(self, report_outcomes_path, sample_report_outcome_entry):
        db = ReportOutcomeDB(report_outcomes_path)
        db.save(sample_report_outcome_entry)
        assert db.save(dict(sample_report_outcome_entry)) is False

    def test_acceptance_rate_computed_correctly(self, report_outcomes_path):
        db = ReportOutcomeDB(report_outcomes_path)
        db.save({"ts": "2026-01-01T00:00:00Z", "target": "a.com", "vuln_class": "idor",
                  "outcome": "accepted", "payout": 1000, "schema_version": 1})
        db.save({"ts": "2026-01-02T00:00:00Z", "target": "b.com", "vuln_class": "idor",
                  "outcome": "triaged", "payout": 500, "schema_version": 1})
        db.save({"ts": "2026-01-03T00:00:00Z", "target": "c.com", "vuln_class": "idor",
                  "outcome": "informative", "schema_version": 1})
        result = db.acceptance_rate()
        idor = next(r for r in result["by_vuln_class"] if r["vuln_class"] == "idor")
        assert idor["accepted"] == 2
        assert idor["closed_no_action"] == 1
        assert idor["acceptance_rate"] == 67  # round(100 * 2/3)
        assert idor["avg_payout"] == 750.0

    def test_acceptance_rate_filters_by_vuln_class(self, report_outcomes_path):
        db = ReportOutcomeDB(report_outcomes_path)
        db.save({"ts": "2026-01-01T00:00:00Z", "target": "a.com", "vuln_class": "idor",
                  "outcome": "accepted", "schema_version": 1})
        db.save({"ts": "2026-01-01T00:00:00Z", "target": "a.com", "vuln_class": "xss",
                  "outcome": "not_applicable", "schema_version": 1})
        result = db.acceptance_rate("idor")
        assert len(result["by_vuln_class"]) == 1
        assert result["by_vuln_class"][0]["vuln_class"] == "idor"

    def test_acceptance_rate_empty_db(self, report_outcomes_path):
        db = ReportOutcomeDB(report_outcomes_path)
        assert db.acceptance_rate() == {"by_vuln_class": []}


class TestPriorityScore:

    def test_hard_kill_on_failed_technique(self):
        failed = [{"target": "a.com", "vuln_class": "ssrf", "technique": "webhook_url",
                   "tech_stack": ["express"], "reason": "egress filtered"}]
        result = priority_score("ssrf", ["express"], "a.com", technique="webhook_url",
                                 patterns=[], failed_patterns=failed, chains=[])
        assert result["hard_kill"] is True
        assert result["score"] == 0
        assert result["failed_pattern_reason"] == "egress filtered"

    def test_no_hard_kill_for_different_technique(self):
        failed = [{"target": "a.com", "vuln_class": "ssrf", "technique": "webhook_url",
                   "tech_stack": ["express"]}]
        result = priority_score("ssrf", ["express"], "a.com", technique="different_technique",
                                 patterns=[], failed_patterns=failed, chains=[])
        assert result["hard_kill"] is False

    def test_wins_boost_historical_success(self):
        patterns = [{"vuln_class": "idor", "tech_stack": ["express"], "payout": 1000, "target": "a.com"}]
        result = priority_score("idor", ["express"], "a.com", patterns=patterns, failed_patterns=[], chains=[])
        assert result["components"]["historical_success_probability"] == 100

    def test_no_data_gives_neutral_baseline(self):
        result = priority_score("idor", ["express"], "a.com", patterns=[], failed_patterns=[], chains=[])
        assert result["components"]["historical_success_probability"] == 50
        assert result["components"]["technology_match"] == 20

    def test_chain_detected_flag_boosts_attack_chain_probability(self):
        result = priority_score("idor", ["express"], "a.com", patterns=[], failed_patterns=[],
                                 chains=[], chain_detected=True)
        assert result["components"]["attack_chain_probability"] == 90

    def test_matching_chain_without_detection_flag_gives_partial_boost(self):
        chains = [{"chain_name": "secret_plus_api", "tech_stack": ["express"]}]
        result = priority_score("idor", ["express"], "a.com", patterns=[], failed_patterns=[], chains=chains)
        assert result["components"]["attack_chain_probability"] == 60
        assert "secret_plus_api" in result["matching_chains"]

    def test_no_matching_chain_gives_zero(self):
        chains = [{"chain_name": "secret_plus_api", "tech_stack": ["django"]}]
        result = priority_score("idor", ["express"], "a.com", patterns=[], failed_patterns=[], chains=chains)
        assert result["components"]["attack_chain_probability"] == 0

    def test_impact_override_used_directly(self):
        result = priority_score("some_custom_class", ["express"], "a.com", patterns=[],
                                 failed_patterns=[], chains=[], impact_override=99)
        assert result["components"]["impact_potential"] == 99

    def test_unknown_vuln_class_uses_default_impact(self):
        result = priority_score("totally_unknown_class", [], "a.com", patterns=[], failed_patterns=[], chains=[])
        assert result["components"]["impact_potential"] == 50

    def test_score_bounded_0_to_100(self):
        # Even with every positive component maxed and no failure penalty,
        # score must stay within [0, 100].
        patterns = [{"vuln_class": "idor", "tech_stack": ["express"], "payout": 1000, "target": "a.com"}]
        result = priority_score("idor", ["express"], "a.com", patterns=patterns, failed_patterns=[],
                                 chains=[], chain_detected=True, impact_override=100)
        assert 0 <= result["score"] <= 100

    def test_score_never_negative_even_with_low_impact_and_kill(self):
        failed = [{"target": "a.com", "vuln_class": "x", "technique": "t", "tech_stack": ["express"]}]
        result = priority_score("x", ["express"], "a.com", technique="t", patterns=[],
                                 failed_patterns=failed, chains=[], impact_override=0)
        assert result["score"] == 0


class TestExpectedValuePerHour:

    def test_hard_kill_gives_zero_ev(self):
        failed = [{"target": "a.com", "vuln_class": "ssrf", "technique": "webhook_url",
                   "tech_stack": ["express"], "reason": "egress filtered"}]
        result = expected_value_per_hour("ssrf", ["express"], "a.com", technique="webhook_url",
                                          patterns=[], failed_patterns=failed, chains=[])
        assert result["hard_kill"] is True
        assert result["ev_per_hour"] == 0
        assert result["ev_label"] == "Kill"

    def test_uses_report_outcome_payout_probability_when_available(self):
        outcomes = [
            {"vuln_class": "idor", "outcome": "accepted"},
            {"vuln_class": "idor", "outcome": "accepted"},
            {"vuln_class": "idor", "outcome": "not_applicable"},
        ]
        result = expected_value_per_hour("idor", ["express"], "a.com", patterns=[],
                                          failed_patterns=[], chains=[], report_outcomes=outcomes)
        assert result["payout_probability"] == 67
        assert result["payout_probability_source"] == "report_outcomes.jsonl"

    def test_falls_back_to_heuristic_without_report_outcomes(self):
        result = expected_value_per_hour("idor", ["express"], "a.com", patterns=[],
                                          failed_patterns=[], chains=[])
        assert result["payout_probability_source"] == "heuristic (no report-outcome data)"
        assert result["payout_probability"] == result["priority_components"]["historical_success_probability"]

    def test_default_time_estimate_used_when_not_overridden(self):
        result = expected_value_per_hour("idor", ["express"], "a.com", patterns=[],
                                          failed_patterns=[], chains=[])
        assert result["estimated_minutes"] == 20  # TESTING_TIME_ESTIMATES["idor"]

    def test_explicit_minutes_overrides_default(self):
        result = expected_value_per_hour("idor", ["express"], "a.com", patterns=[],
                                          failed_patterns=[], chains=[], estimated_minutes=5)
        assert result["estimated_minutes"] == 5

    def test_faster_test_gives_higher_ev_at_same_score(self):
        fast = expected_value_per_hour("idor", ["express"], "a.com", patterns=[],
                                        failed_patterns=[], chains=[], estimated_minutes=10)
        slow = expected_value_per_hour("idor", ["express"], "a.com", patterns=[],
                                        failed_patterns=[], chains=[], estimated_minutes=40)
        assert fast["score"] == slow["score"]
        assert fast["ev_per_hour"] > slow["ev_per_hour"]

    def test_zero_minutes_rejected(self):
        with pytest.raises(ValueError):
            expected_value_per_hour("idor", ["express"], "a.com", patterns=[],
                                     failed_patterns=[], chains=[], estimated_minutes=0)

    def test_ev_label_thresholds(self):
        high = expected_value_per_hour("idor", ["express"], "a.com", patterns=[
            {"vuln_class": "idor", "tech_stack": ["express"], "payout": 1000, "target": "a.com"},
        ], failed_patterns=[], chains=[], estimated_minutes=5, impact_override=100)
        assert high["ev_label"] == "High"


class TestDuplicateOrNoiseCheck:

    def test_clean_when_nothing_matches(self):
        result = duplicate_or_noise_check("a.com", "idor", "/api/users/1")
        assert result == {
            "is_duplicate": False,
            "is_noise": False,
            "clean": True,
            "matching_journal_entries": 0,
            "matching_report_outcomes": [],
            "matching_failed_patterns": 0,
        }

    def test_duplicate_from_confirmed_journal_entry(self):
        journal = [{"target": "a.com", "vuln_class": "idor", "result": "confirmed", "endpoint": "/api/users/1"}]
        result = duplicate_or_noise_check("a.com", "idor", "/api/users/1", journal_entries=journal)
        assert result["is_duplicate"] is True
        assert result["clean"] is False

    def test_duplicate_matches_by_normalized_endpoint_shape(self):
        journal = [{"target": "a.com", "vuln_class": "idor", "result": "confirmed", "endpoint": "/api/users/482"}]
        result = duplicate_or_noise_check("a.com", "idor", "/api/users/9107", journal_entries=journal)
        assert result["is_duplicate"] is True

    def test_duplicate_from_report_outcome(self):
        outcomes = [{"target": "a.com", "vuln_class": "idor", "outcome": "accepted"}]
        result = duplicate_or_noise_check("a.com", "idor", "/api/users/1", report_outcomes=outcomes)
        assert result["is_duplicate"] is True
        assert result["matching_report_outcomes"] == ["accepted"]

    def test_noise_from_failed_pattern_with_no_duplicate(self):
        failed = [{"target": "a.com", "vuln_class": "ssrf", "endpoint": "/api/webhook"}]
        result = duplicate_or_noise_check("a.com", "ssrf", "/api/webhook", failed_patterns=failed)
        assert result["is_noise"] is True
        assert result["is_duplicate"] is False
        assert result["clean"] is False

    def test_duplicate_takes_precedence_over_noise(self):
        journal = [{"target": "a.com", "vuln_class": "ssrf", "result": "confirmed", "endpoint": "/api/webhook"}]
        failed = [{"target": "a.com", "vuln_class": "ssrf", "endpoint": "/api/webhook"}]
        result = duplicate_or_noise_check("a.com", "ssrf", "/api/webhook", journal_entries=journal, failed_patterns=failed)
        assert result["is_duplicate"] is True
        assert result["is_noise"] is False

    def test_different_target_not_matched(self):
        journal = [{"target": "b.com", "vuln_class": "idor", "result": "confirmed", "endpoint": "/api/users/1"}]
        result = duplicate_or_noise_check("a.com", "idor", "/api/users/1", journal_entries=journal)
        assert result["clean"] is True

    def test_rejected_journal_entry_does_not_count_as_duplicate(self):
        journal = [{"target": "a.com", "vuln_class": "idor", "result": "rejected", "endpoint": "/api/users/1"}]
        result = duplicate_or_noise_check("a.com", "idor", "/api/users/1", journal_entries=journal)
        assert result["is_duplicate"] is False


class TestHypothesisDB:

    def test_save_and_read(self, hypotheses_path, sample_hypothesis_entry):
        db = HypothesisDB(hypotheses_path)
        assert db.save(sample_hypothesis_entry) is True
        entries = db.read_all()
        assert len(entries) == 1
        assert entries[0]["confidence"] == 91

    def test_accumulates_multiple_hypotheses_same_target_class(self, hypotheses_path, sample_hypothesis_entry):
        db = HypothesisDB(hypotheses_path)
        db.save(sample_hypothesis_entry)
        entry2 = dict(sample_hypothesis_entry)
        entry2["ts"] = "2026-04-01T10:00:00Z"
        entry2["confidence"] = 60
        assert db.save(entry2) is True
        assert len(db.read_all()) == 2

    def test_exact_duplicate_save_rejected(self, hypotheses_path, sample_hypothesis_entry):
        db = HypothesisDB(hypotheses_path)
        db.save(sample_hypothesis_entry)
        assert db.save(dict(sample_hypothesis_entry)) is False


class TestHypothesisCalibration:

    def test_hit_via_report_outcome(self):
        hyps = [{"target": "a.com", "vuln_class": "idor", "endpoint": "/api/users/1", "confidence": 90}]
        outcomes = [{"target": "a.com", "vuln_class": "idor", "outcome": "accepted"}]
        result = hypothesis_calibration(hyps, report_outcomes=outcomes)
        bucket = next(b for b in result["buckets"] if b["confidence_bucket"] == "80-101")
        assert bucket["resolved_count"] == 1
        assert bucket["actual_hit_rate"] == 100
        assert bucket["calibration_gap"] == -10.0  # stated 90, actual 100 -> underconfident

    def test_miss_via_report_outcome(self):
        hyps = [{"target": "a.com", "vuln_class": "xss", "endpoint": "/search", "confidence": 85}]
        outcomes = [{"target": "a.com", "vuln_class": "xss", "outcome": "not_applicable"}]
        result = hypothesis_calibration(hyps, report_outcomes=outcomes)
        bucket = next(b for b in result["buckets"] if b["confidence_bucket"] == "80-101")
        assert bucket["actual_hit_rate"] == 0
        assert bucket["calibration_gap"] == 85.0  # stated 85, actual 0 -> badly overconfident

    def test_hit_via_journal_when_no_report_outcome(self):
        hyps = [{"target": "a.com", "vuln_class": "idor", "endpoint": "/api/users/12/orders", "confidence": 70}]
        journal = [{"target": "a.com", "vuln_class": "idor", "endpoint": "/api/users/99/orders", "result": "confirmed"}]
        result = hypothesis_calibration(hyps, journal_entries=journal)
        bucket = next(b for b in result["buckets"] if b["confidence_bucket"] == "60-80")
        assert bucket["resolved_count"] == 1
        assert bucket["actual_hit_rate"] == 100

    def test_report_outcome_takes_precedence_over_journal(self):
        # A rejected journal entry for the same vuln_class shouldn't win over
        # a report_outcomes entry that says it was actually accepted.
        hyps = [{"target": "a.com", "vuln_class": "idor", "endpoint": "/api/users/1", "confidence": 70}]
        journal = [{"target": "a.com", "vuln_class": "idor", "endpoint": "/api/users/1", "result": "rejected"}]
        outcomes = [{"target": "a.com", "vuln_class": "idor", "outcome": "accepted"}]
        result = hypothesis_calibration(hyps, journal_entries=journal, report_outcomes=outcomes)
        bucket = next(b for b in result["buckets"] if b["confidence_bucket"] == "60-80")
        assert bucket["actual_hit_rate"] == 100

    def test_unresolved_hypothesis_not_counted_as_miss(self):
        hyps = [{"target": "a.com", "vuln_class": "idor", "endpoint": "/api/users/1", "confidence": 70}]
        result = hypothesis_calibration(hyps)
        bucket = next(b for b in result["buckets"] if b["confidence_bucket"] == "60-80")
        assert bucket["resolved_count"] == 0
        assert bucket["unresolved_count"] == 1
        assert bucket["actual_hit_rate"] is None
        assert bucket["calibration_gap"] is None

    def test_buckets_are_separate_per_confidence_range(self):
        hyps = [
            {"target": "a.com", "vuln_class": "idor", "endpoint": "/x", "confidence": 10},
            {"target": "b.com", "vuln_class": "idor", "endpoint": "/y", "confidence": 90},
        ]
        result = hypothesis_calibration(hyps)
        buckets = {b["confidence_bucket"] for b in result["buckets"]}
        assert buckets == {"0-20", "80-101"}

    def test_empty_hypotheses_gives_no_buckets(self):
        assert hypothesis_calibration([]) == {"buckets": []}

    def test_endpoint_shape_matching_for_journal_resolution(self):
        # /api/users/{id}/orders shape should match regardless of the
        # specific numeric id, same normalize_endpoint() behavior used
        # throughout the rest of the intelligence layer.
        hyps = [{"target": "a.com", "vuln_class": "idor", "endpoint": "/api/users/12/orders", "confidence": 65}]
        journal = [{"target": "a.com", "vuln_class": "idor", "endpoint": "/api/users/999/orders", "result": "partial"}]
        result = hypothesis_calibration(hyps, journal_entries=journal)
        bucket = next(b for b in result["buckets"] if b["confidence_bucket"] == "60-80")
        assert bucket["actual_hit_rate"] == 100
