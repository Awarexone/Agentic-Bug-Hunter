"""Tests for memory/experiment_memory.py — payload-attempt log + stop/pivot decisions."""

import pytest

from memory.experiment_memory import (
    ExperimentDB,
    evaluate_experiment,
    payload_category_affinity,
    should_stop,
    suggest_pivot,
)


class TestExperimentDB:

    def test_save_and_read(self, experiments_path, sample_experiment_entry):
        db = ExperimentDB(experiments_path)
        assert db.save(sample_experiment_entry) is True
        assert experiments_path.exists()
        entries = db.read_all()
        assert len(entries) == 1
        assert entries[0]["payload_category"] == "numeric_id_swap"

    def test_exact_repeat_rejected(self, experiments_path, sample_experiment_entry):
        db = ExperimentDB(experiments_path)
        db.save(sample_experiment_entry)
        assert db.save(dict(sample_experiment_entry)) is False

    def test_same_combo_different_ts_accumulates(self, experiments_path, sample_experiment_entry):
        # Not deduped on (target, endpoint, payload_category) alone — a
        # legitimate re-test later must be allowed to accumulate.
        db = ExperimentDB(experiments_path)
        db.save(sample_experiment_entry)
        entry2 = dict(sample_experiment_entry)
        entry2["ts"] = "2026-04-01T10:00:00Z"
        entry2["result"] = "fail"
        assert db.save(entry2) is True
        assert len(db.read_all()) == 2

    def test_read_all_on_missing_file(self, experiments_path):
        db = ExperimentDB(experiments_path)
        assert db.read_all() == []

    def test_for_endpoint_matches_exact(self, experiments_path, sample_experiment_entry):
        db = ExperimentDB(experiments_path)
        db.save(sample_experiment_entry)
        results = db.for_endpoint("target.com", "/api/v2/users/{id}/orders")
        assert len(results) == 1

    def test_for_endpoint_matches_normalized_shape(self, experiments_path, sample_experiment_entry):
        db = ExperimentDB(experiments_path)
        entry = dict(sample_experiment_entry)
        entry["endpoint"] = "/api/v2/users/482/orders"
        db.save(entry)
        results = db.for_endpoint("target.com", "/api/v2/users/9107/orders")
        assert len(results) == 1

    def test_for_endpoint_excludes_other_targets(self, experiments_path, sample_experiment_entry):
        db = ExperimentDB(experiments_path)
        db.save(sample_experiment_entry)
        results = db.for_endpoint("other.com", "/api/v2/users/{id}/orders")
        assert results == []


class TestPayloadCategoryAffinity:

    def test_wins_and_losses_counted(self):
        experiments = [
            {"vuln_class": "auth-bypass", "payload_category": "missing_authz_check",
             "tech_stack": ["graphql", "node"], "result": "success"},
            {"vuln_class": "auth-bypass", "payload_category": "missing_authz_check",
             "tech_stack": ["graphql", "node"], "result": "fail"},
        ]
        result = payload_category_affinity(["graphql", "node"], experiments)
        assert result[0]["successes"] == 1
        assert result[0]["failures"] == 1
        assert result[0]["sample_size"] == 2

    def test_no_overlap_excluded(self):
        experiments = [
            {"vuln_class": "idor", "payload_category": "numeric_id_swap",
             "tech_stack": ["django"], "result": "success"},
        ]
        result = payload_category_affinity(["express"], experiments)
        assert result == []

    def test_stronger_tech_overlap_ranks_higher(self):
        # Same net_score, but one has 2 overlapping techs and one has 1 —
        # the 2-tech match should sort first (tie-break on overlap strength).
        experiments = [
            {"vuln_class": "auth-bypass", "payload_category": "single_overlap",
             "tech_stack": ["node"], "result": "success"},
            {"vuln_class": "auth-bypass", "payload_category": "double_overlap",
             "tech_stack": ["graphql", "node"], "result": "success"},
        ]
        result = payload_category_affinity(["graphql", "node"], experiments)
        assert result[0]["payload_category"] == "double_overlap"
        assert result[0]["tech_overlap_strength"] == 2

    def test_filters_by_vuln_class(self):
        experiments = [
            {"vuln_class": "idor", "payload_category": "numeric_id_swap",
             "tech_stack": ["express"], "result": "success"},
            {"vuln_class": "xss", "payload_category": "reflected_param",
             "tech_stack": ["express"], "result": "success"},
        ]
        result = payload_category_affinity(["express"], experiments, vuln_class="idor")
        assert len(result) == 1
        assert result[0]["payload_category"] == "numeric_id_swap"

    def test_top_limits_results(self):
        experiments = [
            {"vuln_class": "idor", "payload_category": "a", "tech_stack": ["express"], "result": "success"},
            {"vuln_class": "idor", "payload_category": "b", "tech_stack": ["express"], "result": "success"},
        ]
        result = payload_category_affinity(["express"], experiments, top=1)
        assert len(result) == 1

    def test_inconclusive_tracked_separately(self):
        experiments = [
            {"vuln_class": "idor", "payload_category": "a", "tech_stack": ["express"], "result": "inconclusive"},
        ]
        result = payload_category_affinity(["express"], experiments)
        assert result[0]["inconclusive"] == 1
        assert result[0]["successes"] == 0
        assert result[0]["failures"] == 0


class TestShouldStop:

    def test_success_present_never_stops(self):
        experiments = [{"payload_category": "a", "result": "success"}]
        result = should_stop(experiments, elapsed_minutes=10, minute_limit=5)
        assert result["stop"] is False
        assert "active signal" in result["reason"]

    def test_stops_after_time_limit_with_no_success(self):
        experiments = [{"payload_category": "a", "result": "fail"}]
        result = should_stop(experiments, elapsed_minutes=6, minute_limit=5)
        assert result["stop"] is True
        assert "5-minute rule" in result["reason"]

    def test_stops_after_category_limit_with_no_success(self):
        experiments = [
            {"payload_category": "a", "result": "fail"},
            {"payload_category": "b", "result": "fail"},
            {"payload_category": "c", "result": "fail"},
        ]
        result = should_stop(experiments, elapsed_minutes=2, minute_limit=5, category_limit=3)
        assert result["stop"] is True
        assert "categories exhausted" in result["reason"]

    def test_continues_within_budget(self):
        experiments = [{"payload_category": "a", "result": "fail"}]
        result = should_stop(experiments, elapsed_minutes=2, minute_limit=5, category_limit=3)
        assert result["stop"] is False

    def test_no_experiments_yet_continues(self):
        result = should_stop([], elapsed_minutes=1, minute_limit=5)
        assert result["stop"] is False
        assert result["categories_tried"] == []


class TestSuggestPivot:

    def test_picks_highest_scoring_non_exhausted_candidate(self):
        candidates = [
            {"endpoint": "/a", "score": 40},
            {"endpoint": "/b", "score": 78},
            {"endpoint": "/c", "score": 60},
        ]
        result = suggest_pivot(candidates, exhausted_endpoints={"/b"})
        assert result["endpoint"] == "/c"

    def test_skips_hard_kill_candidates(self):
        candidates = [
            {"endpoint": "/a", "score": 90, "hard_kill": True},
            {"endpoint": "/b", "score": 50},
        ]
        result = suggest_pivot(candidates, exhausted_endpoints=set())
        assert result["endpoint"] == "/b"

    def test_returns_none_when_all_exhausted(self):
        candidates = [{"endpoint": "/a", "score": 90}]
        result = suggest_pivot(candidates, exhausted_endpoints={"/a"})
        assert result is None

    def test_returns_none_for_empty_candidates(self):
        assert suggest_pivot([], exhausted_endpoints=set()) is None


class TestEvaluateExperiment:

    def test_failed_pattern_hard_stop(self):
        failed = [{"target": "a.com", "technique": "numeric_id_swap", "reason": "ownership check present"}]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor",
            failed_patterns=failed,
        )
        assert result["decision"] == "stop"
        assert "already failed" in result["reason"]
        assert "ownership check present" in result["reason"]
        assert result["confidence"] >= 90

    def test_failed_pattern_on_different_target_does_not_block(self):
        failed = [{"target": "other.com", "technique": "numeric_id_swap", "reason": "n/a"}]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor",
            failed_patterns=failed,
        )
        assert result["decision"] != "stop" or "already failed" not in result["reason"]

    def test_no_data_at_all_continues_with_low_confidence(self):
        result = evaluate_experiment(target="a.com", technique="numeric_id_swap", vuln_class="idor")
        assert result["decision"] == "continue"
        assert result["confidence"] == 20

    def test_active_success_overrides_everything(self):
        experiments = [
            {"target": "a.com", "endpoint": "/api/x", "technique": "numeric_id_swap",
             "vuln_class": "idor", "tech_stack": ["express"], "result": "success", "payload_category": "id_swap"},
        ]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor", tech_stack=["express"],
            endpoint="/api/x", experiments=experiments, elapsed_minutes=10, minute_limit=5,
            ev_label="Kill", ev_per_hour=0,
        )
        assert result["decision"] == "continue"
        assert "success" in result["reason"]

    def test_ev_kill_stops_without_budget_or_history(self):
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor", tech_stack=["express"],
            ev_label="Kill", ev_per_hour=0,
        )
        assert result["decision"] == "stop"
        assert "Kill" in result["reason"]

    def test_budget_exhausted_with_only_failures_stops(self):
        experiments = [
            {"target": "a.com", "endpoint": "/api/y", "technique": "numeric_id_swap", "vuln_class": "idor",
             "tech_stack": ["express"], "result": "fail", "payload_category": cat}
            for cat in ("id_swap", "header_swap", "jwt_swap")
        ]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor", tech_stack=["express"],
            endpoint="/api/y", experiments=experiments, elapsed_minutes=2, minute_limit=5, category_limit=3,
        )
        assert result["decision"] == "stop"
        assert "0W/3L" in result["reason"]

    def test_budget_exhausted_with_no_history_pivots_not_stops(self):
        # Time limit hit, but zero experiments logged for this technique yet
        # (e.g. someone else's payload categories burned the clock) — nothing
        # says this technique itself is a loser, so pivot rather than stop.
        experiments = [
            {"target": "a.com", "endpoint": "/api/y", "technique": "other_technique", "vuln_class": "idor",
             "tech_stack": ["express"], "result": "fail", "payload_category": "other_cat"},
        ]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor", tech_stack=["express"],
            endpoint="/api/y", experiments=experiments, elapsed_minutes=10, minute_limit=5,
        )
        assert result["decision"] == "pivot"

    def test_success_on_another_target_still_triggers_continue(self):
        # A win recorded anywhere with tech-stack overlap is an active signal,
        # not just a win on the exact target being evaluated right now.
        experiments = [
            {"target": "other.com", "technique": "numeric_id_swap", "vuln_class": "idor",
             "tech_stack": ["express"], "result": "success", "payload_category": "id_swap"},
        ]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor", tech_stack=["express"],
            experiments=experiments,
        )
        assert result["decision"] == "continue"
        assert "success" in result["reason"]

    def test_single_prior_failure_still_continues(self):
        # One failure elsewhere isn't enough of a track record to pivot on yet.
        experiments = [
            {"target": "other.com", "technique": "numeric_id_swap", "vuln_class": "idor",
             "tech_stack": ["express"], "result": "fail", "payload_category": "id_swap"},
        ]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor", tech_stack=["express"],
            experiments=experiments,
        )
        assert result["decision"] == "continue"
        assert "1W/1L" not in result["reason"]

    def test_similar_tech_poor_track_record_pivots(self):
        experiments = [
            {"target": "other.com", "technique": "numeric_id_swap", "vuln_class": "idor",
             "tech_stack": ["express"], "result": "fail", "payload_category": "id_swap"},
            {"target": "other2.com", "technique": "numeric_id_swap", "vuln_class": "idor",
             "tech_stack": ["express"], "result": "fail", "payload_category": "id_swap"},
            {"target": "other3.com", "technique": "numeric_id_swap", "vuln_class": "idor",
             "tech_stack": ["express"], "result": "fail", "payload_category": "id_swap"},
        ]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor", tech_stack=["express"],
            experiments=experiments,
        )
        assert result["decision"] == "pivot"

    def test_tech_stack_mismatch_excludes_experiment(self):
        experiments = [
            {"target": "other.com", "technique": "numeric_id_swap", "vuln_class": "idor",
             "tech_stack": ["django"], "result": "success", "payload_category": "id_swap"},
        ]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor", tech_stack=["express"],
            experiments=experiments,
        )
        # No overlap with ["django"] -> treated as no prior data.
        assert result["decision"] == "continue"
        assert result["confidence"] == 20

    def test_vuln_class_filter_excludes_other_classes(self):
        experiments = [
            {"target": "other.com", "technique": "numeric_id_swap", "vuln_class": "xss",
             "tech_stack": ["express"], "result": "success", "payload_category": "id_swap"},
        ]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor", tech_stack=["express"],
            experiments=experiments,
        )
        assert result["decision"] == "continue"
        assert result["confidence"] == 20

    def test_result_always_has_all_four_keys(self):
        result = evaluate_experiment(target="a.com", technique="x")
        assert set(result.keys()) == {"decision", "reason", "confidence", "recommended_next_step"}
        assert result["decision"] in {"continue", "pivot", "stop"}
