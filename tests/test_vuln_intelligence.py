"""Tests for memory/vuln_intelligence.py — failed patterns, chains, affinity, endpoint shapes."""

import pytest

from memory.vuln_intelligence import (
    ChainDB,
    FailedPatternDB,
    endpoint_shape_stats,
    normalize_endpoint,
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
