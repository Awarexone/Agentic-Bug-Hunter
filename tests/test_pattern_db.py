"""Tests for memory/pattern_db.py — save, match, duplicate, cross-target."""

import pytest

from memory.pattern_db import PatternDB
from memory.schemas import CURRENT_SCHEMA_VERSION


class TestPatternSave:

    def test_save_creates_file(self, patterns_path, sample_pattern_entry):
        db = PatternDB(patterns_path)
        result = db.save(sample_pattern_entry)
        assert result is True
        assert patterns_path.exists()

    def test_save_returns_false_for_duplicate(self, patterns_path, sample_pattern_entry):
        db = PatternDB(patterns_path)
        assert db.save(sample_pattern_entry) is True
        assert db.save(sample_pattern_entry) is False

    def test_save_allows_same_technique_different_target(self, patterns_path, sample_pattern_entry):
        db = PatternDB(patterns_path)
        db.save(sample_pattern_entry)

        entry2 = sample_pattern_entry.copy()
        entry2["target"] = "other.com"
        assert db.save(entry2) is True

    def test_save_allows_same_target_different_technique(self, patterns_path, sample_pattern_entry):
        db = PatternDB(patterns_path)
        db.save(sample_pattern_entry)

        entry2 = sample_pattern_entry.copy()
        entry2["technique"] = "auth_bypass_via_method_override"
        assert db.save(entry2) is True


class TestPatternRead:

    def test_read_empty(self, patterns_path):
        db = PatternDB(patterns_path)
        assert db.read_all() == []

    def test_read_nonexistent(self, patterns_path):
        db = PatternDB(patterns_path)
        assert db.read_all() == []


class TestPatternMatch:

    def _seed_patterns(self, db):
        """Seed the database with 3 patterns for matching tests."""
        patterns = [
            {
                "ts": "2026-03-20T10:00:00Z",
                "target": "alpha.com",
                "vuln_class": "idor",
                "technique": "id_swap",
                "tech_stack": ["express", "postgresql"],
                "payout": 1500,
                "schema_version": CURRENT_SCHEMA_VERSION,
            },
            {
                "ts": "2026-03-21T10:00:00Z",
                "target": "beta.com",
                "vuln_class": "idor",
                "technique": "uuid_to_int",
                "tech_stack": ["django", "postgresql"],
                "payout": 800,
                "schema_version": CURRENT_SCHEMA_VERSION,
            },
            {
                "ts": "2026-03-22T10:00:00Z",
                "target": "gamma.com",
                "vuln_class": "xss",
                "technique": "dom_clobbering",
                "tech_stack": ["react", "express"],
                "payout": 500,
                "schema_version": CURRENT_SCHEMA_VERSION,
            },
        ]
        for p in patterns:
            db.save(p)

    def test_match_by_vuln_class(self, patterns_path):
        db = PatternDB(patterns_path)
        self._seed_patterns(db)
        results = db.match(vuln_class="idor")
        assert len(results) == 2

    def test_match_by_tech_stack_partial_overlap(self, patterns_path):
        db = PatternDB(patterns_path)
        self._seed_patterns(db)
        # Query for "express" — should match alpha.com and gamma.com
        results = db.match(tech_stack=["express"])
        assert len(results) == 2
        targets = {r["target"] for r in results}
        assert targets == {"alpha.com", "gamma.com"}

    def test_match_combined_filters(self, patterns_path):
        db = PatternDB(patterns_path)
        self._seed_patterns(db)
        # IDOR + express = only alpha.com
        results = db.match(vuln_class="idor", tech_stack=["express"])
        assert len(results) == 1
        assert results[0]["target"] == "alpha.com"

    def test_match_no_results(self, patterns_path):
        db = PatternDB(patterns_path)
        self._seed_patterns(db)
        results = db.match(vuln_class="ssrf")
        assert len(results) == 0

    def test_match_sorted_by_payout(self, patterns_path):
        db = PatternDB(patterns_path)
        self._seed_patterns(db)
        results = db.match(vuln_class="idor")
        assert results[0]["payout"] >= results[1]["payout"]

    def test_match_case_insensitive_tech_stack(self, patterns_path):
        db = PatternDB(patterns_path)
        self._seed_patterns(db)
        results = db.match(tech_stack=["Express"])  # uppercase
        assert len(results) == 2

    def test_cross_target_learning(self, patterns_path):
        """Pattern from target A should be discoverable when hunting target B with same tech."""
        db = PatternDB(patterns_path)
        self._seed_patterns(db)
        # Hunting new target with postgresql — should find patterns from alpha + beta
        results = db.match(tech_stack=["postgresql"])
        assert len(results) == 2
