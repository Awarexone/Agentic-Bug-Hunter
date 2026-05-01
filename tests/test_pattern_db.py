"""Tests for memory/pattern_db.py — save, match, duplicate, cross-target."""

import time

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


class TestPatternPerformance:
    """TODO-8: PatternDB.save() perf at 10k entries.

    The original ``save()`` re-read the entire JSONL file on every call to
    deduplicate, making it O(n²) overall. With 10k entries the back-of-the-
    envelope cost is ~50M JSON parses / line scans — easily tens of seconds.

    These tests pin the dedup behavior we care about (still works after the
    perf fix) and assert a realistic upper bound on insertion time.
    """

    def _make_entry(self, n: int) -> dict:
        return {
            "ts": "2026-04-30T12:00:00Z",
            "target": f"t{n}.com",
            "vuln_class": "idor",
            "technique": f"technique_{n}",
            "tech_stack": ["express", "postgresql"],
            "payout": 100 + (n % 1000),
            "schema_version": CURRENT_SCHEMA_VERSION,
        }

    def test_save_10k_completes_under_5s(self, patterns_path):
        db = PatternDB(patterns_path)
        n = 10_000

        start = time.perf_counter()
        for i in range(n):
            assert db.save(self._make_entry(i)) is True
        elapsed = time.perf_counter() - start

        # The constraint: an active hunter shouldn't pay seconds-per-save.
        # 5 s for 10k inserts ≈ 0.5 ms/insert — comfortably bounded for a
        # JSONL append. The unoptimized O(n²) path took ~30 s+ on a laptop.
        assert elapsed < 5.0, f"save() at 10k entries took {elapsed:.2f}s, expected < 5s"

    def test_save_10k_dedup_still_works(self, patterns_path):
        """Perf fix must NOT change correctness — dedup keeps blocking duplicates."""
        db = PatternDB(patterns_path)
        n = 10_000
        for i in range(n):
            db.save(self._make_entry(i))

        # Re-saving any of the prior entries must still return False.
        assert db.save(self._make_entry(0)) is False
        assert db.save(self._make_entry(n // 2)) is False
        assert db.save(self._make_entry(n - 1)) is False

        # And a brand-new entry still returns True.
        new_entry = self._make_entry(n)
        assert db.save(new_entry) is True

    def test_save_dedup_survives_reopen(self, patterns_path):
        """A new PatternDB instance must observe duplicates from prior saves."""
        db1 = PatternDB(patterns_path)
        for i in range(20):
            db1.save(self._make_entry(i))

        db2 = PatternDB(patterns_path)
        # Existing entry → still a dup, even on a fresh instance.
        assert db2.save(self._make_entry(5)) is False
        # New entry → saved.
        assert db2.save(self._make_entry(100)) is True

    def test_dedup_skips_corrupted_lines(self, patterns_path):
        """A corrupted line in the file should not crash the dedup load.

        Behavior contract: corrupted lines are skipped. A subsequent save with
        a key that "would have" appeared in the corrupted line still succeeds.
        """
        db1 = PatternDB(patterns_path)
        db1.save(self._make_entry(1))
        db1.save(self._make_entry(2))

        # Inject a corrupted line between the two valid entries.
        with open(patterns_path, "a") as f:
            f.write("not valid json at all\n")

        db2 = PatternDB(patterns_path)
        # Existing valid entries are still recognized as dups.
        assert db2.save(self._make_entry(1)) is False
        assert db2.save(self._make_entry(2)) is False
        # A new entry still saves.
        assert db2.save(self._make_entry(3)) is True
