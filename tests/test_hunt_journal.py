"""Tests for memory/hunt_journal.py — write, read, corrupted, concurrent, empty."""

import json
import threading
import pytest

from memory.hunt_journal import HuntJournal
from memory.schemas import SchemaError, CURRENT_SCHEMA_VERSION


class TestJournalWrite:

    def test_append_creates_file(self, journal_path, sample_journal_entry):
        journal = HuntJournal(journal_path)
        journal.append(sample_journal_entry)
        assert journal_path.exists()

    def test_append_writes_valid_jsonl(self, journal_path, sample_journal_entry):
        journal = HuntJournal(journal_path)
        journal.append(sample_journal_entry)
        with open(journal_path) as f:
            line = f.readline()
        parsed = json.loads(line)
        assert parsed["target"] == "target.com"

    def test_append_rejects_invalid_entry(self, journal_path):
        journal = HuntJournal(journal_path)
        with pytest.raises(SchemaError):
            journal.append({"bad": "entry"})
        # File should not be created for failed writes
        assert not journal_path.exists()

    def test_multiple_appends(self, journal_path, sample_journal_entry):
        journal = HuntJournal(journal_path)
        journal.append(sample_journal_entry)

        entry2 = sample_journal_entry.copy()
        entry2["endpoint"] = "/api/v2/users/{id}/export"
        entry2["result"] = "rejected"
        journal.append(entry2)

        entries = journal.read_all()
        assert len(entries) == 2


class TestJournalRead:

    def test_read_empty_file(self, journal_path):
        journal_path.touch()
        journal = HuntJournal(journal_path)
        assert journal.read_all() == []

    def test_read_nonexistent_file(self, journal_path):
        journal = HuntJournal(journal_path)
        assert journal.read_all() == []

    def test_read_skips_corrupted_lines(self, journal_path, sample_journal_entry):
        journal = HuntJournal(journal_path)
        journal.append(sample_journal_entry)

        # Inject a corrupted line
        with open(journal_path, "a") as f:
            f.write("{this is not valid json\n")

        # Append another valid entry
        entry2 = sample_journal_entry.copy()
        entry2["endpoint"] = "/other"
        journal.append(entry2)

        entries = journal.read_all()
        assert len(entries) == 2  # corrupted line skipped

    def test_read_skips_invalid_schema(self, journal_path, sample_journal_entry):
        journal = HuntJournal(journal_path)
        journal.append(sample_journal_entry)

        # Inject a line that's valid JSON but invalid schema
        with open(journal_path, "a") as f:
            f.write(json.dumps({"valid_json": True}) + "\n")

        entries = journal.read_all(validate=True)
        assert len(entries) == 1

    def test_read_without_validation(self, journal_path):
        # Write a raw JSON line that wouldn't pass schema validation
        with open(journal_path, "w") as f:
            f.write(json.dumps({"custom": "data"}) + "\n")

        journal = HuntJournal(journal_path)
        entries = journal.read_all(validate=False)
        assert len(entries) == 1
        assert entries[0]["custom"] == "data"


class TestJournalQuery:

    def test_query_by_target(self, journal_path, sample_journal_entry):
        journal = HuntJournal(journal_path)
        journal.append(sample_journal_entry)

        entry2 = sample_journal_entry.copy()
        entry2["target"] = "other.com"
        journal.append(entry2)

        results = journal.query(target="target.com")
        assert len(results) == 1
        assert results[0]["target"] == "target.com"

    def test_query_by_vuln_class(self, journal_path, sample_journal_entry):
        journal = HuntJournal(journal_path)
        journal.append(sample_journal_entry)

        entry2 = sample_journal_entry.copy()
        entry2["vuln_class"] = "xss"
        journal.append(entry2)

        results = journal.query(vuln_class="idor")
        assert len(results) == 1

    def test_query_multiple_filters(self, journal_path, sample_journal_entry):
        journal = HuntJournal(journal_path)
        journal.append(sample_journal_entry)

        results = journal.query(target="target.com", result="confirmed")
        assert len(results) == 1

        results = journal.query(target="target.com", result="rejected")
        assert len(results) == 0


class TestJournalConcurrency:

    def test_concurrent_appends(self, journal_path, sample_journal_entry):
        """Multiple threads appending simultaneously should not corrupt the file."""
        journal = HuntJournal(journal_path)
        num_threads = 10
        errors = []

        def append_entry(i):
            try:
                entry = sample_journal_entry.copy()
                entry["endpoint"] = f"/api/endpoint/{i}"
                journal.append(entry)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=append_entry, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during concurrent append: {errors}"

        entries = journal.read_all()
        assert len(entries) == num_threads
