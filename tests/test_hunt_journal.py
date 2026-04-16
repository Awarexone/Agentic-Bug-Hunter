"""Tests for memory/hunt_journal.py — write, read, corrupted, concurrent, empty, session summary."""

import json
import threading
import pytest

from memory.hunt_journal import HuntJournal
from memory.schemas import SchemaError, CURRENT_SCHEMA_VERSION, make_session_summary_entry


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


class TestSessionSummarySchema:

    def test_make_session_summary_entry_basic(self):
        entry = make_session_summary_entry(
            target="target.com",
            action="hunt",
            endpoints_tested=["/api/users/1", "/api/orders/2"],
            vuln_classes_tried=["idor", "ssrf"],
            findings_count=1,
        )
        assert entry["target"] == "target.com"
        assert entry["action"] == "hunt"
        assert entry["vuln_class"] == "session_summary"
        assert entry["result"] == "informational"
        assert "auto_logged" in entry["tags"]
        assert "session_summary" in entry["tags"]
        assert "has_findings" in entry["tags"]
        assert entry["schema_version"] == CURRENT_SCHEMA_VERSION

    def test_make_session_summary_no_findings(self):
        entry = make_session_summary_entry(
            target="target.com",
            action="hunt",
            endpoints_tested=["/api/test"],
            vuln_classes_tried=["xss"],
            findings_count=0,
        )
        assert "has_findings" not in entry["tags"]
        assert entry["result"] == "informational"

    def test_make_session_summary_with_session_id(self):
        entry = make_session_summary_entry(
            target="target.com",
            action="hunt",
            endpoints_tested=[],
            vuln_classes_tried=[],
            findings_count=0,
            session_id="autopilot-2026-04-16-001",
        )
        assert "autopilot-2026-04-16-001" in entry["notes"]

    def test_make_session_summary_empty_lists(self):
        entry = make_session_summary_entry(
            target="target.com",
            action="hunt",
            endpoints_tested=[],
            vuln_classes_tried=[],
            findings_count=0,
        )
        assert entry["endpoint"] == "none"
        assert "none" in entry["notes"]

    def test_make_session_summary_invalid_action_falls_back(self):
        entry = make_session_summary_entry(
            target="target.com",
            action="bad_action",
            endpoints_tested=[],
            vuln_classes_tried=[],
            findings_count=0,
        )
        assert entry["action"] == "hunt"

    def test_make_session_summary_long_endpoint_list_truncated(self):
        endpoints = [f"/api/endpoint/{i}" for i in range(50)]
        entry = make_session_summary_entry(
            target="target.com",
            action="hunt",
            endpoints_tested=endpoints,
            vuln_classes_tried=["idor"],
            findings_count=0,
        )
        assert len(entry["endpoint"]) <= 200


class TestLogSessionSummary:

    def test_log_session_summary_writes_entry(self, journal_path):
        journal = HuntJournal(journal_path)
        journal.log_session_summary(
            target="target.com",
            action="hunt",
            endpoints_tested=["/api/users/1"],
            vuln_classes_tried=["idor"],
            findings_count=2,
        )
        entries = journal.read_all()
        assert len(entries) == 1
        assert entries[0]["vuln_class"] == "session_summary"
        assert entries[0]["result"] == "informational"
        assert "auto_logged" in entries[0]["tags"]

    def test_log_session_summary_is_non_fatal_on_bad_target(self, journal_path, capsys):
        """Silent failure — must not raise even with invalid input."""
        journal = HuntJournal(journal_path)
        journal.log_session_summary(
            target="",  # invalid — empty string
            action="hunt",
            endpoints_tested=[],
            vuln_classes_tried=[],
            findings_count=0,
        )
        captured = capsys.readouterr()
        assert "WARNING" in captured.err
        assert not journal_path.exists()  # no write on failure

    def test_log_session_summary_coexists_with_manual_entries(self, journal_path, sample_journal_entry):
        journal = HuntJournal(journal_path)
        journal.append(sample_journal_entry)
        journal.log_session_summary(
            target="target.com",
            action="hunt",
            endpoints_tested=["/api/users/1"],
            vuln_classes_tried=["idor"],
            findings_count=1,
        )
        entries = journal.read_all()
        assert len(entries) == 2
        manual = [e for e in entries if e["vuln_class"] != "session_summary"]
        auto = [e for e in entries if e["vuln_class"] == "session_summary"]
        assert len(manual) == 1
        assert len(auto) == 1

    def test_query_excludes_session_summaries_by_default(self, journal_path, sample_journal_entry):
        """Callers can filter out auto-logged entries by vuln_class."""
        journal = HuntJournal(journal_path)
        journal.append(sample_journal_entry)
        journal.log_session_summary(
            target="target.com",
            action="hunt",
            endpoints_tested=[],
            vuln_classes_tried=[],
            findings_count=0,
        )
        real_findings = journal.query(target="target.com", result="confirmed")
        assert len(real_findings) == 1
        assert real_findings[0]["vuln_class"] == "idor"


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
