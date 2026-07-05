"""Tests for the auth session_id field on journal + pattern entries.

Lives in its own file so the existing test_schemas.py fixtures don't have
to change. Covers:
  - session_id is an optional string on journal + pattern entries
  - validation rejects empty / non-string session_id
  - make_journal_entry / make_pattern_entry auto-pick from BBHUNT_SESSION_ID
  - explicit session_id argument wins over the env var
"""

import pytest

from memory.schemas import (
    CURRENT_SCHEMA_VERSION,
    JOURNAL_OPTIONAL,
    PATTERN_OPTIONAL,
    SchemaError,
    make_journal_entry,
    make_pattern_entry,
    make_session_summary_entry,
    validate_journal_entry,
    validate_pattern_entry,
)


class TestSchemaFieldDefinitions:

    def test_session_id_is_journal_optional(self):
        assert "session_id" in JOURNAL_OPTIONAL

    def test_session_id_is_pattern_optional(self):
        assert "session_id" in PATTERN_OPTIONAL


class TestJournalSessionId:

    def _base(self):
        return {
            "ts": "2026-03-24T21:00:00Z",
            "target": "target.com",
            "action": "hunt",
            "vuln_class": "idor",
            "endpoint": "/api/users/1",
            "result": "confirmed",
            "schema_version": CURRENT_SCHEMA_VERSION,
        }

    def test_session_id_string_accepted(self):
        e = self._base()
        e["session_id"] = "abc123def456"
        assert validate_journal_entry(e)["session_id"] == "abc123def456"

    def test_session_id_empty_string_rejected(self):
        e = self._base()
        e["session_id"] = ""
        with pytest.raises(SchemaError, match="session_id"):
            validate_journal_entry(e)

    def test_session_id_whitespace_only_rejected(self):
        e = self._base()
        e["session_id"] = "   "
        with pytest.raises(SchemaError, match="session_id"):
            validate_journal_entry(e)

    def test_session_id_non_string_rejected(self):
        e = self._base()
        e["session_id"] = 12345
        with pytest.raises(SchemaError, match="session_id"):
            validate_journal_entry(e)

    def test_session_id_omitted_is_valid(self):
        e = self._base()
        assert "session_id" not in validate_journal_entry(e)


class TestPatternSessionId:

    def _base(self):
        return {
            "ts": "2026-03-24T21:00:00Z",
            "target": "target.com",
            "vuln_class": "idor",
            "technique": "numeric_id_swap",
            "tech_stack": ["express"],
            "schema_version": CURRENT_SCHEMA_VERSION,
        }

    def test_session_id_string_accepted(self):
        e = self._base()
        e["session_id"] = "abc123"
        assert validate_pattern_entry(e)["session_id"] == "abc123"

    def test_session_id_empty_rejected(self):
        e = self._base()
        e["session_id"] = ""
        with pytest.raises(SchemaError, match="session_id"):
            validate_pattern_entry(e)


class TestEnvAutoPickup:

    SID = "deadbeef1234"

    def test_journal_entry_picks_up_env_session_id(self, monkeypatch):
        monkeypatch.setenv("BBHUNT_SESSION_ID", self.SID)
        e = make_journal_entry(
            target="target.com",
            action="hunt",
            vuln_class="idor",
            endpoint="/api/users/1",
            result="confirmed",
        )
        assert e.get("session_id") == self.SID

    def test_explicit_arg_overrides_env(self, monkeypatch):
        monkeypatch.setenv("BBHUNT_SESSION_ID", self.SID)
        e = make_journal_entry(
            target="target.com",
            action="hunt",
            vuln_class="idor",
            endpoint="/api/users/1",
            result="confirmed",
            session_id="explicit-id",
        )
        assert e.get("session_id") == "explicit-id"

    def test_no_env_no_arg_no_field(self, monkeypatch):
        monkeypatch.delenv("BBHUNT_SESSION_ID", raising=False)
        e = make_journal_entry(
            target="target.com",
            action="hunt",
            vuln_class="idor",
            endpoint="/api/users/1",
            result="confirmed",
        )
        assert "session_id" not in e

    def test_pattern_entry_picks_up_env_session_id(self, monkeypatch):
        monkeypatch.setenv("BBHUNT_SESSION_ID", self.SID)
        e = make_pattern_entry(
            target="target.com",
            vuln_class="idor",
            technique="numeric_id_swap",
            tech_stack=["express"],
        )
        assert e.get("session_id") == self.SID

    def test_session_summary_picks_up_env_session_id(self, monkeypatch):
        monkeypatch.setenv("BBHUNT_SESSION_ID", self.SID)
        e = make_session_summary_entry(
            target="target.com",
            action="hunt",
            endpoints_tested=["/a", "/b"],
            vuln_classes_tried=["idor"],
            findings_count=1,
        )
        # The function's existing session_id param is a display label; the
        # auth-session hash from env attaches as the structured field.
        assert e.get("session_id") == self.SID

    def test_empty_env_var_treated_as_unset(self, monkeypatch):
        monkeypatch.setenv("BBHUNT_SESSION_ID", "")
        e = make_journal_entry(
            target="target.com",
            action="hunt",
            vuln_class="idor",
            endpoint="/api/users/1",
            result="confirmed",
        )
        assert "session_id" not in e
