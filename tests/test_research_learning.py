"""Tests for schema v2 research events and HuntJournal."""

import json
from pathlib import Path

import pytest

from memory.hunt_journal import HuntJournal
from memory.research_case import build_false_positive_case, write_research_case
from memory.schemas import (
    CURRENT_SCHEMA_VERSION,
    SchemaError,
    make_journal_entry,
    make_research_event,
    validate_journal_entry,
    validate_research_block,
)


def test_schema_version_is_v2():
    assert CURRENT_SCHEMA_VERSION == 2


def test_false_positive_result_accepted():
    entry = make_journal_entry(
        target="example.com",
        action="remember",
        vuln_class="idor",
        endpoint="/api/x/{id}",
        result="false_positive",
        research=make_research_event(
            "false_positive_identified",
            fp_reason="middleware_authorization",
            kill_signal="ownership in middleware",
            contribution_type="false_positive_test",
        ),
        finding_id="fnd-test01",
    )
    assert entry["schema_version"] == 2
    assert entry["research"]["event"] == "false_positive_identified"
    assert entry["research"]["share_consent"] is False


def test_v1_journal_still_validates():
    entry = {
        "ts": "2026-03-24T21:00:00Z",
        "target": "target.com",
        "action": "hunt",
        "vuln_class": "idor",
        "endpoint": "/api/users/1",
        "result": "confirmed",
        "schema_version": 1,
    }
    assert validate_journal_entry(entry)["schema_version"] == 1


def test_share_consent_true_rejected():
    with pytest.raises(SchemaError, match="share_consent"):
        make_research_event("finding_validated", share_consent=True)


def test_correction_requires_fields():
    with pytest.raises(SchemaError, match="initial_hypothesis"):
        validate_research_block({"event": "user_corrected_agent", "correction": "x"})


def test_hunt_journal_append(tmp_path: Path):
    path = tmp_path / "journal.jsonl"
    j = HuntJournal(path)
    entry = make_journal_entry(
        target="t.com",
        action="validate",
        vuln_class="ssrf",
        endpoint="/hook",
        result="rejected",
        research=make_research_event(
            "finding_rejected",
            validation_status="scanner_hit",
            gate_verdict="kill",
        ),
    )
    j.append(entry)
    rows = j.read_all()
    assert len(rows) == 1
    assert rows[0]["finding_id"] if "finding_id" in rows[0] else True
    assert rows[0]["research"]["event"] == "finding_rejected"


def test_research_case_roundtrip(tmp_path: Path):
    case = build_false_positive_case(
        vulnerability_type="IDOR",
        candidate={"endpoint_shape": "/api/{id}", "vuln_class": "idor"},
        false_positive_reason="middleware_authorization",
        kill_signal="middleware ownership",
        framework="FastAPI",
        language="Python",
        finding_id="fnd-abc",
    )
    path = write_research_case(case, cases_dir=tmp_path)
    loaded = json.loads(path.read_text())
    assert loaded["consent"]["community_share"] is False
    assert loaded["false_positive_reason"] == "middleware_authorization"


def test_research_log_fp(tmp_path: Path, monkeypatch):
    from tools.research_log import log_false_positive

    out = log_false_positive(
        target="example.com",
        vuln_class="idor",
        endpoint="/api/p/{id}",
        fp_reason="middleware_authorization",
        kill_signal="middleware check",
        notes="auth in middleware",
        memory_dir=tmp_path,
    )
    assert out["entry"]["result"] == "false_positive"
    assert Path(out["case_path"]).exists()
