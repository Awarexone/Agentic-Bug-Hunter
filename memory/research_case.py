"""
Local research_case fixtures for false-positive / regression learning.

Default path: hunt-memory/cases/<case_id>.json (local only, not shared).
"""

from __future__ import annotations

import json
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from memory.schemas import SchemaError, VALID_CONTRIBUTION_TYPES

CASE_REQUIRED = {
    "schema_version", "case_id", "vulnerability_type", "candidate",
    "final_verdict", "false_positive_reason",
}
CASE_OPTIONAL = {
    "location", "initial_reasoning", "counter_evidence", "kill_signal",
    "framework", "language", "security_control", "expected_behavior",
    "provenance", "consent",
}
CASE_ALL = CASE_REQUIRED | CASE_OPTIONAL
VALID_CASE_VERDICTS = {"false_positive", "VALID", "FALSE_POSITIVE", "UNVERIFIED"}


def _slug(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower()).strip("-")
    return s[:48] or "case"


def validate_research_case(case: dict) -> dict:
    if not isinstance(case, dict):
        raise SchemaError(f"research_case must be a dict, got {type(case).__name__}")
    missing = CASE_REQUIRED - set(case.keys())
    if missing:
        raise SchemaError(f"research_case: missing required fields: {sorted(missing)}")
    unknown = set(case.keys()) - CASE_ALL
    if unknown:
        raise SchemaError(f"research_case: unknown fields: {sorted(unknown)}")
    if not isinstance(case["candidate"], dict):
        raise SchemaError("research_case: 'candidate' must be an object")
    consent = case.get("consent") or {}
    if consent.get("community_share") is True:
        raise SchemaError("research_case: community_share must remain false in v1")
    return case


def build_false_positive_case(
    *,
    vulnerability_type: str,
    candidate: dict[str, Any],
    false_positive_reason: str,
    counter_evidence: list[str] | None = None,
    kill_signal: str | None = None,
    framework: str | None = None,
    language: str | None = None,
    security_control: str | None = None,
    initial_reasoning: str | None = None,
    location: str | None = None,
    finding_id: str | None = None,
    journal_ts: str | None = None,
    schema_version: int = 2,
) -> dict:
    """Build a local FP research_case aligned with the FP issue template."""
    case_id = f"fp-{_slug(vulnerability_type)}-{_slug(false_positive_reason)}-{secrets.token_hex(2)}"
    case: dict[str, Any] = {
        "schema_version": schema_version,
        "case_id": case_id,
        "vulnerability_type": vulnerability_type,
        "candidate": candidate,
        "final_verdict": "false_positive",
        "false_positive_reason": false_positive_reason,
        "expected_behavior": "reject_finding",
        "provenance": {
            "source_finding_id": finding_id,
            "source_event": "false_positive_identified",
            "journal_ts": journal_ts or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "consent": {"local_store": True, "community_share": False},
    }
    if counter_evidence is not None:
        case["counter_evidence"] = counter_evidence
    if kill_signal is not None:
        case["kill_signal"] = kill_signal
    if framework is not None:
        case["framework"] = framework
    if language is not None:
        case["language"] = language
    if security_control is not None:
        case["security_control"] = security_control
    if initial_reasoning is not None:
        case["initial_reasoning"] = initial_reasoning
    if location is not None:
        case["location"] = location
    return validate_research_case(case)


def write_research_case(case: dict, cases_dir: str | Path | None = None) -> Path:
    """Persist a validated case under hunt-memory/cases/."""
    validated = validate_research_case(case)
    root = Path(cases_dir) if cases_dir else Path("hunt-memory") / "cases"
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{validated['case_id']}.json"
    path.write_text(json.dumps(validated, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def contribution_type_for_fp() -> str:
    assert "false_positive_test" in VALID_CONTRIBUTION_TYPES
    return "false_positive_test"
