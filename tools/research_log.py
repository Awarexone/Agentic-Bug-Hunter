"""
Research learning helpers — draft journal events from validate / remember flows.

Local-only. Never sets share_consent=true.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from memory.hunt_journal import HuntJournal, default_journal_path
from memory.research_case import build_false_positive_case, write_research_case
from memory.schemas import (
    make_journal_entry,
    make_research_event,
)


def new_finding_id() -> str:
    return "fnd-" + secrets.token_hex(4)


def draft_from_validation(
    *,
    target: str,
    vuln_class: str,
    endpoint: str,
    status: str,
    rejection_reasons: list[str] | None = None,
    finding_id: str | None = None,
    memory_dir: str | Path | None = None,
    write: bool = True,
) -> dict:
    """Map validation.json status into a research journal draft."""
    finding_id = finding_id or new_finding_id()
    reasons = [r for r in (rejection_reasons or []) if r]
    if status == "validated_finding":
        research = make_research_event(
            "finding_validated",
            validation_status="validated_finding",
            gate_verdict="pass",
            contribution_type="regression_test",
        )
        result = "confirmed"
        action = "validate"
    else:
        # scanner_hit — suggest reject; researcher may later mark --fp
        research = make_research_event(
            "finding_rejected",
            validation_status="scanner_hit",
            gate_verdict="kill",
            lesson="; ".join(reasons) if reasons else "validation gates did not pass",
        )
        result = "rejected"
        action = "validate"

    entry = make_journal_entry(
        target=target or "unknown",
        action=action,
        vuln_class=vuln_class or "unknown",
        endpoint=endpoint or "unknown",
        result=result,
        notes="; ".join(reasons) if reasons else None,
        tags=["from_validate"],
        finding_id=finding_id,
        research=research,
    )
    if write:
        journal = HuntJournal(default_journal_path(memory_dir))
        journal.append(entry)
    return entry


def log_false_positive(
    *,
    target: str,
    vuln_class: str,
    endpoint: str,
    fp_reason: str,
    kill_signal: str | None = None,
    framework: str | None = None,
    language: str | None = None,
    security_control: str | None = None,
    notes: str | None = None,
    finding_id: str | None = None,
    lead_id: str | None = None,
    memory_dir: str | Path | None = None,
    write_case: bool = True,
) -> dict[str, Any]:
    """Record an FP journal event and optional local research_case."""
    finding_id = finding_id or new_finding_id()
    research = make_research_event(
        "false_positive_identified",
        fp_reason=fp_reason,
        kill_signal=kill_signal,
        framework=framework,
        language=language,
        security_control=security_control,
        gate_verdict="kill",
        contribution_type="false_positive_test",
    )
    entry = make_journal_entry(
        target=target,
        action="remember",
        vuln_class=vuln_class,
        endpoint=endpoint,
        result="false_positive",
        severity="none",
        notes=notes,
        tags=["fp"],
        finding_id=finding_id,
        lead_id=lead_id,
        research=research,
    )
    root = Path(memory_dir) if memory_dir else Path("hunt-memory")
    HuntJournal(root / "journal.jsonl").append(entry)

    case_path = None
    if write_case:
        case = build_false_positive_case(
            vulnerability_type=vuln_class,
            candidate={"endpoint_shape": endpoint, "vuln_class": vuln_class},
            false_positive_reason=fp_reason,
            counter_evidence=[notes] if notes else None,
            kill_signal=kill_signal,
            framework=framework,
            language=language,
            security_control=security_control,
            finding_id=finding_id,
            journal_ts=entry["ts"],
        )
        case_path = write_research_case(case, cases_dir=root / "cases")

    return {"entry": entry, "case_path": str(case_path) if case_path else None}


def log_correction(
    *,
    target: str,
    vuln_class: str,
    endpoint: str,
    initial_hypothesis: str,
    correction: str,
    lesson: str | None = None,
    finding_id: str | None = None,
    memory_dir: str | Path | None = None,
) -> dict:
    finding_id = finding_id or new_finding_id()
    research = make_research_event(
        "user_corrected_agent",
        initial_hypothesis=initial_hypothesis,
        correction=correction,
        lesson=lesson,
        contribution_type="validation_method",
    )
    entry = make_journal_entry(
        target=target,
        action="correct",
        vuln_class=vuln_class,
        endpoint=endpoint,
        result="rejected",
        finding_id=finding_id,
        research=research,
        tags=["correction"],
    )
    HuntJournal(default_journal_path(memory_dir)).append(entry)
    return entry


def log_report_outcome(
    *,
    target: str,
    vuln_class: str,
    endpoint: str,
    report_outcome: str,
    lesson: str | None = None,
    finding_id: str | None = None,
    memory_dir: str | Path | None = None,
) -> dict:
    finding_id = finding_id or new_finding_id()
    research = make_research_event(
        "report_outcome",
        report_outcome=report_outcome,
        lesson=lesson,
        contribution_type="validation_method",
    )
    result = "confirmed" if report_outcome == "accepted" else "informational"
    entry = make_journal_entry(
        target=target,
        action="report",
        vuln_class=vuln_class,
        endpoint=endpoint,
        result=result,
        finding_id=finding_id,
        research=research,
        tags=["report_outcome", report_outcome],
    )
    HuntJournal(default_journal_path(memory_dir)).append(entry)
    return entry
