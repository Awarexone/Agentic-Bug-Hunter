"""
Schema validation for hunt memory JSONL entries.

All entries carry schema_version for future migration support.
Validation is strict on required fields, permissive on optional ones.
"""

import os
from datetime import datetime, timezone

CURRENT_SCHEMA_VERSION = 2
SUPPORTED_SCHEMA_VERSIONS = frozenset({1, 2})

# Required fields for each entry type
JOURNAL_REQUIRED = {"ts", "target", "action", "vuln_class", "endpoint", "result", "schema_version"}
JOURNAL_OPTIONAL = {
    "severity", "payout", "technique", "notes", "tags", "session_id",
    "finding_id", "lead_id", "research",
}
JOURNAL_ALL = JOURNAL_REQUIRED | JOURNAL_OPTIONAL

PATTERN_REQUIRED = {"ts", "target", "vuln_class", "technique", "tech_stack", "schema_version"}
PATTERN_OPTIONAL = {"endpoint", "payout", "notes", "tags", "session_id"}
PATTERN_ALL = PATTERN_REQUIRED | PATTERN_OPTIONAL


def _current_session_id() -> str | None:
    """Return the BBHUNT_SESSION_ID env var if set (the auth-aware hash).

    Findings logged during an authenticated run inherit the same 12-char hash
    used by audit.jsonl, so journal entries can be correlated with which
    identity discovered them. Anonymous runs leave the field unset.
    """
    sid = os.environ.get("BBHUNT_SESSION_ID")
    return sid if sid else None

TARGET_REQUIRED = {"target", "first_hunted", "last_hunted", "schema_version"}
TARGET_OPTIONAL = {
    "tech_stack", "scope_snapshot", "tested_endpoints",
    "untested_endpoints", "findings", "hunt_sessions", "total_time_minutes",
}
TARGET_ALL = TARGET_REQUIRED | TARGET_OPTIONAL

AUDIT_REQUIRED = {"ts", "url", "method", "scope_check", "schema_version"}
AUDIT_OPTIONAL = {"response_status", "finding_id", "session_id", "error"}
AUDIT_ALL = AUDIT_REQUIRED | AUDIT_OPTIONAL

VALID_RESULTS = {"confirmed", "rejected", "partial", "informational", "false_positive"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational", "none"}
VALID_ACTIONS = {
    "hunt", "recon", "validate", "report", "remember", "resume", "intel",
    "correct", "contribute",
}
VALID_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
VALID_SCOPE_CHECKS = {"pass", "fail", "skip"}

VALID_RESEARCH_EVENTS = {
    "candidate_created",
    "finding_investigating",
    "finding_validated",
    "finding_rejected",
    "finding_unverified",
    "false_positive_identified",
    "report_generated",
    "report_outcome",
    "technique_succeeded",
    "technique_failed",
    "user_corrected_agent",
    "contribution_opportunity",
}
VALID_REPORT_OUTCOMES = {
    "accepted", "duplicate", "informative", "not_applicable",
    "out_of_scope", "rejected", "pending",
}
VALID_CONTRIBUTION_TYPES = {
    "false_positive_test", "regression_test", "validation_method",
    "skill_improvement", "new_payload", "documentation", "bug_fix",
}
VALID_GATE_VERDICTS = {"pass", "kill", "downgrade", "n/a"}
VALID_TECHNIQUE_OUTCOMES = {"succeeded", "failed"}
VALID_VALIDATION_STATUSES = {"validated_finding", "scanner_hit"}

RESEARCH_OPTIONAL = {
    "gate_verdict", "validation_status", "report_outcome", "fp_reason",
    "kill_signal", "initial_hypothesis", "correction", "lesson",
    "technique_outcome", "framework", "language", "security_control",
    "contribution_type", "contribution_preview_id", "share_consent", "redacted",
}
RESEARCH_REQUIRED = {"event"}
RESEARCH_ALL = RESEARCH_REQUIRED | RESEARCH_OPTIONAL


class SchemaError(Exception):
    """Raised when an entry fails schema validation."""
    pass


def _check_required(entry: dict, required: set, entry_type: str) -> None:
    missing = required - set(entry.keys())
    if missing:
        raise SchemaError(f"{entry_type}: missing required fields: {sorted(missing)}")


def _check_unknown_fields(entry: dict, all_fields: set, entry_type: str) -> None:
    unknown = set(entry.keys()) - all_fields
    if unknown:
        raise SchemaError(f"{entry_type}: unknown fields: {sorted(unknown)}")


def _check_timestamp(ts: str, field_name: str) -> None:
    try:
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        raise SchemaError(f"Invalid timestamp in '{field_name}': {ts!r}")


def _check_schema_version(entry: dict) -> None:
    v = entry.get("schema_version")
    if not isinstance(v, int) or v < 1:
        raise SchemaError(f"schema_version must be a positive integer, got: {v!r}")
    if v not in SUPPORTED_SCHEMA_VERSIONS and v > CURRENT_SCHEMA_VERSION:
        raise SchemaError(
            f"schema_version {v} is newer than supported {CURRENT_SCHEMA_VERSION}"
        )


def validate_research_block(research: dict) -> dict:
    """Validate the optional journal ``research`` object (schema v2)."""
    if not isinstance(research, dict):
        raise SchemaError(f"research must be a dict, got {type(research).__name__}")

    _check_required(research, RESEARCH_REQUIRED, "research")
    _check_unknown_fields(research, RESEARCH_ALL, "research")

    if research["event"] not in VALID_RESEARCH_EVENTS:
        raise SchemaError(
            f"research: 'event' must be one of {sorted(VALID_RESEARCH_EVENTS)}, "
            f"got {research['event']!r}"
        )

    event = research["event"]

    if "gate_verdict" in research and research["gate_verdict"] not in VALID_GATE_VERDICTS:
        raise SchemaError(
            f"research: 'gate_verdict' must be one of {sorted(VALID_GATE_VERDICTS)}, "
            f"got {research['gate_verdict']!r}"
        )

    if "validation_status" in research and research["validation_status"] not in VALID_VALIDATION_STATUSES:
        raise SchemaError(
            f"research: 'validation_status' must be one of {sorted(VALID_VALIDATION_STATUSES)}, "
            f"got {research['validation_status']!r}"
        )

    if event == "report_outcome" and "report_outcome" not in research:
        raise SchemaError("research: 'report_outcome' is required when event is report_outcome")

    if "report_outcome" in research and research["report_outcome"] not in VALID_REPORT_OUTCOMES:
        raise SchemaError(
            f"research: 'report_outcome' must be one of {sorted(VALID_REPORT_OUTCOMES)}, "
            f"got {research['report_outcome']!r}"
        )

    if event == "false_positive_identified" and "fp_reason" not in research:
        raise SchemaError("research: 'fp_reason' is required when event is false_positive_identified")

    if event == "user_corrected_agent":
        for field in ("initial_hypothesis", "correction"):
            if field not in research or not str(research[field]).strip():
                raise SchemaError(
                    f"research: '{field}' is required when event is user_corrected_agent"
                )

    if "technique_outcome" in research and research["technique_outcome"] not in VALID_TECHNIQUE_OUTCOMES:
        raise SchemaError(
            f"research: 'technique_outcome' must be one of {sorted(VALID_TECHNIQUE_OUTCOMES)}, "
            f"got {research['technique_outcome']!r}"
        )

    if "contribution_type" in research and research["contribution_type"] not in VALID_CONTRIBUTION_TYPES:
        raise SchemaError(
            f"research: 'contribution_type' must be one of {sorted(VALID_CONTRIBUTION_TYPES)}, "
            f"got {research['contribution_type']!r}"
        )

    if "share_consent" in research:
        if not isinstance(research["share_consent"], bool):
            raise SchemaError("research: 'share_consent' must be a boolean")
        # v1 writers must keep community sharing off
        if research["share_consent"] is True:
            raise SchemaError(
                "research: share_consent=true is not allowed yet "
                "(community learning is opt-in and not implemented)"
            )

    if "redacted" in research and not isinstance(research["redacted"], bool):
        raise SchemaError("research: 'redacted' must be a boolean")

    for text_field in (
        "fp_reason", "kill_signal", "initial_hypothesis", "correction", "lesson",
        "framework", "language", "security_control", "contribution_preview_id",
    ):
        if text_field in research:
            if not isinstance(research[text_field], str) or not research[text_field].strip():
                raise SchemaError(f"research: '{text_field}' must be a non-empty string")

    return research


def make_research_event(
    event: str,
    *,
    gate_verdict: str | None = None,
    validation_status: str | None = None,
    report_outcome: str | None = None,
    fp_reason: str | None = None,
    kill_signal: str | None = None,
    initial_hypothesis: str | None = None,
    correction: str | None = None,
    lesson: str | None = None,
    technique_outcome: str | None = None,
    framework: str | None = None,
    language: str | None = None,
    security_control: str | None = None,
    contribution_type: str | None = None,
    contribution_preview_id: str | None = None,
    share_consent: bool = False,
    redacted: bool = True,
) -> dict:
    """Build and validate a research block. share_consent defaults to False."""
    research: dict = {"event": event, "share_consent": share_consent, "redacted": redacted}
    optional = {
        "gate_verdict": gate_verdict,
        "validation_status": validation_status,
        "report_outcome": report_outcome,
        "fp_reason": fp_reason,
        "kill_signal": kill_signal,
        "initial_hypothesis": initial_hypothesis,
        "correction": correction,
        "lesson": lesson,
        "technique_outcome": technique_outcome,
        "framework": framework,
        "language": language,
        "security_control": security_control,
        "contribution_type": contribution_type,
        "contribution_preview_id": contribution_preview_id,
    }
    for key, value in optional.items():
        if value is not None:
            research[key] = value
    return validate_research_block(research)


def validate_journal_entry(entry: dict) -> dict:
    """Validate a journal entry. Returns the entry if valid, raises SchemaError if not."""
    if not isinstance(entry, dict):
        raise SchemaError(f"Journal entry must be a dict, got {type(entry).__name__}")

    _check_required(entry, JOURNAL_REQUIRED, "Journal entry")
    _check_unknown_fields(entry, JOURNAL_ALL, "Journal entry")
    _check_schema_version(entry)
    _check_timestamp(entry["ts"], "ts")

    if not isinstance(entry["target"], str) or not entry["target"].strip():
        raise SchemaError("Journal entry: 'target' must be a non-empty string")

    if entry["result"] not in VALID_RESULTS:
        raise SchemaError(
            f"Journal entry: 'result' must be one of {sorted(VALID_RESULTS)}, got {entry['result']!r}"
        )

    if "severity" in entry and entry["severity"] not in VALID_SEVERITIES:
        raise SchemaError(
            f"Journal entry: 'severity' must be one of {sorted(VALID_SEVERITIES)}, got {entry['severity']!r}"
        )

    if entry["action"] not in VALID_ACTIONS:
        raise SchemaError(
            f"Journal entry: 'action' must be one of {sorted(VALID_ACTIONS)}, got {entry['action']!r}"
        )

    if "payout" in entry:
        if not isinstance(entry["payout"], (int, float)) or entry["payout"] < 0:
            raise SchemaError(f"Journal entry: 'payout' must be a non-negative number, got {entry['payout']!r}")

    if "tags" in entry:
        if not isinstance(entry["tags"], list) or not all(isinstance(t, str) for t in entry["tags"]):
            raise SchemaError("Journal entry: 'tags' must be a list of strings")

    if "session_id" in entry:
        if not isinstance(entry["session_id"], str) or not entry["session_id"].strip():
            raise SchemaError("Journal entry: 'session_id' must be a non-empty string")

    for id_field in ("finding_id", "lead_id"):
        if id_field in entry:
            if not isinstance(entry[id_field], str) or not entry[id_field].strip():
                raise SchemaError(f"Journal entry: '{id_field}' must be a non-empty string")

    if "research" in entry:
        validate_research_block(entry["research"])

    return entry


def validate_pattern_entry(entry: dict) -> dict:
    """Validate a pattern entry. Returns the entry if valid, raises SchemaError if not."""
    if not isinstance(entry, dict):
        raise SchemaError(f"Pattern entry must be a dict, got {type(entry).__name__}")

    _check_required(entry, PATTERN_REQUIRED, "Pattern entry")
    _check_unknown_fields(entry, PATTERN_ALL, "Pattern entry")
    _check_schema_version(entry)
    _check_timestamp(entry["ts"], "ts")

    if not isinstance(entry["tech_stack"], list) or not all(isinstance(t, str) for t in entry["tech_stack"]):
        raise SchemaError("Pattern entry: 'tech_stack' must be a list of strings")

    if not isinstance(entry["technique"], str) or not entry["technique"].strip():
        raise SchemaError("Pattern entry: 'technique' must be a non-empty string")

    if "session_id" in entry:
        if not isinstance(entry["session_id"], str) or not entry["session_id"].strip():
            raise SchemaError("Pattern entry: 'session_id' must be a non-empty string")

    return entry


def validate_target_profile(profile: dict) -> dict:
    """Validate a target profile. Returns the profile if valid, raises SchemaError if not."""
    if not isinstance(profile, dict):
        raise SchemaError(f"Target profile must be a dict, got {type(profile).__name__}")

    _check_required(profile, TARGET_REQUIRED, "Target profile")
    _check_unknown_fields(profile, TARGET_ALL, "Target profile")
    _check_schema_version(profile)
    _check_timestamp(profile["first_hunted"], "first_hunted")
    _check_timestamp(profile["last_hunted"], "last_hunted")

    if not isinstance(profile["target"], str) or not profile["target"].strip():
        raise SchemaError("Target profile: 'target' must be a non-empty string")

    if "tech_stack" in profile:
        if not isinstance(profile["tech_stack"], list):
            raise SchemaError("Target profile: 'tech_stack' must be a list")

    if "hunt_sessions" in profile:
        if not isinstance(profile["hunt_sessions"], int) or profile["hunt_sessions"] < 0:
            raise SchemaError("Target profile: 'hunt_sessions' must be a non-negative integer")

    if "total_time_minutes" in profile:
        if not isinstance(profile["total_time_minutes"], (int, float)) or profile["total_time_minutes"] < 0:
            raise SchemaError("Target profile: 'total_time_minutes' must be a non-negative number")

    return profile


def make_journal_entry(
    target: str,
    action: str,
    vuln_class: str,
    endpoint: str,
    result: str,
    severity: str | None = None,
    payout: int | float | None = None,
    technique: str | None = None,
    notes: str | None = None,
    tags: list[str] | None = None,
    session_id: str | None = None,
    finding_id: str | None = None,
    lead_id: str | None = None,
    research: dict | None = None,
) -> dict:
    """Create and validate a new journal entry with current timestamp.

    If session_id is None, falls back to BBHUNT_SESSION_ID env var so
    findings made under an auth-aware hunt automatically carry the same
    identity hash that audit.jsonl uses.
    """
    entry = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": target,
        "action": action,
        "vuln_class": vuln_class,
        "endpoint": endpoint,
        "result": result,
        "schema_version": CURRENT_SCHEMA_VERSION,
    }
    if severity is not None:
        entry["severity"] = severity
    if payout is not None:
        entry["payout"] = payout
    if technique is not None:
        entry["technique"] = technique
    if notes is not None:
        entry["notes"] = notes
    if tags is not None:
        entry["tags"] = tags
    if finding_id is not None:
        entry["finding_id"] = finding_id
    if lead_id is not None:
        entry["lead_id"] = lead_id
    if research is not None:
        entry["research"] = validate_research_block(dict(research))
    if session_id is None:
        session_id = _current_session_id()
    if session_id is not None:
        entry["session_id"] = session_id

    return validate_journal_entry(entry)


def make_pattern_entry(
    target: str,
    vuln_class: str,
    technique: str,
    tech_stack: list[str],
    endpoint: str | None = None,
    payout: int | float | None = None,
    notes: str | None = None,
    tags: list[str] | None = None,
    session_id: str | None = None,
) -> dict:
    """Create and validate a new pattern entry with current timestamp.

    If session_id is None, falls back to BBHUNT_SESSION_ID env var so
    patterns discovered under an auth-aware hunt record which identity
    surfaced the technique (important for IDOR / BOLA-class patterns).
    """
    entry = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": target,
        "vuln_class": vuln_class,
        "technique": technique,
        "tech_stack": tech_stack,
        "schema_version": CURRENT_SCHEMA_VERSION,
    }
    if endpoint is not None:
        entry["endpoint"] = endpoint
    if payout is not None:
        entry["payout"] = payout
    if notes is not None:
        entry["notes"] = notes
    if tags is not None:
        entry["tags"] = tags
    if session_id is None:
        session_id = _current_session_id()
    if session_id is not None:
        entry["session_id"] = session_id

    return validate_pattern_entry(entry)


def validate_audit_entry(entry: dict) -> dict:
    """Validate an audit log entry. Returns the entry if valid, raises SchemaError if not."""
    if not isinstance(entry, dict):
        raise SchemaError(f"Audit entry must be a dict, got {type(entry).__name__}")

    _check_required(entry, AUDIT_REQUIRED, "Audit entry")
    _check_unknown_fields(entry, AUDIT_ALL, "Audit entry")
    _check_schema_version(entry)
    _check_timestamp(entry["ts"], "ts")

    if not isinstance(entry["url"], str) or not entry["url"].strip():
        raise SchemaError("Audit entry: 'url' must be a non-empty string")

    if entry["method"] not in VALID_METHODS:
        raise SchemaError(
            f"Audit entry: 'method' must be one of {sorted(VALID_METHODS)}, got {entry['method']!r}"
        )

    if entry["scope_check"] not in VALID_SCOPE_CHECKS:
        raise SchemaError(
            f"Audit entry: 'scope_check' must be one of {sorted(VALID_SCOPE_CHECKS)}, got {entry['scope_check']!r}"
        )

    if "response_status" in entry:
        if not isinstance(entry["response_status"], int):
            raise SchemaError("Audit entry: 'response_status' must be an integer")

    return entry


def make_session_summary_entry(
    target: str,
    action: str,
    endpoints_tested: list[str],
    vuln_classes_tried: list[str],
    findings_count: int,
    session_id: str | None = None,
) -> dict:
    """Create a journal entry summarising a completed hunt or autopilot session.

    Written automatically at session end so memory populates without requiring
    a manual /remember call.  action should be 'hunt' for interactive sessions
    or 'hunt' for autopilot (both map to the hunt action type).
    """
    tested_str = ", ".join(endpoints_tested) if endpoints_tested else "none"
    classes_str = ", ".join(vuln_classes_tried) if vuln_classes_tried else "none"
    notes = (
        f"Auto-logged session summary. "
        f"Endpoints tested: {len(endpoints_tested)}. "
        f"Vuln classes tried: {classes_str}. "
        f"Findings: {findings_count}."
    )
    if session_id:
        notes += f" Session: {session_id}."

    tags = ["auto_logged", "session_summary"]
    if findings_count > 0:
        tags.append("has_findings")

    entry = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": target,
        "action": action if action in VALID_ACTIONS else "hunt",
        "vuln_class": "session_summary",
        "endpoint": tested_str[:200] if tested_str else "session",
        "result": "informational",
        "notes": notes,
        "tags": tags,
        "schema_version": CURRENT_SCHEMA_VERSION,
    }
    # Stamp with the auth session_id if the run was authenticated. The
    # function's existing session_id param is a *display label* (e.g.
    # "autopilot-2026-03-24-001") — keep that semantic but also attach the
    # auth-session hash as a separate optional field on the entry for
    # cross-correlation with audit.jsonl.
    auth_sid = _current_session_id()
    if auth_sid is not None:
        entry["session_id"] = auth_sid
    return validate_journal_entry(entry)


def make_audit_entry(
    url: str,
    method: str,
    scope_check: str,
    response_status: int | None = None,
    finding_id: str | None = None,
    session_id: str | None = None,
    error: str | None = None,
) -> dict:
    """Create and validate a new audit log entry with current timestamp."""
    entry = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "url": url,
        "method": method,
        "scope_check": scope_check,
        "schema_version": CURRENT_SCHEMA_VERSION,
    }
    if response_status is not None:
        entry["response_status"] = response_status
    if finding_id is not None:
        entry["finding_id"] = finding_id
    if session_id is not None:
        entry["session_id"] = session_id
    if error is not None:
        entry["error"] = error

    return validate_audit_entry(entry)
