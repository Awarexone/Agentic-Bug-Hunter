"""
Schema validation for hunt memory JSONL entries.

All entries carry schema_version for future migration support.
Validation is strict on required fields, permissive on optional ones.
"""

import os
from datetime import datetime, timezone

CURRENT_SCHEMA_VERSION = 1

# Required fields for each entry type
JOURNAL_REQUIRED = {"ts", "target", "action", "vuln_class", "endpoint", "result", "schema_version"}
JOURNAL_OPTIONAL = {"severity", "payout", "technique", "notes", "tags", "session_id"}
JOURNAL_ALL = JOURNAL_REQUIRED | JOURNAL_OPTIONAL

PATTERN_REQUIRED = {"ts", "target", "vuln_class", "technique", "tech_stack", "schema_version"}
PATTERN_OPTIONAL = {"endpoint", "payout", "notes", "tags", "session_id"}
PATTERN_ALL = PATTERN_REQUIRED | PATTERN_OPTIONAL

# A technique that was tried and did NOT pan out, keyed the same way as a
# successful pattern (target, vuln_class, technique) so recon-ranker /
# autopilot can look up "have I already tried this here" and skip it.
FAILED_PATTERN_REQUIRED = {"ts", "target", "vuln_class", "technique", "tech_stack", "schema_version"}
FAILED_PATTERN_OPTIONAL = {"endpoint", "reason", "notes", "tags", "session_id"}
FAILED_PATTERN_ALL = FAILED_PATTERN_REQUIRED | FAILED_PATTERN_OPTIONAL

# A confirmed multi-signal exploit chain (A+B -> higher-severity finding),
# persisted so the same chain shape can be recognized on a future target
# with an overlapping tech stack.
CHAIN_REQUIRED = {"ts", "target", "chain_name", "steps", "schema_version"}
CHAIN_OPTIONAL = {"tech_stack", "endpoint", "payout", "severity", "notes", "tags", "session_id"}
CHAIN_ALL = CHAIN_REQUIRED | CHAIN_OPTIONAL

# What happened to a submitted report — the triage/acceptance outcome, kept
# separate from journal.jsonl's pre-submission result so report-writer can
# learn which vuln_class/technique/wording actually gets paid vs N/A'd,
# not just which techniques found something.
REPORT_OUTCOME_REQUIRED = {"ts", "target", "vuln_class", "outcome", "schema_version"}
REPORT_OUTCOME_OPTIONAL = {
    "technique", "platform", "severity", "payout", "report_id", "notes", "tags", "session_id",
}
REPORT_OUTCOME_ALL = REPORT_OUTCOME_REQUIRED | REPORT_OUTCOME_OPTIONAL

# A single test attempt — one payload category tried against one endpoint —
# the granular log beneath patterns.jsonl/failed_patterns.jsonl. Those two
# files record the *outcome* of a target+vuln_class+technique; this records
# every individual attempt along the way, which is what the stop/pivot
# decisions in memory/experiment_memory.py need (patterns.jsonl alone can't
# tell you "3 payload categories tried here with 0 successes").
EXPERIMENT_REQUIRED = {
    "ts", "target", "endpoint", "vuln_class", "payload_category", "result", "schema_version",
}
EXPERIMENT_OPTIONAL = {
    "technique", "tech_stack", "time_spent_minutes", "notes", "tags", "session_id",
}
EXPERIMENT_ALL = EXPERIMENT_REQUIRED | EXPERIMENT_OPTIONAL

# A hypothesis at the moment hypothesis-engine generated it: what it
# predicted (vuln_class, endpoint, a stated confidence 0-100) and why
# (signals). Logged so the prediction can be checked against what actually
# happened later — journal.jsonl / report_outcomes.jsonl have the outcome,
# this has the forecast. Neither file alone can answer "was hypothesis-
# engine's 90%-confidence bucket actually right 90% of the time."
HYPOTHESIS_REQUIRED = {"ts", "target", "vuln_class", "endpoint", "confidence", "schema_version"}
HYPOTHESIS_OPTIONAL = {
    "hypothesis_name", "tech_stack", "signals", "source", "notes", "tags", "session_id",
}
HYPOTHESIS_ALL = HYPOTHESIS_REQUIRED | HYPOTHESIS_OPTIONAL


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

VALID_RESULTS = {"confirmed", "rejected", "partial", "informational"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational", "none"}
VALID_ACTIONS = {"hunt", "recon", "validate", "report", "remember", "resume", "intel"}
VALID_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
VALID_SCOPE_CHECKS = {"pass", "fail", "skip"}
VALID_REPORT_OUTCOMES = {"accepted", "triaged", "duplicate", "informative", "not_applicable", "resolved"}
VALID_EXPERIMENT_RESULTS = {"success", "fail", "inconclusive"}


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


def validate_failed_pattern_entry(entry: dict) -> dict:
    """Validate a failed-pattern entry. Returns the entry if valid, raises SchemaError if not.

    Same shape as a pattern entry (target/vuln_class/technique/tech_stack) plus
    an optional free-text 'reason' the technique didn't work — this is what lets
    recon-ranker / autopilot skip a dead end instead of re-suggesting it.
    """
    if not isinstance(entry, dict):
        raise SchemaError(f"Failed pattern entry must be a dict, got {type(entry).__name__}")

    _check_required(entry, FAILED_PATTERN_REQUIRED, "Failed pattern entry")
    _check_unknown_fields(entry, FAILED_PATTERN_ALL, "Failed pattern entry")
    _check_schema_version(entry)
    _check_timestamp(entry["ts"], "ts")

    if not isinstance(entry["tech_stack"], list) or not all(isinstance(t, str) for t in entry["tech_stack"]):
        raise SchemaError("Failed pattern entry: 'tech_stack' must be a list of strings")

    if not isinstance(entry["technique"], str) or not entry["technique"].strip():
        raise SchemaError("Failed pattern entry: 'technique' must be a non-empty string")

    if "reason" in entry:
        if not isinstance(entry["reason"], str) or not entry["reason"].strip():
            raise SchemaError("Failed pattern entry: 'reason' must be a non-empty string")

    if "session_id" in entry:
        if not isinstance(entry["session_id"], str) or not entry["session_id"].strip():
            raise SchemaError("Failed pattern entry: 'session_id' must be a non-empty string")

    return entry


def validate_chain_entry(entry: dict) -> dict:
    """Validate an attack-chain entry. Returns the entry if valid, raises SchemaError if not.

    'steps' captures the A->B(->C) narrative (e.g. ["exposed .env secret",
    "secret authenticates to internal API", "API returns other tenants' data"])
    so a future hunt on similar tech can recognize and re-run the same chain shape.
    """
    if not isinstance(entry, dict):
        raise SchemaError(f"Chain entry must be a dict, got {type(entry).__name__}")

    _check_required(entry, CHAIN_REQUIRED, "Chain entry")
    _check_unknown_fields(entry, CHAIN_ALL, "Chain entry")
    _check_schema_version(entry)
    _check_timestamp(entry["ts"], "ts")

    if not isinstance(entry["chain_name"], str) or not entry["chain_name"].strip():
        raise SchemaError("Chain entry: 'chain_name' must be a non-empty string")

    if not isinstance(entry["steps"], list) or not all(isinstance(s, str) and s.strip() for s in entry["steps"]):
        raise SchemaError("Chain entry: 'steps' must be a list of non-empty strings")

    if len(entry["steps"]) < 2:
        raise SchemaError("Chain entry: 'steps' must have at least 2 entries to be a chain")

    if "tech_stack" in entry:
        if not isinstance(entry["tech_stack"], list) or not all(isinstance(t, str) for t in entry["tech_stack"]):
            raise SchemaError("Chain entry: 'tech_stack' must be a list of strings")

    if "severity" in entry and entry["severity"] not in VALID_SEVERITIES:
        raise SchemaError(
            f"Chain entry: 'severity' must be one of {sorted(VALID_SEVERITIES)}, got {entry['severity']!r}"
        )

    if "payout" in entry:
        if not isinstance(entry["payout"], (int, float)) or entry["payout"] < 0:
            raise SchemaError(f"Chain entry: 'payout' must be a non-negative number, got {entry['payout']!r}")

    if "session_id" in entry:
        if not isinstance(entry["session_id"], str) or not entry["session_id"].strip():
            raise SchemaError("Chain entry: 'session_id' must be a non-empty string")

    return entry


def validate_report_outcome_entry(entry: dict) -> dict:
    """Validate a report-outcome entry. Returns the entry if valid, raises SchemaError if not.

    Logged once a platform triages/pays/N-A's a submitted report, so
    report-writer can learn which vuln_class + technique + wording actually
    converts to a paid report versus one that gets closed as informative.
    """
    if not isinstance(entry, dict):
        raise SchemaError(f"Report outcome entry must be a dict, got {type(entry).__name__}")

    _check_required(entry, REPORT_OUTCOME_REQUIRED, "Report outcome entry")
    _check_unknown_fields(entry, REPORT_OUTCOME_ALL, "Report outcome entry")
    _check_schema_version(entry)
    _check_timestamp(entry["ts"], "ts")

    if not isinstance(entry["target"], str) or not entry["target"].strip():
        raise SchemaError("Report outcome entry: 'target' must be a non-empty string")

    if not isinstance(entry["vuln_class"], str) or not entry["vuln_class"].strip():
        raise SchemaError("Report outcome entry: 'vuln_class' must be a non-empty string")

    if entry["outcome"] not in VALID_REPORT_OUTCOMES:
        raise SchemaError(
            f"Report outcome entry: 'outcome' must be one of {sorted(VALID_REPORT_OUTCOMES)}, got {entry['outcome']!r}"
        )

    if "severity" in entry and entry["severity"] not in VALID_SEVERITIES:
        raise SchemaError(
            f"Report outcome entry: 'severity' must be one of {sorted(VALID_SEVERITIES)}, got {entry['severity']!r}"
        )

    if "payout" in entry:
        if not isinstance(entry["payout"], (int, float)) or entry["payout"] < 0:
            raise SchemaError(f"Report outcome entry: 'payout' must be a non-negative number, got {entry['payout']!r}")

    if "technique" in entry:
        if not isinstance(entry["technique"], str) or not entry["technique"].strip():
            raise SchemaError("Report outcome entry: 'technique' must be a non-empty string")

    if "session_id" in entry:
        if not isinstance(entry["session_id"], str) or not entry["session_id"].strip():
            raise SchemaError("Report outcome entry: 'session_id' must be a non-empty string")

    return entry


def validate_experiment_entry(entry: dict) -> dict:
    """Validate an experiment entry. Returns the entry if valid, raises SchemaError if not.

    One attempt: a specific payload_category tried against a specific
    endpoint. Not deduplicated on a narrow key — the same combination
    legitimately recurs every time that surface gets re-tested, and each
    attempt is its own data point for should_stop()/suggest_pivot().
    """
    if not isinstance(entry, dict):
        raise SchemaError(f"Experiment entry must be a dict, got {type(entry).__name__}")

    _check_required(entry, EXPERIMENT_REQUIRED, "Experiment entry")
    _check_unknown_fields(entry, EXPERIMENT_ALL, "Experiment entry")
    _check_schema_version(entry)
    _check_timestamp(entry["ts"], "ts")

    if not isinstance(entry["target"], str) or not entry["target"].strip():
        raise SchemaError("Experiment entry: 'target' must be a non-empty string")

    if not isinstance(entry["endpoint"], str) or not entry["endpoint"].strip():
        raise SchemaError("Experiment entry: 'endpoint' must be a non-empty string")

    if not isinstance(entry["vuln_class"], str) or not entry["vuln_class"].strip():
        raise SchemaError("Experiment entry: 'vuln_class' must be a non-empty string")

    if not isinstance(entry["payload_category"], str) or not entry["payload_category"].strip():
        raise SchemaError("Experiment entry: 'payload_category' must be a non-empty string")

    if entry["result"] not in VALID_EXPERIMENT_RESULTS:
        raise SchemaError(
            f"Experiment entry: 'result' must be one of {sorted(VALID_EXPERIMENT_RESULTS)}, got {entry['result']!r}"
        )

    if "tech_stack" in entry:
        if not isinstance(entry["tech_stack"], list) or not all(isinstance(t, str) for t in entry["tech_stack"]):
            raise SchemaError("Experiment entry: 'tech_stack' must be a list of strings")

    if "technique" in entry:
        if not isinstance(entry["technique"], str) or not entry["technique"].strip():
            raise SchemaError("Experiment entry: 'technique' must be a non-empty string")

    if "time_spent_minutes" in entry:
        if not isinstance(entry["time_spent_minutes"], (int, float)) or entry["time_spent_minutes"] < 0:
            raise SchemaError("Experiment entry: 'time_spent_minutes' must be a non-negative number")

    if "tags" in entry:
        if not isinstance(entry["tags"], list) or not all(isinstance(t, str) for t in entry["tags"]):
            raise SchemaError("Experiment entry: 'tags' must be a list of strings")

    if "session_id" in entry:
        if not isinstance(entry["session_id"], str) or not entry["session_id"].strip():
            raise SchemaError("Experiment entry: 'session_id' must be a non-empty string")

    return entry


def validate_hypothesis_entry(entry: dict) -> dict:
    """Validate a hypothesis entry. Returns the entry if valid, raises SchemaError if not.

    Not deduplicated on a narrow key (same reasoning as ReportOutcomeDB /
    ExperimentDB): the same target+vuln_class+endpoint can legitimately be
    re-hypothesized across sessions as new signals accumulate, and each
    generation is its own calibration data point.
    """
    if not isinstance(entry, dict):
        raise SchemaError(f"Hypothesis entry must be a dict, got {type(entry).__name__}")

    _check_required(entry, HYPOTHESIS_REQUIRED, "Hypothesis entry")
    _check_unknown_fields(entry, HYPOTHESIS_ALL, "Hypothesis entry")
    _check_schema_version(entry)
    _check_timestamp(entry["ts"], "ts")

    if not isinstance(entry["target"], str) or not entry["target"].strip():
        raise SchemaError("Hypothesis entry: 'target' must be a non-empty string")

    if not isinstance(entry["vuln_class"], str) or not entry["vuln_class"].strip():
        raise SchemaError("Hypothesis entry: 'vuln_class' must be a non-empty string")

    if not isinstance(entry["endpoint"], str) or not entry["endpoint"].strip():
        raise SchemaError("Hypothesis entry: 'endpoint' must be a non-empty string")

    confidence = entry["confidence"]
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not (0 <= confidence <= 100):
        raise SchemaError(f"Hypothesis entry: 'confidence' must be a number 0-100, got {confidence!r}")

    if "tech_stack" in entry:
        if not isinstance(entry["tech_stack"], list) or not all(isinstance(t, str) for t in entry["tech_stack"]):
            raise SchemaError("Hypothesis entry: 'tech_stack' must be a list of strings")

    if "signals" in entry:
        if not isinstance(entry["signals"], list) or not all(isinstance(s, str) for s in entry["signals"]):
            raise SchemaError("Hypothesis entry: 'signals' must be a list of strings")

    if "hypothesis_name" in entry:
        if not isinstance(entry["hypothesis_name"], str) or not entry["hypothesis_name"].strip():
            raise SchemaError("Hypothesis entry: 'hypothesis_name' must be a non-empty string")

    if "tags" in entry:
        if not isinstance(entry["tags"], list) or not all(isinstance(t, str) for t in entry["tags"]):
            raise SchemaError("Hypothesis entry: 'tags' must be a list of strings")

    if "session_id" in entry:
        if not isinstance(entry["session_id"], str) or not entry["session_id"].strip():
            raise SchemaError("Hypothesis entry: 'session_id' must be a non-empty string")

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


def make_failed_pattern_entry(
    target: str,
    vuln_class: str,
    technique: str,
    tech_stack: list[str],
    endpoint: str | None = None,
    reason: str | None = None,
    notes: str | None = None,
    tags: list[str] | None = None,
    session_id: str | None = None,
) -> dict:
    """Create and validate a new failed-pattern entry with current timestamp.

    Call this when a technique is tried and rejected/killed, so the same
    (target, vuln_class, technique) combination isn't re-suggested later.
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
    if reason is not None:
        entry["reason"] = reason
    if notes is not None:
        entry["notes"] = notes
    if tags is not None:
        entry["tags"] = tags
    if session_id is None:
        session_id = _current_session_id()
    if session_id is not None:
        entry["session_id"] = session_id

    return validate_failed_pattern_entry(entry)


def make_chain_entry(
    target: str,
    chain_name: str,
    steps: list[str],
    tech_stack: list[str] | None = None,
    endpoint: str | None = None,
    payout: int | float | None = None,
    severity: str | None = None,
    notes: str | None = None,
    tags: list[str] | None = None,
    session_id: str | None = None,
) -> dict:
    """Create and validate a new attack-chain entry with current timestamp."""
    entry = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": target,
        "chain_name": chain_name,
        "steps": steps,
        "schema_version": CURRENT_SCHEMA_VERSION,
    }
    if tech_stack is not None:
        entry["tech_stack"] = tech_stack
    if endpoint is not None:
        entry["endpoint"] = endpoint
    if payout is not None:
        entry["payout"] = payout
    if severity is not None:
        entry["severity"] = severity
    if notes is not None:
        entry["notes"] = notes
    if tags is not None:
        entry["tags"] = tags
    if session_id is None:
        session_id = _current_session_id()
    if session_id is not None:
        entry["session_id"] = session_id

    return validate_chain_entry(entry)


def make_report_outcome_entry(
    target: str,
    vuln_class: str,
    outcome: str,
    technique: str | None = None,
    platform: str | None = None,
    severity: str | None = None,
    payout: int | float | None = None,
    report_id: str | None = None,
    notes: str | None = None,
    tags: list[str] | None = None,
    session_id: str | None = None,
) -> dict:
    """Create and validate a new report-outcome entry with current timestamp."""
    entry = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": target,
        "vuln_class": vuln_class,
        "outcome": outcome,
        "schema_version": CURRENT_SCHEMA_VERSION,
    }
    if technique is not None:
        entry["technique"] = technique
    if platform is not None:
        entry["platform"] = platform
    if severity is not None:
        entry["severity"] = severity
    if payout is not None:
        entry["payout"] = payout
    if report_id is not None:
        entry["report_id"] = report_id
    if notes is not None:
        entry["notes"] = notes
    if tags is not None:
        entry["tags"] = tags
    if session_id is None:
        session_id = _current_session_id()
    if session_id is not None:
        entry["session_id"] = session_id

    return validate_report_outcome_entry(entry)


def make_experiment_entry(
    target: str,
    endpoint: str,
    vuln_class: str,
    payload_category: str,
    result: str,
    technique: str | None = None,
    tech_stack: list[str] | None = None,
    time_spent_minutes: int | float | None = None,
    notes: str | None = None,
    tags: list[str] | None = None,
    session_id: str | None = None,
) -> dict:
    """Create and validate a new experiment entry with current timestamp."""
    entry = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": target,
        "endpoint": endpoint,
        "vuln_class": vuln_class,
        "payload_category": payload_category,
        "result": result,
        "schema_version": CURRENT_SCHEMA_VERSION,
    }
    if technique is not None:
        entry["technique"] = technique
    if tech_stack is not None:
        entry["tech_stack"] = tech_stack
    if time_spent_minutes is not None:
        entry["time_spent_minutes"] = time_spent_minutes
    if notes is not None:
        entry["notes"] = notes
    if tags is not None:
        entry["tags"] = tags
    if session_id is None:
        session_id = _current_session_id()
    if session_id is not None:
        entry["session_id"] = session_id

    return validate_experiment_entry(entry)


def make_hypothesis_entry(
    target: str,
    vuln_class: str,
    endpoint: str,
    confidence: int | float,
    hypothesis_name: str | None = None,
    tech_stack: list[str] | None = None,
    signals: list[str] | None = None,
    source: str | None = None,
    notes: str | None = None,
    tags: list[str] | None = None,
    session_id: str | None = None,
) -> dict:
    """Create and validate a new hypothesis entry with current timestamp."""
    entry = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": target,
        "vuln_class": vuln_class,
        "endpoint": endpoint,
        "confidence": confidence,
        "schema_version": CURRENT_SCHEMA_VERSION,
    }
    if hypothesis_name is not None:
        entry["hypothesis_name"] = hypothesis_name
    if tech_stack is not None:
        entry["tech_stack"] = tech_stack
    if signals is not None:
        entry["signals"] = signals
    if source is not None:
        entry["source"] = source
    if notes is not None:
        entry["notes"] = notes
    if tags is not None:
        entry["tags"] = tags
    if session_id is None:
        session_id = _current_session_id()
    if session_id is not None:
        entry["session_id"] = session_id

    return validate_hypothesis_entry(entry)


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
