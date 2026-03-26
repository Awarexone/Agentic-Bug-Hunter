"""
Schema validation for hunt memory JSONL entries.

All entries carry schema_version for future migration support.
Validation is strict on required fields, permissive on optional ones.
"""

from datetime import datetime, timezone

CURRENT_SCHEMA_VERSION = 1

# Required fields for each entry type
JOURNAL_REQUIRED = {"ts", "target", "action", "vuln_class", "endpoint", "result", "schema_version"}
JOURNAL_OPTIONAL = {"severity", "payout", "technique", "notes", "tags"}
JOURNAL_ALL = JOURNAL_REQUIRED | JOURNAL_OPTIONAL

PATTERN_REQUIRED = {"ts", "target", "vuln_class", "technique", "tech_stack", "schema_version"}
PATTERN_OPTIONAL = {"endpoint", "payout", "notes", "tags"}
PATTERN_ALL = PATTERN_REQUIRED | PATTERN_OPTIONAL

TARGET_REQUIRED = {"target", "first_hunted", "last_hunted", "schema_version"}
TARGET_OPTIONAL = {
    "tech_stack", "scope_snapshot", "tested_endpoints",
    "untested_endpoints", "findings", "hunt_sessions", "total_time_minutes",
}
TARGET_ALL = TARGET_REQUIRED | TARGET_OPTIONAL

VALID_RESULTS = {"confirmed", "rejected", "partial", "informational"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational", "none"}
VALID_ACTIONS = {"hunt", "recon", "validate", "report", "remember", "resume", "intel"}


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
) -> dict:
    """Create and validate a new journal entry with current timestamp."""
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
) -> dict:
    """Create and validate a new pattern entry with current timestamp."""
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

    return validate_pattern_entry(entry)
