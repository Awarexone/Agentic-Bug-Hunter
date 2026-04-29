"""
Hunt memory system — persistent journal, pattern database, and schema validation.

Runtime data stored at ~/.claude/projects/{project}/hunt-memory/
This package contains the code (read/write/validate), not the data.
"""

from memory.schemas import (
    validate_journal_entry,
    validate_target_profile,
    validate_pattern_entry,
    validate_audit_entry,
)
from memory.pattern_db import PatternDB
from memory.audit_log import AuditLog, RateLimiter, CircuitBreaker
from memory.rotation import (
    DEFAULT_KEEP,
    DEFAULT_MAX_BYTES,
    list_backups,
    purge_backups,
    rotate,
    rotate_if_needed,
    total_bytes,
)

__all__ = [
    "validate_journal_entry",
    "validate_target_profile",
    "validate_pattern_entry",
    "validate_audit_entry",
    "PatternDB",
    "AuditLog",
    "RateLimiter",
    "CircuitBreaker",
    "DEFAULT_KEEP",
    "DEFAULT_MAX_BYTES",
    "list_backups",
    "purge_backups",
    "rotate",
    "rotate_if_needed",
    "total_bytes",
]
