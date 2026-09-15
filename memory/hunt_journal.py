"""
Hunt journal — append-only research/finding events to journal.jsonl.

Restores a thin writer after HuntJournal was removed, so /remember and
validate hooks can persist schema-validated entries with rotation.
"""

from __future__ import annotations

import fcntl
import json
from pathlib import Path

from memory.rotation import DEFAULT_KEEP, DEFAULT_MAX_BYTES, rotate_if_needed
from memory.schemas import SchemaError, validate_journal_entry


class HuntJournal:
    """Append validated journal entries to a JSONL file."""

    def __init__(
        self,
        path: str | Path,
        max_bytes: int = DEFAULT_MAX_BYTES,
        keep_backups: int = DEFAULT_KEEP,
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.keep_backups = keep_backups

    def append(self, entry: dict) -> dict:
        """Validate and append one journal entry. Returns the validated entry."""
        validated = validate_journal_entry(entry)
        rotate_if_needed(self.path, max_bytes=self.max_bytes, keep=self.keep_backups)
        line = json.dumps(validated, ensure_ascii=False, separators=(",", ":"))
        with open(self.path, "a", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.write(line + "\n")
                f.flush()
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        return validated

    def read_all(self) -> list[dict]:
        """Stream all journal entries (skips corrupt lines)."""
        if not self.path.exists():
            return []
        rows: list[dict] = []
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows


def default_journal_path(memory_dir: str | Path | None = None) -> Path:
    """Resolve journal.jsonl under a hunt-memory directory."""
    root = Path(memory_dir) if memory_dir else Path("hunt-memory")
    return root / "journal.jsonl"


__all__ = ["HuntJournal", "default_journal_path", "SchemaError"]
