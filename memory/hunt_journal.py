"""
Append-only hunt journal backed by JSONL files.

Uses fcntl.flock() for safe concurrent appends.
Corrupted lines are skipped with a warning, not a crash.
"""

import fcntl
import json
import os
import sys
from pathlib import Path

from memory.schemas import validate_journal_entry, SchemaError


class HuntJournal:
    """Read/write hunt journal entries from a JSONL file."""

    def __init__(self, path: str | Path):
        """
        Args:
            path: Path to the journal.jsonl file. Parent dirs are created if needed.
        """
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, entry: dict) -> None:
        """Validate and append a journal entry. Raises SchemaError on invalid entry, OSError on disk failure."""
        validated = validate_journal_entry(entry)
        line = json.dumps(validated, separators=(",", ":")) + "\n"
        encoded = line.encode("utf-8")

        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                written = os.write(fd, encoded)
                if written != len(encoded):
                    raise OSError(f"Partial write: {written}/{len(encoded)} bytes")
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def read_all(self, *, validate: bool = True) -> list[dict]:
        """Read all journal entries. Corrupted lines are skipped with a warning.

        Args:
            validate: If True, validate each entry against the schema. Invalid entries are skipped.

        Returns:
            List of valid journal entries.
        """
        if not self.path.exists():
            return []

        entries = []
        with open(self.path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    print(
                        f"WARNING: journal line {lineno} is corrupted (skipping): {e}",
                        file=sys.stderr,
                    )
                    continue

                if validate:
                    try:
                        validate_journal_entry(entry)
                    except SchemaError as e:
                        print(
                            f"WARNING: journal line {lineno} failed validation (skipping): {e}",
                            file=sys.stderr,
                        )
                        continue

                entries.append(entry)

        return entries

    def query(self, *, target: str | None = None, vuln_class: str | None = None,
              action: str | None = None, result: str | None = None) -> list[dict]:
        """Query journal entries by field values. All filters are AND-ed."""
        entries = self.read_all()
        if target is not None:
            entries = [e for e in entries if e.get("target") == target]
        if vuln_class is not None:
            entries = [e for e in entries if e.get("vuln_class") == vuln_class]
        if action is not None:
            entries = [e for e in entries if e.get("action") == action]
        if result is not None:
            entries = [e for e in entries if e.get("result") == result]
        return entries
