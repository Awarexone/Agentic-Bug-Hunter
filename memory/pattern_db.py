"""
Pattern database — successful techniques indexed by vuln class + tech stack.

Patterns are stored in a JSONL file, one entry per line.
Matching supports partial tech stack overlap for cross-target learning.
"""

import fcntl
import json
import os
import sys
from pathlib import Path

from memory.rotation import DEFAULT_KEEP, DEFAULT_MAX_BYTES, rotate_if_needed
from memory.schemas import validate_pattern_entry, SchemaError


class PatternDB:
    """Read/write/match successful hunt patterns."""

    def __init__(
        self,
        path: str | Path,
        max_bytes: int = DEFAULT_MAX_BYTES,
        keep_backups: int = DEFAULT_KEEP,
    ):
        """
        Args:
            path: Path to the patterns.jsonl file. Parent dirs are created if needed.
            max_bytes: Rotate the file when it exceeds this size.
            keep_backups: Number of rotated backups to retain.
        """
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.keep_backups = keep_backups

    def save(self, entry: dict) -> bool:
        """Validate and save a pattern entry. Returns True if saved, False if duplicate.

        A duplicate is defined as same target + vuln_class + technique.
        """
        validated = validate_pattern_entry(entry)

        # Check for duplicates
        existing = self.read_all(validate=False)
        for e in existing:
            if (e.get("target") == validated["target"]
                    and e.get("vuln_class") == validated["vuln_class"]
                    and e.get("technique") == validated["technique"]):
                return False

        line = json.dumps(validated, separators=(",", ":")) + "\n"
        encoded = line.encode("utf-8")

        rotate_if_needed(self.path, max_bytes=self.max_bytes, keep=self.keep_backups)

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

        return True

    def read_all(self, *, validate: bool = True) -> list[dict]:
        """Read all pattern entries. Corrupted lines are skipped with a warning."""
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
                        f"WARNING: patterns line {lineno} is corrupted (skipping): {e}",
                        file=sys.stderr,
                    )
                    continue

                if validate:
                    try:
                        validate_pattern_entry(entry)
                    except SchemaError as e:
                        print(
                            f"WARNING: patterns line {lineno} failed validation (skipping): {e}",
                            file=sys.stderr,
                        )
                        continue

                entries.append(entry)

        return entries

    def match(self, *, vuln_class: str | None = None,
              tech_stack: list[str] | None = None) -> list[dict]:
        """Find patterns matching vuln class and/or overlapping tech stack.

        Args:
            vuln_class: Exact match on vuln_class field.
            tech_stack: Partial overlap match — returns patterns where ANY tech in
                        the query overlaps with the pattern's tech_stack.

        Returns:
            Matching patterns sorted by payout (highest first), then recency.
        """
        patterns = self.read_all()

        if vuln_class is not None:
            patterns = [p for p in patterns if p.get("vuln_class") == vuln_class]

        if tech_stack is not None:
            query_set = {t.lower() for t in tech_stack}
            patterns = [
                p for p in patterns
                if query_set & {t.lower() for t in p.get("tech_stack", [])}
            ]

        # Sort: highest payout first, then most recent
        patterns.sort(
            key=lambda p: (p.get("payout", 0), p.get("ts", "")),
            reverse=True,
        )

        return patterns
