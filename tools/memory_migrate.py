#!/usr/bin/env python3
"""
Migrate hunt-memory JSONL files from schema v1 → v2 (copy-forward).

Does not delete data. Writes .bak alongside via rotation helpers when rewriting.

Usage:
    python -m tools.memory_migrate
    python -m tools.memory_migrate --dir hunt-memory --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from memory.schemas import CURRENT_SCHEMA_VERSION, SchemaError, validate_journal_entry  # noqa: E402
from memory.schemas import validate_pattern_entry, validate_audit_entry  # noqa: E402

MIGRATE_FILES = ("journal.jsonl", "patterns.jsonl", "audit.jsonl")


def _upgrade_line(name: str, obj: dict) -> dict:
    if obj.get("schema_version", 1) >= CURRENT_SCHEMA_VERSION:
        return obj
    upgraded = dict(obj)
    upgraded["schema_version"] = CURRENT_SCHEMA_VERSION
    if name == "journal.jsonl":
        return validate_journal_entry(upgraded)
    if name == "patterns.jsonl":
        return validate_pattern_entry(upgraded)
    if name == "audit.jsonl":
        return validate_audit_entry(upgraded)
    return upgraded


def migrate_file(path: Path, dry_run: bool = False) -> tuple[int, int]:
    """Returns (upgraded_count, skipped_count)."""
    if not path.exists():
        return 0, 0
    lines = path.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    upgraded = skipped = 0
    for raw in lines:
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            skipped += 1
            out.append(raw)
            continue
        try:
            before = obj.get("schema_version", 1)
            new_obj = _upgrade_line(path.name, obj)
            if new_obj.get("schema_version") != before:
                upgraded += 1
            out.append(json.dumps(new_obj, ensure_ascii=False, separators=(",", ":")))
        except SchemaError:
            skipped += 1
            out.append(raw)
    if not dry_run and upgraded:
        bak = path.with_suffix(path.suffix + ".pre-v2.bak")
        bak.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        path.write_text("\n".join(out) + ("\n" if out else ""), encoding="utf-8")
    return upgraded, skipped


def main() -> int:
    ap = argparse.ArgumentParser(description="Migrate hunt-memory JSONL to schema v2")
    ap.add_argument("--dir", default="hunt-memory", help="hunt-memory directory")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    root = Path(args.dir)
    if not root.exists():
        print(f"No directory: {root}")
        return 0
    total_u = total_s = 0
    for name in MIGRATE_FILES:
        for path in root.rglob(name):
            u, s = migrate_file(path, dry_run=args.dry_run)
            total_u += u
            total_s += s
            print(f"{path}: upgraded={u} skipped={s}" + (" (dry-run)" if args.dry_run else ""))
    print(f"Done. upgraded={total_u} skipped={total_s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
