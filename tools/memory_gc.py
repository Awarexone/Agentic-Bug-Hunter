#!/usr/bin/env python3
"""
Memory GC — inspect and rotate hunt-memory JSONL files.

Scans the hunt-memory directory for append-only logs (audit.jsonl,
patterns.jsonl, journal.jsonl) and reports per-file size + backup usage.
Optionally rotates oversize files or purges existing backups.

Usage:
    python -m tools.memory_gc                       # report only
    python -m tools.memory_gc --dir hunt-memory     # report on a custom dir
    python -m tools.memory_gc --rotate              # force-rotate live files
    python -m tools.memory_gc --rotate --max-mb 5   # rotate above 5 MB
    python -m tools.memory_gc --purge-backups       # delete all .1/.2/.3 files
"""

import argparse
import os
import sys
from pathlib import Path

# Make memory/ importable when running as a script from repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from memory.rotation import (  # noqa: E402
    DEFAULT_KEEP,
    DEFAULT_MAX_BYTES,
    list_backups,
    purge_backups,
    rotate_if_needed,
    total_bytes,
)

# Files we consider rotatable. Anything else in the directory is left alone.
ROTATABLE = ("audit.jsonl", "patterns.jsonl", "journal.jsonl")


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def _find_targets(root: Path) -> list[Path]:
    """Return all rotatable JSONL "live" paths at any depth under root.

    Also includes paths whose live file is gone but rotated backups exist —
    so ``--purge-backups`` can still clean them up.
    """
    if not root.exists():
        return []
    found: set[Path] = set()
    for name in ROTATABLE:
        found.update(root.rglob(name))
        # Match orphaned backups (audit.jsonl.1, audit.jsonl.2, ...) and
        # surface their live path as a target even if the live file is gone.
        for bp in root.rglob(name + ".*"):
            stem = bp.with_suffix("")  # strip the .N suffix
            if stem.name == name:
                found.add(stem)
    return sorted(found)


def report(root: Path, max_bytes: int, keep: int) -> int:
    """Print per-file size report. Returns the number of files over cap."""
    targets = _find_targets(root)
    if not targets:
        print(f"No rotatable files under {root}")
        return 0

    print(f"Scanning {root} (cap: {_human_size(max_bytes)}, keep: {keep})")
    print()
    print(f"{'FILE':<60} {'LIVE':>10} {'TOTAL':>10} {'BACKUPS':>8}  STATUS")
    print("-" * 100)

    over = 0
    for path in targets:
        live = path.stat().st_size if path.exists() else 0
        total = total_bytes(path, keep=keep)
        backups = len(list_backups(path, keep=keep))
        status = "OVER CAP" if live >= max_bytes else "ok"
        if live >= max_bytes:
            over += 1
        rel = path.relative_to(root) if path.is_relative_to(root) else path
        print(
            f"{str(rel):<60} {_human_size(live):>10} "
            f"{_human_size(total):>10} {backups:>8}  {status}"
        )
    return over


def do_rotate(root: Path, max_bytes: int, keep: int) -> int:
    """Rotate every oversize file. Returns the count rotated."""
    rotated = 0
    for path in _find_targets(root):
        if rotate_if_needed(path, max_bytes=max_bytes, keep=keep):
            rotated += 1
            print(f"rotated: {path}")
    return rotated


def do_purge(root: Path, keep: int) -> int:
    """Purge all existing backups. Returns the count removed."""
    removed = 0
    for path in _find_targets(root):
        n = purge_backups(path, keep=keep)
        if n:
            removed += n
            print(f"purged {n} backup(s): {path}")
    return removed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument(
        "--dir", default="hunt-memory",
        help="Hunt memory directory to scan (default: hunt-memory)",
    )
    parser.add_argument(
        "--max-mb", type=float, default=DEFAULT_MAX_BYTES / (1024 * 1024),
        help="Rotate files above this size in megabytes (default: 10)",
    )
    parser.add_argument(
        "--keep", type=int, default=DEFAULT_KEEP,
        help=f"Backups to retain (default: {DEFAULT_KEEP})",
    )
    parser.add_argument("--rotate", action="store_true", help="Rotate oversize files")
    parser.add_argument("--purge-backups", action="store_true", help="Delete all backups")
    args = parser.parse_args(argv)

    root = Path(args.dir).resolve()
    max_bytes = int(args.max_mb * 1024 * 1024)

    over = report(root, max_bytes, args.keep)
    print()

    if args.purge_backups:
        removed = do_purge(root, args.keep)
        print(f"\nPurged {removed} backup file(s).")

    if args.rotate:
        rotated = do_rotate(root, max_bytes, args.keep)
        print(f"\nRotated {rotated} file(s).")
    elif over and not args.purge_backups:
        print(f"{over} file(s) over cap. Re-run with --rotate to rotate them.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
