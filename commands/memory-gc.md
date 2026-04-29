---
description: Inspect or rotate hunt-memory JSONL files (audit.jsonl, patterns.jsonl, journal.jsonl). Caps file size and keeps N rotated backups so memory does not grow unbounded.
---

# /memory-gc

Garbage-collect the hunt-memory directory. Reports current sizes, rotates oversized files past a configurable cap, or purges old backups.

## Why This Exists

Append-only logs grow without bound. On active hunters:
- `audit.jsonl` can reach 100 MB+ in months (every outbound request)
- `patterns.jsonl` and `journal.jsonl` accumulate forever

This command surfaces that growth and gives you a one-shot fix.

## Usage

```
/memory-gc                       # report only
/memory-gc --rotate              # rotate files above 10 MB (default cap)
/memory-gc --rotate --max-mb 5   # custom cap
/memory-gc --purge-backups       # delete all .1/.2/.3 backups
/memory-gc --dir <path>          # scan a non-default hunt-memory dir
```

## What It Does

1. Walks the hunt-memory directory recursively.
2. Finds `audit.jsonl`, `patterns.jsonl`, and `journal.jsonl` files at any depth.
3. Prints a per-file table: live size, total (live + backups), backup count, status.
4. With `--rotate`: renames oversize files to `<file>.1`, shifting older backups up to `<file>.{keep}`. The oldest is dropped.
5. With `--purge-backups`: removes every `.1`/`.2`/`.3` backup, keeping only live files.

## Implementation

The agent shells out to:

```bash
python -m tools.memory_gc [args]
```

from the repo root.

## Defaults

- **Rotation cap:** 10 MB per file
- **Backups kept:** 3 (so `<file>.1` newest → `<file>.3` oldest)
- **Scope:** `hunt-memory/` and any nested target dirs

Auto-rotation also fires inside `AuditLog.log()` and `PatternDB.save()` whenever a write would push the file past the cap, so this command is mainly for reporting and one-shot cleanup.
