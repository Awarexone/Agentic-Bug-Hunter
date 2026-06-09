# Memory

Cross-session hunt memory system. Findings and patterns from one target carry forward to the next.

## Modules

| File | Purpose |
|:---|:---|
| `pattern_db.py` | Stores and retrieves cross-target vulnerability patterns |
| `audit_log.py` | Request audit log, rate limiter, circuit breaker |
| `rotation.py` | JSONL rotation — 10 MB cap, keeps 3 backups, auto-fired on append |
| `schemas.py` | Schema validation for all memory data |

## Storage

Hunt memory is stored as JSONL files in `~/.claude/hunt-memory/`. Managed via `/memory-gc`.
