# Memory

Cross-session hunt memory system. Findings and patterns from one target carry forward to the next.

## Modules

| File | Purpose |
|:---|:---|
| `pattern_db.py` | Stores and retrieves cross-target successful vulnerability patterns |
| `vuln_intelligence.py` | Intelligence layer: `FailedPatternDB` (don't-retry list), `ChainDB` (confirmed multi-signal exploit chains), plus `tech_vuln_affinity()` / `endpoint_shape_stats()` — live aggregations over patterns + failed_patterns, not separate caches. CLI: `python3 -m memory.vuln_intelligence <cmd>`, used by the `vulnerability-intelligence` and `recon-ranker` agents |
| `audit_log.py` | Request audit log, rate limiter, circuit breaker |
| `rotation.py` | JSONL rotation — 10 MB cap, keeps 3 backups, auto-fired on append |
| `schemas.py` | Schema validation for all memory data (journal, pattern, failed_pattern, chain, target profile, audit entries) |

## Storage

Hunt memory is stored as JSONL files in `hunt-memory/` (see `~/.claude/hunt-memory/` for the global default). Managed via `/memory-gc`.

| File | Written by | Read by |
|:---|:---|:---|
| `journal.jsonl` | `/remember` (always) | `/pickup`, `intel_engine.py` |
| `patterns.jsonl` | `/remember` (confirmed + payout > 0) | `recon-ranker`, `vulnerability-intelligence`, `/pickup` |
| `failed_patterns.jsonl` | `vulnerability-intelligence` LEARN mode (result: rejected) | `recon-ranker` (hard-kill dead ends), `autopilot` |
| `chains.jsonl` | `vulnerability-intelligence` LEARN mode (confirmed chain finding) | `vulnerability-intelligence` BRIEF mode, `recon-ranker` |
| `audit.jsonl` | `autopilot` (every outbound request) | — |
| `targets/<target>.json` | `/remember` | `/pickup`, `intel_engine.py`, `recon-ranker` |

The lead board (`memory/leads/<target>.jsonl`, written by `tools/lead_board.py`) is a separate, per-target correlation ledger — it's where recon signals get routed to `hunt-*` skills and where cross-signal chains (secret+API, IDOR+account-surface, CORS+sensitive-endpoint, upload+processing) are detected in real time, before any of them are confirmed enough to persist to `chains.jsonl`.
