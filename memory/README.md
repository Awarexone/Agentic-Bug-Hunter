# Memory

Cross-session hunt memory system. Findings and patterns from one target carry forward to the next.

## Modules

| File | Purpose |
|:---|:---|
| `pattern_db.py` | Stores and retrieves cross-target successful vulnerability patterns |
| `vuln_intelligence.py` | Intelligence layer: `FailedPatternDB` (don't-retry list), `ChainDB` (confirmed multi-signal exploit chains), `ReportOutcomeDB` (report acceptance patterns), plus `tech_vuln_affinity()` / `endpoint_shape_stats()` / `priority_score()` (the autopilot decision-engine formula) — live aggregations over patterns + failed_patterns, not separate caches. CLI: `python3 -m memory.vuln_intelligence <cmd>`, used by `vulnerability-intelligence`, `hypothesis-engine`, `recon-ranker`, `autopilot`, and `report-writer` |
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
| `chains.jsonl` | `vulnerability-intelligence` LEARN mode (confirmed chain finding) | `vulnerability-intelligence` BRIEF mode, `recon-ranker`, `hypothesis-engine` |
| `report_outcomes.jsonl` | `/remember --outcome` (report triage result) | `report-writer` (acceptance-rate by vuln class) |
| `audit.jsonl` | `autopilot` (every outbound request) | — |
| `targets/<target>.json` | `/remember` | `/pickup`, `intel_engine.py`, `recon-ranker` |

The lead board (`memory/leads/<target>.jsonl`, written by `tools/lead_board.py`) is a separate, per-target correlation ledger — it's where recon signals get routed to `hunt-*` skills. Two tiers of correlation happen here, live, before anything is confirmed enough to persist to `chains.jsonl`:
- **Chains** (2 signals, e.g. secret+API, IDOR+account-surface, CORS+sensitive-endpoint, upload+processing) — "worth investigating together."
- **Hypotheses** (3+ signals, same host, e.g. leaked secret + live API + weak authorization) — a named vulnerability claim with a declared impact, the strongest signal on the board. `tools/lead_board.py graph <target>` renders the full Asset → Endpoint → Technology → Vulnerability Hypothesis → Impact graph built from both tiers.
