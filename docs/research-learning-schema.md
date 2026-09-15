# Research Event Schema (Step 5)

Source of design: contributor intelligence / research-learning inspection.
**Decision:** Extend `memory/schemas.py` to schema **v2**. Research events live as journal extensions (optional `research` object) plus optional local `research_case` fixtures. No second memory store. Community sharing off in v1.

## Principles

| Principle | Implication |
|---|---|
| Reuse hunt memory | Same `journal.jsonl` / `patterns.jsonl` / rotation / GC |
| Strict schemas | Unknown top-level fields rejected; new fields declared |
| Local learning ON | Write events locally by default |
| Community OFF | No share/upload in feature v1 |
| Artifacts ≠ identity | No H1 username / email profiling |
| Gates stay authoritative | Events record 7Q / 4-gate outcomes; they do not decide validity |
| No secrets | Strip cookies, tokens, Authorization, emails, raw bodies |

## Event enum (v1 ship set)

| Event | When | Primary writer |
|---|---|---|
| `candidate_created` | Lead `new` | `lead_board` |
| `finding_investigating` | Lead `investigating` | `lead_board.touch` |
| `finding_validated` | 7Q PASS / `validated_finding` | `/validate`, `/remember` |
| `finding_rejected` | 7Q KILL / 4-gate fail | `/validate`, `/triage` |
| `finding_unverified` | Partial evidence | `/remember` |
| `false_positive_identified` | Researcher marks FP | `/remember --fp` |
| `report_generated` | Report draft written | `/report` |
| `report_outcome` | Platform disposition (user-supplied) | `/remember --outcome` |
| `technique_succeeded` | Confirmed reusable technique | `/remember` + `PatternDB` |
| `technique_failed` | Dead technique | `/remember` |
| `user_corrected_agent` | Researcher corrects agent | `/remember --correct` |
| `contribution_opportunity` | Local preview only | Derived |

Deferred: recon/hunt session spam, payload/rule/framework events, auto PR, scoring, community dataset.

## Schema v2

```text
CURRENT_SCHEMA_VERSION = 2
```

### Enum extensions

- `VALID_ACTIONS` += `correct`, `contribute`
- `VALID_RESULTS` += `false_positive`
- `VALID_RESEARCH_EVENTS` — table above
- `VALID_REPORT_OUTCOMES` = accepted | duplicate | informative | not_applicable | out_of_scope | rejected | pending
- `VALID_CONTRIBUTION_TYPES` (pruned) = false_positive_test | regression_test | validation_method | skill_improvement | new_payload | documentation | bug_fix
- `VALID_GATE_VERDICTS` = pass | kill | downgrade | n/a

### Journal: new optional fields

| Field | Type | Purpose |
|---|---|---|
| `finding_id` | string | Correlate validate → remember → report → outcome |
| `lead_id` | string | Link to lead board |
| `research` | object | Research event payload |

### `research` object

| Field | Required? | Notes |
|---|---|---|
| `event` | yes | One of `VALID_RESEARCH_EVENTS` |
| `gate_verdict` | no | From 7Q / triage |
| `validation_status` | no | `validated_finding` \| `scanner_hit` |
| `report_outcome` | if report_outcome | Platform disposition |
| `fp_reason` | if FP | Slug e.g. `middleware_authorization` |
| `kill_signal` | if FP | Maps to FP issue template |
| `initial_hypothesis` / `correction` / `lesson` | if correction | Technical, not identity |
| `technique_outcome` | if technique_* | succeeded \| failed |
| `framework` / `language` / `security_control` | no | Normalization |
| `contribution_type` | if contrib opp | Pruned enum |
| `contribution_preview_id` | no | Local only |
| `share_consent` | no | Default `false`; writers must keep false in v1 |
| `redacted` | no | Sanitization claim |

## Finding lifecycle (reuse lead board)

Lead board remains the hunt tracker. Journal/`research` is the learning signal.

| Lead status | Research event | Journal result |
|---|---|---|
| new | candidate_created | informational / partial |
| investigating | finding_investigating | partial |
| killed | finding_rejected or false_positive_identified | rejected \| false_positive |
| reported | report_generated (+ later outcome) | confirmed |

## Example — false positive

```json
{
  "ts": "2026-09-15T17:22:01Z",
  "target": "example.com",
  "action": "remember",
  "vuln_class": "idor",
  "endpoint": "/api/project/{id}/export",
  "result": "false_positive",
  "schema_version": 2,
  "finding_id": "fnd-a1b2c3",
  "lead_id": "lb-9f3a21",
  "research": {
    "event": "false_positive_identified",
    "gate_verdict": "kill",
    "fp_reason": "middleware_authorization",
    "kill_signal": "ownership check in middleware before object fetch",
    "framework": "FastAPI",
    "language": "Python",
    "contribution_type": "false_positive_test",
    "share_consent": false,
    "redacted": true
  }
}
```

## `research_case` fixture (local / contributed)

Prefer `hunt-memory/cases/<case_id>.json` locally. Sanitized copies under `tests/fixtures/research_cases/` only when contributing.

Maps to `.github/ISSUE_TEMPLATE/false_positive.md` (flagged → candidate; why → counter_evidence + reason; Kill Signal → kill_signal).

## Hook points

| Hook | Location |
|---|---|
| Schema factories | `memory/schemas.py` |
| Validate persist | `tools/validate.py:write_validation_json` |
| Remember | `commands/remember.md` (+ restore thin journal append helper) |
| Lead lifecycle | `tools/lead_board.py` touch/add/ingest |
| FP regressions | `tests/test_false_positives.py` |
| Rotation / GC | `memory/rotation.py`, `tools/memory_gc.py` |

## Migration v1 → v2

- Readers accept schema_version ∈ {1, 2}
- Writers emit 2
- Offline: `tools/memory_migrate.py` (or later `bughunter memory migrate`) — copy-forward, never delete hunt-memory

## Non-goals (feature v1)

Second memory DB, community share, auto GitHub PR, reputation/rankings, replacing 7Q gate, secrets storage, full product event enum, opportunity scoring, `bughunter update`/`version` (separate workstream).

## Coding sprint (7 tasks)

1. Bump schemas to v2 + tests
2. `false_positive` result + remember flags; thin journal append helper
3. Hook `write_validation_json` → research draft
4. FP case builder → local `research_case`
5. `--correct` / `--outcome` paths
6. Lead board optional `finding_id` mirror
7. `memory_migrate.py` + GC awareness; document local-only defaults

## Open questions

1. `false_positive` as result value, or only `rejected` + research event? (Design: both.)
2. Cases live in `hunt-memory/cases/` vs in-repo fixtures only after contribute?
3. Restore small `memory/hunt_journal.py` append API, or stay prompt-only?
4. Auto-prompt FP vs reject after failed validate, or require explicit `--fp`?
5. Add optional `finding_id` to lead board in same sprint?
6. Hash targets in research_case exports even when local?
7. Bump plugin version when schema v2 ships, or wait for update CLI?
