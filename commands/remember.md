---
description: Log current finding or successful pattern to hunt memory. Auto-fills from /validate output if available. Usage: /remember
---

# /remember

Save a finding or successful pattern to persistent hunt memory.

## What This Does

1. Auto-populates fields from session context (target, endpoint, vuln_class, technique)
2. If `/validate` was run in this session, pre-fills from validation output
3. Prompts you to confirm or edit before saving
4. Writes to `journal.jsonl` (always) + `patterns.jsonl` (if confirmed + payout > 0)
5. Updates the target profile's `tested_endpoints` and `findings`
6. Hands off to the `vulnerability-intelligence` agent's LEARN mode:
   - `result: rejected` → agent runs `python3 -m memory.vuln_intelligence save-failed` so this exact target+technique is never re-suggested by `recon-ranker`/`autopilot` again
   - `result: confirmed` and the finding traces back to a `source: "chain"` lead in `memory/leads/<target>.jsonl` → agent runs `save-chain` so the chain shape is recognized on future targets sharing this tech stack
   - anything else (`partial`, `informational`, or a confirmed finding with no chain) → no additional write, `patterns.jsonl` already has it

## Usage

```
/remember                    # after finding something
/remember --from-validate    # explicitly pull from last /validate
/remember --outcome accepted --report-id H1-12345   # after a platform triages a submitted report
```

## Interactive Flow

```
REMEMBER — Log finding to hunt memory

Target:     target.com (auto-detected)
Endpoint:   /api/v2/users/{id}/orders (from session)
Vuln Class: idor (from session)
Technique:  numeric_id_swap_with_put_method

Result:     [confirmed / rejected / partial / informational]?
Severity:   [critical / high / medium / low]?
Payout:     $___?
Notes:      ___?
Tags:       [comma-separated]?

Save to hunt memory? [y/n]
```

## `--outcome`: Logging a Report's Triage Result

The result you log at finding-time (`confirmed`/`rejected`/...) is your own pre-submission assessment. The platform's actual triage decision comes later and is a separate signal — it's what tells `report-writer` which vuln classes/wording actually convert to paid reports. When a submitted report gets triaged, run:

```
/remember --outcome accepted --report-id H1-12345
```

```
REMEMBER — Report Outcome

Target:      target.com (auto-detected)
Vuln Class:  idor (from session or last /report)
Outcome:     [accepted / triaged / duplicate / informative / not_applicable / resolved]?
Platform:    [hackerone / bugcrowd / intigriti / immunefi]?
Payout:      $___?
Report ID:   ___?

Save to report_outcomes.jsonl? [y/n]
```

This writes to `hunt-memory/report_outcomes.jsonl` via `python3 -m memory.vuln_intelligence save-outcome`. It does not touch `journal.jsonl`/`patterns.jsonl` — those already have the finding itself.

## Minimum Required Fields

- target
- vuln_class
- endpoint
- result

## What Gets Written

| Field | journal.jsonl | patterns.jsonl | failed_patterns.jsonl | chains.jsonl | report_outcomes.jsonl | target profile |
|---|---|---|---|---|---|---|
| Finding details | Always | If confirmed + payout > 0 | If rejected | If confirmed from a detected chain | — | findings[] updated |
| Report triage (`--outcome`) | — | — | — | — | Always | — |
| Tested endpoint | — | — | — | — | — | tested_endpoints[] updated |
| Tech stack | — | From target profile | From target profile | From target profile | — | — |

## Why This Matters

- Next time you hunt a target with similar tech stack, your successful patterns are suggested first
- Techniques that already failed here don't get re-suggested — `recon-ranker` hard-kills any endpoint matching a `failed_patterns.jsonl` entry
- `/pickup target.com` shows which endpoints you've tested and which remain
- Cross-target learning: patterns AND confirmed chains from target A inform hunting on target B
- `report-writer` checks `report_outcomes.jsonl`'s acceptance rate per vuln class before writing, so a class that's been getting closed as `informative` gets a higher evidence bar next time, not the same template
