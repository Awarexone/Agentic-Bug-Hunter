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

## Minimum Required Fields

- target
- vuln_class
- endpoint
- result

## What Gets Written

| Field | journal.jsonl | patterns.jsonl | failed_patterns.jsonl | chains.jsonl | target profile |
|---|---|---|---|---|---|
| Finding details | Always | If confirmed + payout > 0 | If rejected | If confirmed from a detected chain | findings[] updated |
| Tested endpoint | — | — | — | — | tested_endpoints[] updated |
| Tech stack | — | From target profile | From target profile | From target profile | — |

## Why This Matters

- Next time you hunt a target with similar tech stack, your successful patterns are suggested first
- Techniques that already failed here don't get re-suggested — `recon-ranker` hard-kills any endpoint matching a `failed_patterns.jsonl` entry
- `/pickup target.com` shows which endpoints you've tested and which remain
- Cross-target learning: patterns AND confirmed chains from target A inform hunting on target B
