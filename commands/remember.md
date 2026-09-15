---
description: Log current finding or research signal to hunt memory. Auto-fills from /validate output if available. Usage: /remember
---

# /remember

Save a finding or research learning signal to persistent hunt memory (schema v2).

## What This Does

1. Auto-populates fields from session context (target, endpoint, vuln_class, technique)
2. If `/validate` was run in this session, pre-fills from validation output
3. Prompts you to confirm or edit before saving
4. Writes to `journal.jsonl` (always) + `patterns.jsonl` (if confirmed + payout > 0)
5. Updates the target profile's `tested_endpoints` and `findings`
6. For false positives, also writes a local `hunt-memory/cases/<case_id>.json` (never shared by default)

## Usage

```
/remember                         # after finding something
/remember --from-validate         # pull from last /validate
/remember --fp                    # false positive → result=false_positive + research case
/remember --correct               # researcher corrected the agent
/remember --outcome accepted      # report platform outcome (accepted|duplicate|informative|…)
```

## Interactive Flow

```
REMEMBER — Log finding to hunt memory

Target:     target.com (auto-detected)
Endpoint:   /api/v2/users/{id}/orders (from session)
Vuln Class: idor (from session)
Technique:  numeric_id_swap_with_put_method

Result:     [confirmed / rejected / partial / informational / false_positive]?
Severity:   [critical / high / medium / low / none]?
Payout:     $___?
Notes:      ___?
Tags:       [comma-separated]?

# when --fp
FP reason:  middleware_authorization
Kill signal: ownership check in middleware before object fetch

# when --correct
Initial hypothesis: Potential SSRF
Correction:         destination restricted by closed allowlist
Lesson:             do not classify SSRF when allowlist is closed

# when --outcome
Report outcome: [accepted / duplicate / informative / not_applicable / out_of_scope / rejected / pending]

Save to hunt memory? [y/n]
```

## Implementation Notes (for the agent)

Prefer the Python helpers so schema validation + rotation stay consistent:

```bash
# false positive
python3 -c "from tools.research_log import log_false_positive; print(log_false_positive(
  target='TARGET', vuln_class='idor', endpoint='/api/x/{id}',
  fp_reason='middleware_authorization', kill_signal='…', notes='…'))"

# correction
python3 -c "from tools.research_log import log_correction; print(log_correction(
  target='TARGET', vuln_class='ssrf', endpoint='/hooks/preview',
  initial_hypothesis='…', correction='…', lesson='…'))"

# report outcome
python3 -c "from tools.research_log import log_report_outcome; print(log_report_outcome(
  target='TARGET', vuln_class='idor', endpoint='/api/x',
  report_outcome='duplicate', lesson='…'))"
```

Or append via `memory.HuntJournal` + `make_journal_entry` / `make_research_event`.

`share_consent` must stay `false`. Never store cookies, tokens, or raw response bodies.

## Minimum Required Fields

- target
- vuln_class
- endpoint
- result

## What Gets Written

| Field | journal.jsonl | patterns.jsonl | cases/ | target profile |
|---|---|---|---|---|
| Finding details | Always | If confirmed + payout > 0 | If `--fp` | findings[] updated |
| Research event | Optional `research` block | — | provenance | — |
| Tested endpoint | — | — | — | tested_endpoints[] updated |

## Why This Matters

- False positives become reusable kill signals for the validator
- Corrections teach the hunter what not to claim next time
- Report outcomes improve future triage without guessing program decisions
- Cross-target learning still uses patterns from confirmed paid finds
