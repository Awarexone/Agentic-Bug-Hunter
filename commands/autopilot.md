---
description: Run autonomous hunt loop on a target — scope check → recon → rank surface → hunt → validate → report with configurable checkpoints. Usage: /autopilot target.com [--paranoid|--normal|--yolo]
---

# /autopilot

Autonomous hunt loop with deterministic scope safety and configurable checkpoints.

## Usage

```
/autopilot target.com                    # default: --paranoid mode
/autopilot target.com --normal           # batch checkpoint after validation
/autopilot target.com --yolo             # minimal checkpoints (still requires report approval)
/autopilot target.com --quick            # fast surface scan, fewer checks, lower token use
/autopilot targets.txt                   # multiple targets — one domain per line in the file
```

## Session Isolation (Important)

**Start a fresh Claude Code session per target.** Claude accumulates context across a session —
testing multiple targets in one session causes cross-contamination where findings, payloads,
and tech stack assumptions from target A bleed into target B.

Best practice:
```bash
# Terminal 1: target A
claude  →  /autopilot targetA.com

# Terminal 2: target B (separate process)
claude  →  /autopilot targetB.com
```

If you must test multiple targets in one session, run `/pickup target.com` at the start of
each target switch to reload the correct context.

## Token Optimization

Use `--quick` for faster, lower-cost scans (skips deep fuzzing and extended nuclei templates):
```
/autopilot target.com --quick    # ~40% fewer tokens, covers main attack surface
/hunt target.com --vuln-class idor   # single bug class — lowest token use
```

For long hunts, run `/compact` (Claude Code built-in) periodically to compress context
without losing findings.

## What This Does

`/autopilot` is **the same pipeline as running `/scope → /recon → /surface → /hunt → /validate → /report` back-to-back, but driven by one agent loop instead of you re-prompting at each step.** Same scripts. Same outputs. No new capabilities — just less typing and built-in checkpoints.

```
1. SCOPE     Load and confirm program scope                       (≡ /scope)
2. RECON     bash tools/recon_engine.sh <target>                  (≡ /recon, reuses cache if < 7 days old)
3. RANK      Prioritize attack surface (recon-ranker agent)       (≡ /surface)
4. HUNT      python3 tools/hunt.py --target <target> --scan-only  (≡ /hunt)
5. VALIDATE  7-Question Gate on findings                          (≡ /validate)
6. REPORT    Draft reports for validated findings                 (≡ /report — never auto-submits)
7. CHECKPOINT  Present to human for review                        (frequency depends on mode flag)
```

### When to pick `/autopilot` vs running the steps yourself

- **Use the manual chain** (`/recon` → `/hunt` → `/validate` → `/report`) when you want full control between steps, when you're exploring a new bug class, or when you're on a weaker / free model that wanders. You can stop after any phase and inspect output.
- **Use `/autopilot`** when you trust the target surface, want to burn through scope quickly, and only need to look up when something interesting fires. The checkpoint mode controls how often it stops.
- **Output equivalence**: an `/autopilot` run on `target.com` produces the same `recon/<target>/` and `findings/<target>/` directories as running `/recon target.com` then `/hunt target.com` manually.

## Safety Guarantees

- **Every URL** is checked against the scope allowlist before any request
- **Every request** is logged to `hunt-memory/audit.jsonl`
- **Reports are NEVER auto-submitted** — always requires explicit approval
- **PUT/DELETE/PATCH** require human approval in --yolo mode (safe methods only)
- **Circuit breaker** stops hammering if 5 consecutive 403/429/timeout on same host
- **Rate limited** at 1 req/sec (testing) and 10 req/sec (recon)

## Checkpoint Modes

| Mode | When it stops | Best for |
|---|---|---|
| `--paranoid` | Every finding + partial signal | New targets, learning the surface |
| `--normal` | After validation batch | Systematic coverage |
| `--yolo` | After full surface exhausted | Familiar targets, experienced hunters |

## After Autopilot

- Run `/remember` to log successful patterns to hunt memory
- Run `/pickup target.com` next time to pick up where you left off
- Check `hunt-memory/audit.jsonl` for a full request log
