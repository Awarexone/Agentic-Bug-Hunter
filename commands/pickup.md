---
description: Pick up a previous hunt on a target — shows hunt history, untested endpoints, and memory-informed suggestions. Usage: /pickup target.com
---

# /pickup

Pick up where you left off on a target.

> **Renamed from `/resume`** — `/resume` is a reserved Claude Code command. Use `/pickup` to continue a previous hunt.

## What This Does

1. Reads the target profile from `hunt-memory/targets/<target>.json`
2. Shows hunt history (sessions, findings, payouts)
3. Lists untested endpoints from last recon
4. Suggests techniques based on tech stack + pattern DB
5. Asks: continue hunting or re-run recon?

## Usage

```
/pickup target.com
```

## Output

```
PICKUP: target.com
═══════════════════════════════════════

Hunt History:
  Sessions:    3
  Last hunt:   2026-03-24
  Total time:  2h 00m
  Findings:    1 confirmed (IDOR, $1500 paid)

Untested Surface:
  3 endpoints from last recon:
  1. /api/v2/users/{id}/export
  2. /api/v2/users/{id}/share
  3. /api/v2/users/{id}/history

Memory Suggestions:
  Tech stack [Next.js, GraphQL, PostgreSQL] matches 2 targets
  where you found auth bypass. Try introspection → mutation pattern.

Actions:
  [r] Continue hunting untested endpoints
  [n] Re-run recon first (surface may have changed)
  [s] Show full hunt journal for this target
```

## If No Previous Hunt

```
No previous hunt data for target.com.
Run /recon target.com first, then /hunt target.com.
```
