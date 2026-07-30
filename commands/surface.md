---
description: Show ranked attack surface for a target based on recon output + hunt memory. Invokes js-intelligence, vulnerability-intelligence, hypothesis-engine, then recon-ranker. Usage: /surface target.com
---

# /surface

View the prioritized attack surface for a target.

## What This Does

1. Reads cached recon output from `recon/<target>/`
2. Invokes the `js-intelligence` agent to mine JS bundles/source maps for hidden endpoints, feature flags, debug routes, leaked config, and auth flow details, writing `recon/<target>/js-intelligence.md`
3. Invokes the `vulnerability-intelligence` agent to build `recon/<target>/intelligence-briefing.md` — tech→vuln affinity, known chains matching this tech stack, and a don't-retry list, pulled from `hunt-memory/` (see `memory/vuln_intelligence.py`)
4. Invokes the `hypothesis-engine` agent, which synthesizes recon + js-intelligence + the briefing + the lead board's attack graph (`tools/lead_board.py graph`) into ranked, evidence-backed vulnerability hypotheses, writing `recon/<target>/hypotheses.md`
5. Invokes the `recon-ranker` agent, which scores everything above plus the lead board (`memory/leads/<target>.jsonl`, including any correlation chains/hypotheses `lead_board.py` already detected during `/recon`) to produce a **scored, confidence-rated** ranking
6. Outputs P1 (start here), P2 (after P1), and Kill List (skip) — every entry states the score components behind it, not just a label

Four separate agents on purpose: `js-intelligence` and `vulnerability-intelligence` do the heavier extraction/memory-reasoning work once, up front; `hypothesis-engine` turns that into falsifiable claims; `recon-ranker` stays fast/cheap and just applies the scoring formula using what it's handed. Skip any step whose output already exists and is fresh — this pipeline is meant to run incrementally, not from scratch every time.

## Usage

```
/surface target.com
```

## Prerequisites

Run `/recon target.com` first. If no recon data exists, you'll be prompted to run recon.

## Output

```
ATTACK SURFACE: target.com
═══════════════════════════════════════

Priority 1 (start here):
1. api.target.com/v2/users/{id} — score 78, confidence 65
   Why: IDOR-candidate base (+18) · chain lead: secret+API detected (+25) ·
        tech affinity idor net_score +4 on [express, postgresql] (+8) · feature age 9d (+10)
   Tech: Express + PostgreSQL | First seen 9 days ago
   Suggested: numeric ID swap on GET/PUT/DELETE — chain leg B was `/api/v2/users?id=1001`

2. api.target.com/graphql — score 71, confidence 45 (heuristic — no prior GraphQL data)
   Why: GraphQL base (+25) · non-standard port (+6)
   Suggested: introspection → field-level auth check on sensitive mutations

Priority 2 (after P1):
1. cdn.target.com:8443/upload — score 44, confidence 30
   Why: upload base (+20) · non-standard port (+6) · no chain/memory match
   Suggested: extension bypass, magic bytes

Kill List (skip):
- static.target.com — score 4, CDN only
- api.target.com/webhooks/retry — score −100, KILLED: failed-pattern match
  (ssrf/webhook_url_param already rejected here 2026-03-01: "egress filtered")

Memory:
- Tech-vuln affinity: 3 patterns, 0 failed for [express, postgresql] on this target's stack
- Chain applied: secret_plus_api (confirmed elsewhere, $4000, critical) — same shape matched here
- Hypothesis: account_takeover_via_leaked_secret (hypotheses.md, confidence 78%, impact critical)
- 3 endpoints tested in previous session, 5 remain
```
