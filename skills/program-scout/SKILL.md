---
name: program-scout
description: Use when starting a new hunting session, looking for high-value bug bounty targets, building a hunting backlog, or asking "what should I hunt next?" Queries public program databases (HackerOne, Bugcrowd, Intigriti, Immunefi), scores programs by bounty potential and attack surface, and generates deployment-ready plans. Works with the program-scout agent. Only operates on publicly available program metadata — never probes targets directly.
---

# Program Scout Skill

Discover high-value active bug bounty programs and generate deployment plans for the Hunter agent pipeline.

## When to Use

- Starting a fresh hunting session with no target in mind
- Building a prioritized backlog of targets
- Evaluating whether a specific program is worth the time investment
- Generating deployment plans that feed directly into `/recon` → `/hunt` pipeline

## Workflow

```
1. DISCOVER  → Query public APIs for programs matching your criteria
2. FILTER    → Remove paused, private, low-bounty programs
3. SCORE     → Apply 0-40 scoring algorithm
4. PLAN      → Generate deployment plan for top candidates
5. DELIVER   → Output to deployment/<program>/plan.md
```

## Data Sources

### HackerOne (GraphQL)

```bash
# Program scope
curl -s "https://hackerone.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { team(handle: \"HANDLE\") { name url policy_scopes(archived: false) { edges { node { asset_type asset_identifier eligible_for_bounty } } } } }"}'

# Disclosed reports (intel)
curl -s "https://hackerone.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ hacktivity_items(first:25, order_by:{field:popular, direction:DESC}, where:{team:{handle:{_eq:\"HANDLE\"}}}) { nodes { ... on HacktivityDocument { report { title severity_rating } } } } }"}'
```

### Bugcrowd

```bash
curl -s "https://bugcrowd.com/programs.json" \
  | jq '.programs[] | select(.status == "open")'
```

### Intigriti

```bash
curl -s "https://app.intigriti.com/api/programs" \
  | jq '.[] | select(.status == "Active")'
```

### Immunefi

```bash
curl -s "https://immunefi.com/api/v1/programs" \
  | jq '.[] | select(.bountyRange.maximum > 0)'
```

### Cross-Platform Scope Aggregation

```bash
# Uses bounty-targets-data (no auth, hourly public dump)
tools/scope_aggregator.sh <program> --platform all
```

## Scoring Algorithm

| Factor | Weight | Calculation |
|--------|--------|-------------|
| Bounty Range | 30% | `min(max_bounty / 1000, 10)` |
| Attack Surface | 20% | `min(in_scope_assets / 5, 10)` |
| Average Payout (90d) | 30% | `min(avg_payout / 500, 10)` |
| Recent Activity (30d) | 20% | `min(reports_resolved / 10, 10)` |

| Score | Rating | Action |
|-------|--------|--------|
| 30-40 | HOT | Start immediately |
| 20-29 | WARM | Allocate 1-2 sessions |
| 10-19 | COOL | Only if specific expertise |
| 0-9 | SKIP | Not worth time |

## Deployment Plan Template

After scoring, output a deployment plan:

```markdown
# Deployment Plan: <program>

**Scout Score:** <N>/40 (<rating>)
**Platform:** <platform>

## Program Overview
- URL: <program page>
- Bounty: $<min> — $<max>
- Avg Payout (90d): $<amount>

## In-Scope Assets
<all in-scope domains, APIs, apps>

## Out of Scope (NEVER TEST)
<all exclusions>

## Crown Jewels
1. <what hurts the org most>
2. <second priority>

## Recommended Vuln Classes
Based on disclosed reports and tech stack:
- <class> — <evidence>

## Attack Plan
1. `/scope <asset>` — verify all assets
2. `/recon <domain>` — discover full surface
3. `/surface <domain>` — rank attack surface
4. `/hunt <domain>` — test highest-priority targets
5. `/validate` — gate every finding
6. `/report` — platform-specific reports

## Security Checklist
- [ ] Full program policy read
- [ ] All assets verified via `/scope`
- [ ] Safe harbor confirmed
- [ ] Two test accounts set up (if needed)
- [ ] Rate limits noted
- [ ] Disclosed reports reviewed for prior art
```

## Integration

```
/scope-aggregate <program>    → get all in-scope assets
    ↓
Program Scout                 → score and rank programs
    ↓
deployment/<program>/plan.md  → human reviews and confirms
    ↓
/recon <primary_domain>       → begin hunting pipeline
```

## Rules

1. **READ-ONLY on targets** — never probe, scan, or test target infrastructure
2. **Public data only** — use public APIs and program pages
3. **Cache results** — program data cached for 24 hours
4. **Respect rate limits** — max 1 req/sec to any platform API
5. **Always verify currency** — cached data must be < 24 hours old
