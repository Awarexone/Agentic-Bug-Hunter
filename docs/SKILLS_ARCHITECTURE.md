# Skills Architecture

Reference for understanding how the 9 skills, 15 commands, and 8 agents in `claude-bug-bounty` fit together. Read this before changing any skill — the plugin has intentional design that should be preserved.

---

## 1. Design philosophy

**Two orthogonal axes split the surface:**

- **Domain** — `web2` / `web3` / `token` / `report` / `recon`
- **Concern** — `HOW to think` (process) vs `WHAT to hunt` (knowledge) vs `payload` (weapon) vs `validation` (quality gate)

**Three load-time principles:**

1. **Each skill is loadable in isolation** — a hunter can pull `web2-vuln-classes` alone without dragging methodology in; a teacher can pull `bb-methodology` alone without overwhelming detail.
2. **Commands are declarative guides** — they describe the workflow but do not explicitly load skills. Claude reads the description and chooses the right skill implicitly.
3. **Agents are stateful executors with explicit skill bindings** — each agent is the operational counterpart to one skill (see §4).

**v2.0.0 (`a154787`) split a monolithic SKILL into 7 domain skills. v2.1+ (`7b9258a`) added `bb-methodology` to "fill the HOW-to-think gap" — a deliberate separation of process from knowledge.**

---

## 2. Skill responsibility matrix

| Skill | Sole job | Must NOT do |
|---|---|---|
| [bb-methodology](skills/bb-methodology/SKILL.md) | **HOW** — thinking framework, 5-phase non-linear workflow, session discipline, developer psychology | vuln class details, payloads, report templates |
| [bug-bounty](skills/bug-bounty/SKILL.md) | **WHAT (tactical)** — 20 vuln class quick-reference, A→B→C chain patterns, cross-skill routing index | (currently embeds 7-Q Gate + CVSS + always-rejected — see §5 drift) |
| [web2-recon](skills/web2-recon/SKILL.md) | **EXECUTION** — recon pipeline (subfinder, dnsx, httpx, katana, gau, ffuf), continuous monitoring | discuss vuln content |
| [web2-vuln-classes](skills/web2-vuln-classes/SKILL.md) | **KNOWLEDGE** — 20 web2 bug classes with root cause, detection patterns, bypass tables, paid examples | ship payloads (link to security-arsenal) |
| [security-arsenal](skills/security-arsenal/SKILL.md) | **WEAPONS** — payloads, bypass tables, gf patterns, wordlists | explain vuln theory; own always-rejected list (drift — see §5) |
| [triage-validation](skills/triage-validation/SKILL.md) | **QUALITY GATE** — 7-Question Gate, 4 pre-submission gates, always-rejected list, conditionally-valid table | write reports; ship payloads |
| [report-writing](skills/report-writing/SKILL.md) | **OUTPUT** — H1/Bugcrowd/Intigriti/Immunefi templates, CVSS 3.1 + 4.0 (canonical home) | run validation gates |
| [web3-audit](skills/web3-audit/SKILL.md) | **WEB3 KNOWLEDGE** — 10 DeFi bug classes, pre-dive kill signals, Foundry PoC template | touch web2 content |
| [meme-coin-audit](skills/meme-coin-audit/SKILL.md) | **TOKEN AUDIT** — rug pull detection, SPL/Token-2022 risks, bonding curve & LP attacks | touch general DeFi |

---

## 3. Decision tree — which skill should Claude invoke?

```
Starting a new session / lost / "what next?"     → bb-methodology
Recon / asset enumeration / subdomain / fuzzing  → web2-recon
Hunting a specific vuln class deeply             → web2-vuln-classes
Need a payload or bypass technique               → security-arsenal
Found something — is it submittable?             → triage-validation
Validated — time to write the report             → report-writing
Building an A→B→C chain / cross-class tactics    → bug-bounty
Smart contract / DeFi audit                      → web3-audit
Token / meme coin / rug pull check               → meme-coin-audit
```

---

## 4. Command and agent → skill routing

### Commands (15 — all declarative, none explicitly load a skill)

| Command | Implicitly invokes | Notes |
|---|---|---|
| [/recon](commands/recon.md) | self-contained orchestration | calls `recon-agent` if delegating |
| [/hunt](commands/hunt.md) | self-contained methodology guide | |
| [/autopilot](commands/autopilot.md) | self-contained orchestrator | full recon→rank→hunt→validate→report loop |
| [/validate](commands/validate.md) | `triage-validation` | delegates to `validator` agent |
| [/triage](commands/triage.md) | `triage-validation` | 7-Q Gate shorthand |
| [/report](commands/report.md) | `report-writing` | delegates to `report-writer` agent |
| [/chain](commands/chain.md) | `bug-bounty` | A→B chain methodology |
| [/scope](commands/scope.md) | self-contained | scope checker logic |
| [/web3-audit](commands/web3-audit.md) | `web3-audit` | delegates to `web3-auditor` agent |
| [/surface](commands/surface.md) | `bug-bounty` + memory | uses `recon-ranker` agent |
| [/pickup](commands/pickup.md) | self-contained | session/memory loader |
| [/remember](commands/remember.md) | self-contained | auto-memory writer |
| [/intel](commands/intel.md) | `bug-bounty` | CVE + disclosure intel |
| [/token-scan](commands/token-scan.md) | `meme-coin-audit` | delegates to `token-auditor` agent |
| [/memory-gc](commands/memory-gc.md) | self-contained | memory rotation |

### Agents (8 — each binds to one primary skill)

| Agent | Primary skill | Model |
|---|---|---|
| [recon-agent](agents/recon-agent.md) | `web2-recon` | haiku-4-5 |
| [validator](agents/validator.md) | `triage-validation` | sonnet-4-6 |
| [chain-builder](agents/chain-builder.md) | `bug-bounty` | sonnet-4-6 |
| [web3-auditor](agents/web3-auditor.md) | `web3-audit` | sonnet-4-6 |
| [report-writer](agents/report-writer.md) | `report-writing` | opus-4-6 |
| [token-auditor](agents/token-auditor.md) | `meme-coin-audit` | sonnet-4-6 |
| [autopilot](agents/autopilot.md) | (orchestrator — uses scope_checker.py + audit log) | sonnet-4-6 |
| [recon-ranker](agents/recon-ranker.md) | `bug-bounty` + memory | sonnet-4-6 |

**Routing health:** every command and agent has a clear destination. The trigger conflicts identified in §5 happen at the **skill-description level** (Claude picking the wrong skill from a user prompt), not at the routing level.

---

## 5. Known drift — content duplicated without design rationale

These duplications were not authored intentionally and should be resolved in a future round. **Do not fix in this PR — listed here so the next round has evidence to act on.**

| Drift | Locations | Suggested canonical home | Severity |
|---|---|---|---|
| **CVSS 3.1 / 4.0 scoring** | [bug-bounty](skills/bug-bounty/SKILL.md), [bb-methodology](skills/bb-methodology/SKILL.md), [triage-validation](skills/triage-validation/SKILL.md), [report-writing](skills/report-writing/SKILL.md) | `report-writing` | medium — 4 copies drift apart over time |
| **7-Question Gate** | [bug-bounty:1280](skills/bug-bounty/SKILL.md), [triage-validation:14](skills/triage-validation/SKILL.md) | `triage-validation` | high — same gate in 2 places, can give different answers |
| **Always-rejected / NEVER SUBMIT list** | [security-arsenal:735](skills/security-arsenal/SKILL.md), [triage-validation:139](skills/triage-validation/SKILL.md) | `triage-validation` | high — verbatim duplicate |
| **Conditionally-valid-with-chain table** | [security-arsenal](skills/security-arsenal/SKILL.md), [triage-validation](skills/triage-validation/SKILL.md) | `triage-validation` | medium |
| **vuln class summaries (bug-bounty L100-1200)** | [bug-bounty](skills/bug-bounty/SKILL.md) vs [web2-vuln-classes](skills/web2-vuln-classes/SKILL.md) | unclear — needs spike | unknown — could be intentional cheat-sheet or v2.0 oversight |

### Intentional design — DO NOT touch

- **`bug-bounty` (WHAT) ↔ `bb-methodology` (HOW) split** — commit `7b9258a` explicitly created this split. The cross-reference at [bug-bounty:53](skills/bug-bounty/SKILL.md) is the canonical handoff form.
- **Each skill self-contained for isolated load** — small surface duplication (1-2 lines pointing at concepts) is acceptable when the alternative is forcing another skill to load.

---

## 6. Cross-reference convention

When skill A needs to mention skill B's content:

```markdown
> See [skill-b](skills/skill-b/SKILL.md) for the 7-Question Gate.
```

**Rules:**
- One line, no inline copy
- Link to the file, not a vague "see other skill"
- The exception is the existing `bug-bounty ↔ bb-methodology` form at [bug-bounty:53](skills/bug-bounty/SKILL.md) — keep that pattern as the model

---

## 7. Future directions (decision menu for next round)

After reading this document, the next round picks **one** of:

| Direction | Cost | Benefit | When to pick |
|---|---|---|---|
| **A. Drift cleanup** — execute §5 fixes via per-skill PRs | 4 small PRs, ~2-3 hr each | Eliminates the trigger conflicts that confuse Claude's skill selection | If §5 drift is causing wrong skill to be invoked in real usage |
| **B. Single-skill deep-dive** — pick ONE skill (e.g., `web2-vuln-classes` 2024-2025 case refresh, or `security-arsenal` modern payload set, or `bb-methodology` mindset deepening) and 10x it | 1-2 weeks | Maximum leverage on hunt success | If you can name the skill that, when stronger, would most improve real bug bounty wins |
| **C. Knowledge update pipeline** — `/distill` command + `CHANGELOG_skills.md` + skill-creator eval integration | 1 week build, ongoing payoff | Hunt experience auto-feeds skills; no more manual curation drift | If maintenance burden of keeping skills current is the bottleneck |

**Recommended sequencing:** if drift in §5 is biting, do A first (cheap, removes noise). Otherwise B is highest leverage — concentrated improvement to one skill beats diffused polish across nine.

---

## 8. Validation

This document is correct iff:

- [ ] Reader can name each skill's job in 30 seconds after one read-through
- [ ] Reader can locate any of the 4 §5 drift items by line number without re-grepping
- [ ] Decision tree (§3) routes the user's last 5 hunts to the skill they actually used
- [ ] Cross-reference convention (§6) matches the existing [bug-bounty:53](skills/bug-bounty/SKILL.md) form

If any of the above fails, file an issue or update this doc — it is the source of truth for "what each skill is for" and supersedes inline comments inside SKILL.md files.
