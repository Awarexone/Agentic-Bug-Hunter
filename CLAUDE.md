# Claude Bug Bounty — Plugin Guide

This repo is a Claude Code plugin for professional bug bounty hunting across HackerOne, Bugcrowd, Intigriti, and Immunefi.

## What's Here

### Skills (9 domains — load with `/bug-bounty`, `/web2-recon`, `/token-scan`, etc.)

| Skill | Domain |
|---|---|
| `skills/bug-bounty/` | Master workflow — recon to report, all vuln classes, LLM testing, chains |
| `skills/bb-methodology/` | **Hunting mindset + 5-phase non-linear workflow + tool routing + session discipline** |
| `skills/web2-recon/` | Subdomain enum, live host discovery, URL crawling, nuclei |
| `skills/web2-vuln-classes/` | 18 bug classes with bypass tables (SSRF, open redirect, file upload, Agentic AI) |
| `skills/security-arsenal/` | Payloads, bypass tables, gf patterns, always-rejected list |
| `skills/web3-audit/` | 10 smart contract bug classes, Foundry PoC template, pre-dive kill signals |
| `skills/meme-coin-audit/` | Meme coin rug pull detection, token authority checks, bonding curve exploits, LP attacks |
| `skills/report-writing/` | H1/Bugcrowd/Intigriti/Immunefi report templates, CVSS 3.1, human tone |
| `skills/triage-validation/` | 7-Question Gate, 4 gates, never-submit list, conditionally valid table |

### Commands (14 slash commands)

| Command | Usage |
|---|---|
| `/recon` | `/recon target.com` — full recon pipeline |
| `/hunt` | `/hunt target.com` — start hunting |
| `/validate` | `/validate` — run 7-Question Gate on current finding |
| `/report` | `/report` — write submission-ready report |
| `/chain` | `/chain` — build A→B→C exploit chain |
| `/scope` | `/scope <asset>` — verify asset is in scope |
| `/triage` | `/triage` — quick 7-Question Gate |
| `/web3-audit` | `/web3-audit <contract.sol>` — smart contract audit |
| `/autopilot` | `/autopilot target.com --normal` — autonomous hunt loop |
| `/surface` | `/surface target.com` — ranked attack surface |
| `/resume` | `/resume target.com` — pick up previous hunt |
| `/remember` | `/remember` — log finding to hunt memory |
| `/intel` | `/intel target.com` — fetch CVE + disclosure intel |
| `/token-scan` | `/token-scan <contract>` — meme coin/token rug pull scanner |

### Agents (8 specialized agents)

- `recon-agent` — subdomain enum + live host discovery
- `report-writer` — generates H1/Bugcrowd/Immunefi reports
- `validator` — 4-gate checklist on a finding
- `web3-auditor` — smart contract bug class analysis
- `chain-builder` — builds A→B→C exploit chains
- `autopilot` — autonomous hunt loop (scope→recon→rank→hunt→validate→report)
- `recon-ranker` — attack surface ranking from recon output + memory
- `token-auditor` — fast meme coin/token rug pull and security analysis

### Rules (always active)

- `rules/hunting.md` — 17 critical hunting rules
- `rules/reporting.md` — report quality rules

### Tools (Python/shell — in `tools/`)

- `tools/hunt.py` — master orchestrator
- `tools/recon_engine.sh` — subdomain + URL discovery
- `tools/validate.py` — 4-gate finding validator
- `tools/report_generator.py` — report writer
- `tools/learn.py` — CVE + disclosure intel
- `tools/intel_engine.py` — on-demand intel with memory context
- `tools/scope_checker.py` — deterministic scope safety checker
- `tools/cicd_scanner.sh` — GitHub Actions workflow scanner (sisakulint wrapper, remote scan)
- `tools/token_scanner.py` — automated token red flag scanner (EVM + Solana)

### MCP Integrations (in `mcp/`)

- `mcp/burp-mcp-client/` — Burp Suite proxy integration
- `mcp/hackerone-mcp/` — HackerOne public API (Hacktivity, program stats, policy)

### Hunt Memory (in `memory/`)

- `memory/hunt_journal.py` — append-only hunt log (JSONL)
- `memory/pattern_db.py` — cross-target pattern learning
- `memory/audit_log.py` — request audit log, rate limiter, circuit breaker
- `memory/schemas.py` — schema validation for all data

## Start Here

```bash
claude
# /recon target.com
# /hunt target.com
# /validate   (after finding something)
# /report     (after validation passes)
```

## Install Skills

```bash
chmod +x install.sh && ./install.sh
```

## Critical Rules (Always Active)

1. READ FULL SCOPE before touching any asset
2. NEVER hunt theoretical bugs — "Can attacker do this RIGHT NOW?"
3. Run 7-Question Gate BEFORE writing any report
4. KILL weak findings fast — N/A hurts your validity ratio
5. 5-minute rule — nothing after 5 min = move on
