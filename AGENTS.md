# Bug Bounty Hunter — OpenCode Guide

This project is a professional bug bounty hunting framework for HackerOne, Bugcrowd, Intigriti, and Immunefi.

## Skills (loaded from `.opencode/skills/`)

Read the relevant SKILL.md before starting any task in that domain.

| Directory | Domain |
|---|---|
| `.opencode/skills/bug-bounty/` | Master workflow — recon → triage → exploit → report |
| `.opencode/skills/bb-methodology/` | Hunting mindset, 5-phase non-linear workflow, tool routing |
| `.opencode/skills/web2-recon/` | Subdomain enum, live host discovery, URL crawling, nuclei |
| `.opencode/skills/web2-vuln-classes/` | 18 bug classes with bypass tables (SSRF, open redirect, file upload, Agentic AI) |
| `.opencode/skills/security-arsenal/` | Payloads, bypass tables, gf patterns, always-rejected list |
| `.opencode/skills/web3-audit/` | 10 smart contract bug classes, Foundry PoC template |
| `.opencode/skills/meme-coin-audit/` | Rug pull detection, token authority checks, bonding curve exploits |
| `.opencode/skills/report-writing/` | H1/Bugcrowd/Intigriti/Immunefi report templates, CVSS 3.1 |
| `.opencode/skills/triage-validation/` | 7-Question Gate, 4 gates, never-submit list |

## Commands (loaded from `.opencode/commands/`)

OpenCode uses natural language — say "recon target.com" or "run recon on target.com".

| Command file | What it does |
|---|---|
| `recon` | Full recon pipeline (subfinder → httpx → gau → nuclei) |
| `hunt` | Start hunting a target |
| `validate` | Run 7-Question Gate on current finding |
| `report` | Write submission-ready report |
| `chain` | Build A→B→C exploit chain |
| `scope` | Verify an asset is in scope |
| `scope-aggregate` | Pull every in-scope asset across all platforms |
| `triage` | Quick 7-Question Gate |
| `web3-audit` | Smart contract audit |
| `autopilot` | Autonomous hunt loop (scope→recon→rank→hunt→validate→report) |
| `surface` | Ranked attack surface from recon output |
| `pickup` | Resume a previous hunt session |
| `remember` | Log finding to hunt memory |
| `intel` | Fetch CVE + disclosure intel for a target |
| `token-scan` | Meme coin/token rug pull scanner |
| `memory-gc` | Inspect/rotate hunt-memory JSONL files |
| `secrets-hunt` | Leaked-credential scan (trufflehog/noseyparker/gitleaks) |
| `takeover` | Subdomain takeover candidates |
| `cloud-recon` | Public S3/Azure/GCP + CloudFlare-bypass origin IPs |
| `param-discover` | Find hidden HTTP parameters |
| `bypass-403` | Header/method/encoding bypass tricks against 403/401 |
| `arsenal` | List installed external tools |
| `scan-cves` | Focused nuclei CVE sweep (high/critical) |

## Tools (`tools/`)

Key scripts — run directly or let the commands invoke them:

- `tools/recon_engine.sh` — subdomain + URL discovery
- `tools/vuln_scanner.sh` — XSS/SQLi/SSTI/MFA/SAML probe pipeline
- `tools/validate.py` — 4-gate finding validator
- `tools/scope_checker.py` — deterministic scope safety checker
- `tools/hunt.py` — master orchestrator

## Rules (always active)

1. **READ FULL SCOPE FIRST** — only test assets the program explicitly lists
2. **ONLY REAL BUGS** — ask "Can an attacker do this RIGHT NOW?" — if no, stop
3. **KILL WEAK FINDINGS FAST** — run 7-Question Gate before spending time on a report
4. **NEVER GO OUT OF SCOPE** — one wrong request can get you banned
5. **5-MINUTE RULE** — no progress after 5 minutes? move to the next target
6. **VALIDATE BEFORE REPORT** — always validate before writing
7. **IMPACT FIRST** — start with the bugs that have the worst real-world consequences

## Hunt Memory

Memory files live in `memory/` and auto-rotate at 10 MB. To manually rotate during a long session:

```bash
python3 -m tools.memory_gc --rotate
```

## MCP Proxy Integration

If `opencode.json` has MCP servers configured, use them for live traffic visibility:
- **burp** — read Burp proxy history, replay requests
- **caido** — read Caido proxy history, replay requests, batch requests (up to 50)
- **hackerone** — query HackerOne Hacktivity, program stats, policy (public API, no key needed)

If no proxy MCP is active, fall back to `curl` for HTTP requests and paste request/response manually.

## OpenCode-specific notes

- Invoke commands with natural language: `"recon target.com"`, `"validate this finding"`, `"write a report"`
- Use `@` to mention files inline: `"audit @contracts/Token.sol"`
- Use `@explore` subagent for fast, read-only codebase exploration
- Use `@general` subagent for parallel work units
- Skills reference `TodoWrite`/`Task` — map these to `todowrite` and the `@` mention system
