# Bug Bounty Agent Toolkit — Plugin Guide

This repo is an agent-portable bug bounty plugin for professional hunting across HackerOne, Bugcrowd, Intigriti, and Immunefi. It supports Claude Code, OpenCode, Pi Agent, Codex-style Agent Skills, and shared `.agents/skills` harnesses.

## What's Here

### Skills (13 domains — load with `/bug-bounty`, `/web2-recon`, `/token-scan`, etc.)

| Skill | Domain |
|---|---|
| `skills/bug-bounty/` | Master workflow — recon to report, all vuln classes, LLM testing, chains |
| `skills/bb-methodology/` | **Hunting mindset + 5-phase non-linear workflow + tool routing + session discipline** |
| `skills/web2-recon/` | Subdomain enum, live host discovery, URL crawling, nuclei |
| `skills/web2-vuln-classes/` | 21 bug classes with bypass tables (SSRF, open redirect, file upload, Agentic AI) |
| `skills/security-arsenal/` | Payloads, bypass tables, gf patterns, always-rejected list |
| `skills/web3-audit/` | 10 smart contract bug classes, Foundry PoC template, pre-dive kill signals |
| `skills/meme-coin-audit/` | Meme coin rug pull detection, token authority checks, bonding curve exploits, LP attacks |
| `skills/report-writing/` | H1/Bugcrowd/Intigriti/Immunefi report templates, CVSS 3.1, human tone |
| `skills/triage-validation/` | 7-Question Gate, 4 gates, never-submit list, conditionally valid table |
| `skills/credential-attack/` | Password spray methodology — when/why, 4-stage pipeline, mode selection, lockout tactics, legal guardrails |
| `skills/mobile-pentest/` | Android/iOS app pentest — runtime-first proxy workflow, APK/IPA decompile, deeplink injection, WebView bridge |
| `skills/cicd-security/` | CI/CD pipeline hunting — GitHub Actions injection, secret exfil, self-hosted runner poisoning |
| `skills/graphql-audit/` | GraphQL hunting — introspection, field suggestions, batching DoS, IDOR via aliasing, injection |

### Commands (slash commands)

> **Note:** All commands are prefixed to avoid conflicts with Codex's built-in commands.
> `/resume` is a reserved Codex command — use `/pickup` to continue a previous hunt.

| Command | Usage |
|---|---|
| `/recon` | `/recon target.com` — full recon pipeline |
| `/hunt` | `/hunt target.com` — start hunting |
| `/validate` | `/validate` — run 7-Question Gate on current finding |
| `/report` | `/report` — write submission-ready report |
| `/chain` | `/chain` — build A→B→C exploit chain |
| `/scope` | `/scope <asset>` — verify asset is in scope |
| `/scope-aggregate` | `/scope-aggregate <program>` — pull every in-scope asset across H1/Bugcrowd/Intigriti/YWH/Immunefi |
| `/triage` | `/triage` — quick 7-Question Gate |
| `/web3-audit` | `/web3-audit <contract.sol>` — smart contract audit |
| `/autopilot` | `/autopilot target.com --normal` — autonomous hunt loop |
| `/surface` | `/surface target.com` — ranked attack surface |
| `/pickup` | `/pickup target.com` — pick up previous hunt (was `/resume`) |
| `/remember` | `/remember` — log finding to hunt memory |
| `/intel` | `/intel target.com` — fetch CVE + disclosure intel |
| `/token-scan` | `/token-scan <contract>` — meme coin/token rug pull scanner |
| `/memory-gc` | `/memory-gc [--rotate|--purge-backups]` — inspect/rotate hunt-memory JSONL files (10MB cap, 3 backups) |
| `/secrets-hunt` | `/secrets-hunt --js-bundle <recon-dir>` — leaked-credential scan (trufflehog/noseyparker/gitleaks) |
| `/takeover` | `/takeover --recon <recon-dir>` — subdomain takeover candidates (dnsReaper/subjack) |
| `/cloud-recon` | `/cloud-recon --keyword <name>` — public S3/Azure/GCP + CloudFlare-bypass origin IPs |
| `/param-discover` | `/param-discover <url>` — find hidden HTTP parameters (Arjun/x8) |
| `/bypass-403` | `/bypass-403 <url>` — try header/method/encoding tricks against a 403/401 |
| `/arsenal` | `/arsenal [tool]` — list installed external tools or get an install hint |
| `/scan-cves` | `/scan-cves <host>` — focused nuclei CVE sweep (high/critical) + optional log4j-scan |
| `/wordlist-gen` | `/wordlist-gen <target>` — company-specific password wordlist; requires `--with-credential-attack` |
| `/osint-employees` | `/osint-employees <target>` — employee names + emails; requires `--with-credential-attack` |
| `/breach-check` | `/breach-check <wordlist>` — HIBP k-anonymity rank wordlist by breach count |
| `/spray` | `/spray <url> --mode http-form\|oauth\|o365\|okta --users <f> --passes <f>` — password spray with hard guards |
| `/graphql-audit` | `/graphql-audit <url>` — full GraphQL audit |

### Agents (9 specialized agents)

- `recon-agent` — subdomain enum + live host discovery
- `report-writer` — generates H1/Bugcrowd/Immunefi reports
- `validator` — 4-gate checklist on a finding
- `web3-auditor` — smart contract bug class analysis
- `chain-builder` — builds A→B→C exploit chains
- `autopilot` — autonomous hunt loop (scope→recon→rank→hunt→validate→report)
- `recon-ranker` — attack surface ranking from recon output + memory
- `token-auditor` — fast meme coin/token rug pull and security analysis
- `credential-hunter` — orchestrates wordlist-gen + osint-employees + breach-check; HARD STOPS at spray for human go/no-go

### Rules (always active)

- `rules/hunting.md` — 17 critical hunting rules
- `rules/reporting.md` — report quality rules

### Tools (Python/shell — in `tools/`)

See **`tools/README.md`** for the full ~50-tool catalogue. Highlights:

- `tools/hunt.py` — master orchestrator (auto lead-board ingest + EOL after recon; `--graphql` / `--cve-hunt` / `--zero-day`)
- `tools/lead_board.py` — persistent recon→skill lead ledger (`ingest` / `show` / `next` / `touch`)
- `tools/recon_engine.sh` · `vuln_scanner.sh` · `validate.py` · `scope_checker.py`
- `tools/graphql_audit.sh` · `cicd_scanner.sh` · `cve_scan.sh` · `eol_check.py`
- `tools/waf_encoder.py` · `waf_response_analyzer.py` · `multipart_mutator.py` · `bypass_403.sh`
- `tools/external_arsenal.sh` — installed-tool registry (~50 tools); `_have <tool>` gate
- `tools/secrets_hunter.sh` · `takeover_scanner.sh` · `cloud_recon.sh` · `param_discovery.sh`
- Credential attack (opt-in): `wordlist_engine.sh` · `osint_employees.sh` · `breach_checker.py` · `spray_orchestrator.sh`
- Web3: `token_scanner.py`

### External tool references

- `wordlists/REFERENCES.md` — pointers to SecLists / OneListForAll / fuzz4bounty / PayloadsAllTheThings
- `skills/security-arsenal/REFERENCES.md` — methodology, writeup archives, dorks, key-verification
- `skills/security-arsenal/METHODOLOGY_CHEATSHEET.md` — per-vuln quick-check tables

### MCP Integrations (in `mcp/`)

- `mcp/burp-mcp-client/` — Burp Suite proxy integration
- `mcp/hackerone-mcp/` — HackerOne public API (Hacktivity, program stats, policy)

### Hunt Memory (in `memory/`)

- `memory/pattern_db.py` — cross-target pattern learning
- `memory/audit_log.py` — request audit log, rate limiter, circuit breaker
- `memory/rotation.py` — size-based JSONL rotation (10MB cap, keep 3 backups), auto-fired on append
- `memory/schemas.py` — schema validation for all data
- `memory/leads/<target>.jsonl` — lead board ledger (via `lead_board.py`)

## Start Here

```bash
Codex
# /recon target.com
# /hunt target.com
# /validate   (after finding something)
# /report     (after validation passes)
```

## Install Skills

```bash
chmod +x install.sh && ./install.sh
```

Install for another harness:

```bash
./install.sh --agent opencode          # ~/.config/opencode/skills + commands + agents
./install.sh --agent pi                # ~/.pi/agent/skills + prompt templates
./install.sh --agent codex             # ~/.codex/skills + commands
./install.sh --agent agents            # ~/.agents/skills shared by OpenCode/Pi
./install.sh --agent all               # every supported global target
./install.sh --agent opencode --project # local .opencode/ install
./install.sh --agent pi --project       # local .pi/ install
```

## Critical Rules (Always Active)

1. READ FULL SCOPE before touching any asset
2. NEVER hunt theoretical bugs — "Can attacker do this RIGHT NOW?"
3. Run 7-Question Gate BEFORE writing any report
4. KILL weak findings fast — N/A hurts your validity ratio
5. 5-minute rule — nothing after 5 min = move on
6. **LEAD BOARD — never lose a lead.** After recon, run `lead_board.py ingest <target>` + `show`, and route each finding to its `hunt-*` skill in plain language ("GraphQL endpoint → hunt-graphql"). When starting/killing/reporting a lead, `touch` its status. The hunter focuses on one lead at a time; the board remembers the rest so none is forgotten. Surface stale high-priority leads unprompted.
