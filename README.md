<div align="center">

# Claude Bug Bounty

**The agent harness for professional bug bounty hunting. Web2 + Web3. Recon to report.**

<sub>by <a href="https://github.com/shuvonsec">shuvonsec</a></sub>

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Shell](https://img.shields.io/badge/Shell-bash-4EAA25.svg?style=flat-square&logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Markdown](https://img.shields.io/badge/Docs-Markdown-083FA1.svg?style=flat-square&logo=markdown&logoColor=white)](https://commonmark.org)
[![Claude Code Skill](https://img.shields.io/badge/Claude_Code-Plugin-D97706.svg?style=flat-square&logo=anthropic&logoColor=white)](https://claude.ai/claude-code)

[Quick Start](#quick-start) &nbsp;&middot;&nbsp; [Architecture](#architecture) &nbsp;&middot;&nbsp; [Skills](#skills) &nbsp;&middot;&nbsp; [Commands](#commands) &nbsp;&middot;&nbsp; [Agents](#agents) &nbsp;&middot;&nbsp; [Tools](#tool-reference) &nbsp;&middot;&nbsp; [Rules](#rules)

---

**7 skill domains &nbsp;|&nbsp; 13 slash commands &nbsp;|&nbsp; 7 agents &nbsp;|&nbsp; 20 web2 vuln classes &nbsp;|&nbsp; 10 web3 bug classes &nbsp;|&nbsp; MCP integrations &nbsp;|&nbsp; persistent hunt memory &nbsp;|&nbsp; autonomous mode**

</div>

---

## What's New

### v3.0.0 — Bionic Hunter: Autonomous Mode + MCP Integrations (Mar 2026)

The "brain in a jar" is now a **bionic hacker**. Claude can see your live traffic (via Burp MCP), remember past hunts, fetch real-time intel, and run autonomous hunt loops with human checkpoints.

**New in v3.0.0:**

- **Autonomous Hunt Loop** (`/autopilot`) — 7-step loop (scope→recon→rank→hunt→validate→report→checkpoint) with 3 modes: `--paranoid` (stop per finding), `--normal` (batch), `--yolo` (minimal checkpoints, still requires approval for submissions)
- **Persistent Hunt Memory** — JSONL-based journal, cross-target pattern learning, target profiles. What worked on target A informs hunting on target B
- **Deterministic Scope Safety** — `scope_checker.py` with anchored suffix matching. Code check, not LLM judgment
- **Burp Suite MCP Integration** — Read proxy history, replay requests, Collaborator payloads
- **HackerOne MCP Server** — Public API: disclosed reports, program stats, scope/policy
- **On-Demand Intel** (`/intel`) — Wraps learn.py + HackerOne MCP + memory context. Shows untested CVEs, new endpoints, cross-target patterns
- **Attack Surface Ranking** (`/surface`) — AI-ranked attack surface from recon output + hunt memory
- **Audit Logging** — Every outbound request logged. Per-host rate limiting. Circuit breaker pattern
- **5 New Commands** — `/autopilot`, `/surface`, `/resume`, `/remember`, `/intel`
- **2 New Agents** — `autopilot` (autonomous loop), `recon-ranker` (surface ranking)
- **129 Tests** — Full test coverage for memory, schemas, scope checker, audit log, HackerOne MCP, intel engine
- **Reorganized** — All tools in `tools/`, MCP servers in `mcp/`, memory system in `memory/`

### v2.1.0 — 20 Vuln Classes + Payload Expansion

Added SAML/SSO attacks, MFA bypass, Agentic AI (ASI01-ASI10), expanded bypass tables.

### v2.0.0 — ECC-Style Plugin Architecture

Restructured from monolithic skill file into full Claude Code plugin with modular skills, slash commands, specialized agents, hooks, and rules.

---

Most bug bounty toolkits give you a bag of scripts. This one gives you an **agent harness that reasons about what to test, validates what you find, and writes reports that pay.**

Claude reads your recon output, maps it to the highest-ROI attack surface, drives 25+ tools in the right order, kills weak findings before you waste time writing them up, and generates submission-ready reports — all from a conversation.

### Why this beats scattered scripts

| Problem with scripts | How this solves it |
|:---|:---|
| No methodology — just commands | 7 skill domains with battle-tested hunting workflow |
| False positives waste hours | 7-Question Gate + 4 gates kill weak findings in 30 seconds |
| Reports get downgraded | Report-writer agent with escalation language, CVSS, title formula |
| Duplicate submissions | Built-in dedup check as part of validation gates |
| Monolithic knowledge | 7 focused skills — load only what's relevant per task |
| Scattered tool invocations | 5 specialized agents coordinate tools in the right order |
| No web3 support | 10 DeFi bug classes, Foundry PoC template, pre-dive kill signals |

---

## The Trilogy

| Repo | Purpose |
|:---|:---|
| **[claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)** | Full hunting pipeline — recon, scanning, validation, reporting |
| **[web3-bug-bounty-hunting-ai-skills](https://github.com/shuvonsec/web3-bug-bounty-hunting-ai-skills)** | Smart contract security — 10 bug classes, Foundry PoCs, Immunefi case studies |
| **[public-skills-builder](https://github.com/shuvonsec/public-skills-builder)** | Ingest 500+ public writeups and generate Claude skill files |

`public-skills-builder` generates knowledge → `claude-bug-bounty` runs the hunt → `web3-bug-bounty-hunting-ai-skills` goes deeper on DeFi.

---

## Quick Start

**1. Clone and install skills**

```bash
git clone https://github.com/shuvonsec/claude-bug-bounty.git
cd claude-bug-bounty
chmod +x install.sh && ./install.sh
```

**2. Start hunting**

```bash
claude
# /recon target.com        — full asset discovery
# /hunt target.com         — active vuln testing
# /validate                — check your finding before writing
# /report                  — generate submission-ready report
```

**3. Or run tools directly**

```bash
python3 tools/hunt.py --target hackerone.com              # Full automated hunt
./tools/recon_engine.sh target.com                         # Step 1: Recon
python3 tools/learn.py --tech "nextjs,graphql,jwt"         # Step 2: Intel
python3 tools/intel_engine.py --target target.com --tech nextjs  # Step 2b: Memory-aware intel
python3 tools/hunt.py --target target.com --scan-only      # Step 3: Scan
python3 tools/validate.py                                  # Step 4: Validate
python3 tools/report_generator.py findings/                # Step 5: Report
```

---

## Architecture

```
Target ──▶ Recon ──▶ Learn ──▶ Hunt ──▶ Validate ──▶ Report
           │          │         │          │            │
           │          │         │          │            └── /report
           │          │         │          └── /validate + /triage
           │          │         └── /hunt + /chain + /web3-audit
           │          └── (intel from H1 Hacktivity + disclosed reports)
           └── /recon + recon-agent
                       │
                subfinder + Chaos API + assetfinder
                dnsx + httpx (live hosts + tech)
                katana + waybackurls + gau (URLs)
                gf patterns (classify by bug class)
                nuclei (known CVEs)
```

Each stage feeds the next. Claude orchestrates the entire flow, or you can run any stage independently using slash commands or agents.

---

## Skills

7 skill domains. Each is a focused SKILL.md file Claude loads when relevant.

| Skill | What It Contains | When to Use |
|:---|:---|:---|
| `bug-bounty` | Master workflow — recon to report, all vuln classes, LLM testing, chains, bypass tables | Start any web2 hunt |
| `web2-recon` | Subdomain enum (Chaos API, subfinder), live hosts (httpx), URL crawl (katana), JS analysis, 5-minute rule | Starting recon on a target |
| `web2-vuln-classes` | 18 bug classes — IDOR, auth bypass, XSS, SSRF (11 IP bypass), SQLi, business logic, race, OAuth (11 redirect bypass), file upload (10 bypass), GraphQL, LLM, API, ATO taxonomy, SSTI, subdomain takeover, cloud, HTTP smuggling, cache poisoning | Hunting a specific vuln class |
| `security-arsenal` | XSS/SSRF/SQLi/XXE/path traversal payloads, gf patterns, always-rejected list, conditionally-valid table | Need specific payloads or want to check submittability |
| `web3-audit` | 10 DeFi bug classes, pre-dive kill signals (TVL formula), Foundry PoC template, grep patterns | Any smart contract audit |
| `report-writing` | H1/Bugcrowd/Intigriti/Immunefi templates, CVSS 3.1, title formula, impact statement, escalation language | Writing a submission |
| `triage-validation` | 7-Question Gate, 4 gates, never-submit list, conditionally-valid table, 60-second checklist | Before writing any report |

---

## Commands

13 slash commands covering the full hunting workflow.

| Command | What It Does |
|:---|:---|
| `/recon target.com` | Full recon pipeline — subdomain enum, live hosts, URL crawl, nuclei scan, output to `recon/<target>/` |
| `/hunt target.com` | Active vuln testing — read scope, check intel, detect tech stack, test highest-ROI bug classes |
| `/validate` | 7-Question Gate + 4 gates — PASS, KILL, DOWNGRADE, or CHAIN REQUIRED in under 15 min |
| `/report` | Generate submission-ready report for H1/Bugcrowd/Intigriti/Immunefi with CVSS |
| `/chain` | Given bug A, systematically find B and C — all chain patterns, 20-min time-box rules |
| `/scope <asset>` | Verify an asset is in scope, owned by target org, not third-party |
| `/triage` | Quick 7-Question Gate — go/no-go in 2 minutes before spending time validating |
| `/web3-audit <contract>` | Smart contract audit — 10-class checklist, grep patterns, Foundry PoC template |
| `/autopilot target.com` | Autonomous hunt loop — scope, recon, rank, hunt, validate, report with checkpoints |
| `/surface target.com` | Ranked attack surface from recon output + hunt memory |
| `/resume target.com` | Pick up a previous hunt — shows untested endpoints, memory-informed suggestions |
| `/remember` | Log current finding or pattern to persistent hunt memory |
| `/intel target.com` | On-demand intel — CVEs, disclosed reports, cross-referenced with hunt memory |

---

## Agents

7 specialized agents, each with a specific role and appropriate model.

| Agent | Role | Model |
|:---|:---|:---|
| `recon-agent` | Runs full recon pipeline — subfinder, Chaos API, dnsx, httpx, katana, gf, nuclei | claude-haiku-4-5 (fast) |
| `report-writer` | Generates professional H1/Bugcrowd/Intigriti/Immunefi reports, human tone, impact-first | claude-opus-4-6 (quality) |
| `validator` | Applies 7-Question Gate + 4 gates — outputs PASS/KILL/DOWNGRADE/CHAIN REQUIRED | claude-sonnet-4-6 |
| `web3-auditor` | Checks 10 bug class checklist on Solidity contracts, generates Foundry PoC stubs | claude-sonnet-4-6 |
| `chain-builder` | Given bug A, finds B/C — knows all major chain patterns, applies 20-min time-box | claude-sonnet-4-6 |
| `autopilot` | Autonomous 7-step hunt loop with scope safety, rate limiting, circuit breaker | claude-sonnet-4-6 |
| `recon-ranker` | Attack surface ranking from recon output + hunt memory + pattern DB | claude-haiku-4-5 (fast) |

---

## Tool Reference

All tools are in the `tools/` directory.

### Core Pipeline

| Tool | Role |
|:---|:---|
| `tools/hunt.py` | Master orchestrator — chains recon, scan, and report stages |
| `tools/recon_engine.sh` | Subdomain enum, DNS resolution, live host detection, URL crawling |
| `tools/learn.py` | Pulls CVEs and disclosed reports for detected tech stacks |
| `tools/intel_engine.py` | On-demand intel with memory context — wraps learn.py + HackerOne MCP |
| `tools/mindmap.py` | Generates prioritized attack mindmap with test checklist |
| `tools/validate.py` | 4-gate validation — scope, impact, duplicate check, CVSS scoring |
| `tools/report_generator.py` | Outputs formatted HackerOne/Bugcrowd/Intigriti reports |
| `tools/scope_checker.py` | Deterministic scope safety — anchored suffix matching, not LLM judgment |

### Vulnerability Scanners

| Tool | What It Hunts |
|:---|:---|
| `tools/h1_idor_scanner.py` | Object-level and field-level IDOR via parameter swapping |
| `tools/h1_mutation_idor.py` | GraphQL mutation IDOR — cross-account object access |
| `tools/h1_oauth_tester.py` | OAuth misconfigs — PKCE, state bypass, redirect_uri abuse |
| `tools/h1_race.py` | Race conditions — parallel timing, TOCTOU, limit overrun |
| `tools/zero_day_fuzzer.py` | Smart fuzzer for logic bugs, edge cases, access control |
| `tools/cve_hunter.py` | Tech stack fingerprinting matched against known CVEs |
| `tools/vuln_scanner.sh` | Orchestrates nuclei + dalfox + sqlmap |

### AI / LLM Security

| Tool | What It Hunts |
|:---|:---|
| `tools/hai_probe.py` | AI chatbot IDOR, prompt injection, data exfiltration |
| `tools/hai_payload_builder.py` | Prompt injection payloads — direct, indirect, ASCII smuggling |
| `tools/hai_browser_recon.js` | Browser-side recon of AI feature endpoints |

### MCP Integrations

| Server | What It Provides |
|:---|:---|
| `mcp/burp-mcp-client/` | Burp Suite proxy integration — read traffic, replay requests, Collaborator |
| `mcp/hackerone-mcp/` | HackerOne public API — disclosed reports, program stats, scope/policy |

### Hunt Memory System

| Module | Role |
|:---|:---|
| `memory/hunt_journal.py` | Append-only hunt log (JSONL) with concurrent-safe writes |
| `memory/pattern_db.py` | Cross-target pattern learning — what worked on A informs B |
| `memory/audit_log.py` | Request audit log, per-host rate limiter, circuit breaker |
| `memory/schemas.py` | Schema validation for all JSONL entry types |

### Utilities

| Tool | Role |
|:---|:---|
| `tools/sneaky_bits.py` | JS secret finder and endpoint extractor from bundles |
| `tools/target_selector.py` | Scores and ranks bug bounty programs by ROI |
| `scripts/dork_runner.py` | Google dork automation for passive recon |
| `scripts/full_hunt.sh` | Shell wrapper for the complete pipeline |

---

## Vulnerability Classes

### Web2 — 18 Classes

| Class | Techniques | Typical Payout |
|:---|:---|:---|
| **IDOR** | Object-level, field-level, GraphQL node(), UUID enum, WebSocket, method swap, old API version | $500–$5K |
| **Auth Bypass** | Missing middleware on sibling endpoints, client-side-only checks, BFLA | $1K–$10K |
| **XSS** | Reflected, stored, DOM, postMessage, CSP bypass, mXSS, XSS via AI response | $500–$5K |
| **SSRF** | Redirect chain, DNS rebinding, cloud metadata, IPv6/decimal bypass, 11 IP bypass techniques | $1K–$15K |
| **Business Logic** | Fast-path skip, workflow bypass, negative quantity, race TOCTOU, price manipulation | $500–$10K |
| **Race Conditions** | Parallel TOCTOU, coupon reuse, limit overrun, double spend | $500–$5K |
| **SQLi** | Error-based, blind, time-based, ORM bypass, WAF bypass | $1K–$15K |
| **OAuth/OIDC** | Missing PKCE, state bypass, redirect_uri, 11 open redirect bypass techniques | $500–$5K |
| **File Upload** | Extension bypass, MIME confusion, polyglots, SVG XSS, 10 bypass techniques | $500–$5K |
| **GraphQL** | Introspection, node() IDOR, batching rate limit bypass, auth bypass on mutations | $1K–$10K |
| **LLM/AI** | Prompt injection chains, chatbot IDOR, markdown exfil, ASI01-ASI10 agentic framework | $500–$10K |
| **API Misconfig** | Mass assignment, JWT none/RS256→HS256/weak secret, prototype pollution, CORS | $500–$5K |
| **ATO** | Password reset poisoning, token in Referer, weak tokens, email change, 9 ATO paths | $1K–$20K |
| **SSTI** | Jinja2→RCE, Twig→RCE, Freemarker→RCE, ERB→RCE, Spring Thymeleaf | $2K–$10K |
| **Subdomain Takeover** | GitHub Pages, S3, Heroku, Netlify, Azure — impact escalation via OAuth redirect_uri | $200–$5K |
| **Cloud/Infra** | S3 listing, EC2 metadata, Firebase open rules, K8s API, Docker API, exposed panels | $500–$20K |
| **HTTP Smuggling** | CL.TE, TE.CL, TE.TE, H2.CL — request tunneling | $5K–$30K |
| **Cache Poisoning** | Unkeyed headers, parameter cloaking, web cache deception | $1K–$10K |
| **MFA Bypass** | No rate limit, OTP reuse, response manipulation, workflow skip, race, backup codes | $1K–$10K |
| **SAML/SSO** | XML signature wrapping (XSW), comment injection, signature stripping, XXE in assertion | $2K–$20K |

### Web3 — 10 Bug Classes

| Class | Frequency | Typical Payout |
|:---|:---|:---|
| **Accounting Desync** | 28% of Criticals | $50K–$2M |
| **Access Control** | 19% of Criticals | $50K–$2M |
| **Incomplete Code Path** | 17% of Criticals | $50K–$2M |
| **Off-By-One** | 22% of Highs | $10K–$100K |
| **Oracle Manipulation** | 12% of reports | $100K–$2M |
| **ERC4626 Attacks** | Moderate | $50K–$500K |
| **Reentrancy** | Classic | $10K–$500K |
| **Flash Loan** | Moderate | $100K–$2M |
| **Signature Replay** | Moderate | $10K–$200K |
| **Proxy/Upgrade** | Moderate | $50K–$2M |

---

## Rules

These are always active. Non-negotiable.

```
1.  READ FULL SCOPE — verify every asset before the first request
2.  NO THEORETICAL BUGS — "Can attacker do this RIGHT NOW?" If no, stop
3.  KILL WEAK FINDINGS FAST — Gate 0 is 30 seconds, saves hours
4.  NEVER HUNT OUT-OF-SCOPE — one request = potential ban
5.  5-MINUTE RULE — nothing after 5 min = move on
6.  AUTOMATION = RECON ONLY — manual testing finds unique bugs
7.  IMPACT-FIRST — "worst thing if auth broken?" drives your target selection
8.  SIBLING RULE — if 9 endpoints have auth, check the 10th
9.  A→B SIGNAL — confirming A means B exists nearby, hunt it
10. VALIDATE BEFORE WRITING — 7-Question Gate takes 15 minutes, report takes 30
```

Full rules with explanations: `rules/hunting.md` + `rules/reporting.md`

---

## Installation

### Prerequisites

```bash
# macOS
brew install go python3 node jq

# Linux (Debian/Ubuntu)
sudo apt install golang python3 nodejs jq
```

### Install

```bash
git clone https://github.com/shuvonsec/claude-bug-bounty.git
cd claude-bug-bounty
chmod +x install.sh && ./install.sh
cp config.example.json config.json  # Add your API keys
```

### Set Up API Keys

The recon pipeline uses the Chaos API from ProjectDiscovery for subdomain discovery. Get a free key:

1. Sign up at [chaos.projectdiscovery.io](https://chaos.projectdiscovery.io)
2. Copy your API key
3. Export it before running any recon:

```bash
export CHAOS_API_KEY="your-key-here"

# For persistence, add to your shell profile:
echo 'export CHAOS_API_KEY="your-key-here"' >> ~/.zshrc
source ~/.zshrc
```

The recon commands use `$CHAOS_API_KEY` — the key is never stored in any file in this repo.

**Optional API keys** for better subdomain coverage (configure in `~/.config/subfinder/config.yaml`):
- [VirusTotal](https://www.virustotal.com) — free
- [SecurityTrails](https://securitytrails.com) — free tier
- [Censys](https://censys.io) — free tier
- [Shodan](https://shodan.io) — paid but cheap

This installs 18+ tools: `subfinder`, `httpx`, `dnsx`, `nuclei`, `katana`, `waybackurls`, `gau`, `dalfox`, `ffuf`, `anew`, `qsreplace`, `assetfinder`, `gf`, `interactsh-client`, `sqlmap`, `XSStrike`, `SecretFinder`, `LinkFinder`, and nuclei-templates.

---

## Directory Structure

```
claude-bug-bounty/
├── CLAUDE.md                        # Plugin guide
├── README.md                        # This file
├── CHANGELOG.md                     # Version history
├── TODOS.md                         # Deferred work items
├── install.sh                       # One-command skill installer
│
├── skills/                          # 7 skill domains
│   ├── bug-bounty/SKILL.md          # Master workflow (1,200+ lines)
│   ├── web2-recon/SKILL.md          # Recon pipeline
│   ├── web2-vuln-classes/SKILL.md   # 20 bug classes + bypass tables
│   ├── security-arsenal/SKILL.md    # Payloads + submission rules
│   ├── web3-audit/SKILL.md          # 10 DeFi bug classes + Foundry
│   ├── report-writing/SKILL.md      # Report templates + CVSS
│   └── triage-validation/SKILL.md   # 7-Question Gate + 4 gates
│
├── commands/                        # 13 slash commands
│   ├── recon.md                     # /recon target.com
│   ├── hunt.md                      # /hunt target.com
│   ├── validate.md                  # /validate
│   ├── report.md                    # /report
│   ├── chain.md                     # /chain
│   ├── scope.md                     # /scope <asset>
│   ├── triage.md                    # /triage
│   ├── web3-audit.md                # /web3-audit <contract>
│   ├── autopilot.md                 # /autopilot target.com
│   ├── surface.md                   # /surface target.com
│   ├── resume.md                    # /resume target.com
│   ├── remember.md                  # /remember
│   └── intel.md                     # /intel target.com
│
├── agents/                          # 7 specialized agents
│   ├── recon-agent.md               # Recon pipeline (haiku)
│   ├── report-writer.md             # Report generation (opus)
│   ├── validator.md                 # Finding validation (sonnet)
│   ├── web3-auditor.md              # Contract audit (sonnet)
│   ├── chain-builder.md             # Exploit chains (sonnet)
│   ├── autopilot.md                 # Autonomous hunt loop (sonnet)
│   └── recon-ranker.md              # Surface ranking (haiku)
│
├── tools/                           # All Python/shell tools
│   ├── hunt.py                      # Master orchestrator
│   ├── recon_engine.sh              # Subdomain + URL discovery
│   ├── learn.py                     # CVE + disclosure intel
│   ├── intel_engine.py              # Memory-aware intel wrapper
│   ├── mindmap.py                   # Attack surface mapper
│   ├── validate.py                  # 4-gate validator
│   ├── report_generator.py          # Report writer
│   ├── scope_checker.py             # Deterministic scope checker
│   ├── h1_idor_scanner.py           # IDOR scanner
│   ├── h1_mutation_idor.py          # GraphQL IDOR
│   ├── h1_oauth_tester.py           # OAuth tester
│   ├── h1_race.py                   # Race condition tester
│   ├── zero_day_fuzzer.py           # Smart fuzzer
│   ├── cve_hunter.py                # CVE matcher
│   ├── vuln_scanner.sh              # Nuclei/Dalfox/SQLMap
│   ├── hai_probe.py                 # AI chatbot tester
│   ├── hai_payload_builder.py       # Prompt injection generator
│   ├── hai_browser_recon.js         # Browser AI recon
│   ├── sneaky_bits.py               # JS secret finder
│   └── target_selector.py           # Program ROI scorer
│
├── memory/                          # Persistent hunt memory system
│   ├── __init__.py                  # Package exports
│   ├── schemas.py                   # Schema validation
│   ├── hunt_journal.py              # Append-only hunt log
│   ├── pattern_db.py                # Cross-target patterns
│   └── audit_log.py                 # Audit log + rate limiter + circuit breaker
│
├── mcp/                             # MCP server integrations
│   ├── burp-mcp-client/             # Burp Suite proxy
│   │   ├── config.json              # Connection config template
│   │   └── README.md                # Setup guide
│   └── hackerone-mcp/               # HackerOne public API
│       ├── server.py                # MCP server (3 tools)
│       └── config.json              # Connection config
│
├── tests/                           # 129 tests
│   ├── conftest.py                  # Shared fixtures
│   ├── test_schemas.py              # Schema validation (22 tests)
│   ├── test_hunt_journal.py         # Journal + concurrency (18 tests)
│   ├── test_pattern_db.py           # Pattern matching (13 tests)
│   ├── test_scope_checker.py        # Scope safety (22 tests)
│   ├── test_audit_log.py            # Audit + rate + circuit (22 tests)
│   ├── test_hackerone_mcp.py        # API contract (5 tests)
│   ├── test_hackerone_server.py     # MCP server (13 tests)
│   └── test_intel_engine.py         # Intel prioritization (14 tests)
│
├── hooks/hooks.json                 # Session start/stop hooks
├── rules/                           # Always-active rules
│   ├── hunting.md                   # 17 hunting rules
│   └── reporting.md                 # 12 report quality rules
├── docs/                            # Documentation
├── web3/                            # Smart contract skill chain
├── scripts/                         # Shell wrappers
├── wordlists/                       # 5 wordlists
├── recon/                           # Recon output (per target)
├── findings/                        # Validated findings
└── reports/                         # Submission-ready reports
```

---

## Contributing

PRs welcome. Good contributions:

- New vulnerability scanners or detection modules
- Payload additions to `skills/security-arsenal/SKILL.md`
- New agent definitions for specific platforms or bug classes
- Real-world methodology improvements (with evidence from paid reports)
- Platform support (YesWeHack, Synack, HackenProof)

```bash
git checkout -b feature/your-contribution
git commit -m "Add: short description"
git push origin feature/your-contribution
```

---

## Contact

| | |
|:--|:--|
| GitHub | [shuvonsec](https://github.com/shuvonsec) |
| Email | [shuvonsec@gmail.com](mailto:shuvonsec@gmail.com) |
| Twitter | [@shuvonsec](https://x.com/shuvonsec) |
| LinkedIn | [shuvonsec](https://linkedin.com/in/shuvonsec) |

---

## Legal

**For authorized security testing only.** Only test targets within an approved bug bounty scope. Never test systems without explicit permission. Follow responsible disclosure practices. Read each program's rules of engagement before hunting.

---

<div align="center">

MIT License

**Built by bug hunters, for bug hunters.**

If this helped you find a bug, consider leaving a star.

</div>
