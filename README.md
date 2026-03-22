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

**7 skill domains &nbsp;|&nbsp; 8 slash commands &nbsp;|&nbsp; 5 agents &nbsp;|&nbsp; 20 web2 vuln classes &nbsp;|&nbsp; 10 web3 bug classes &nbsp;|&nbsp; battle-tested across HackerOne, Bugcrowd, Intigriti, Immunefi**

</div>

---

## What's New

### v2.0.0 — ECC-Style Plugin Architecture (Mar 2026)

This release restructures the entire repo from a monolithic skill file into a full **Claude Code plugin** modeled after the `everything-claude-code` architecture — with modular skills, slash commands, specialized agents, hooks, and rules.

**Skills (7 focused domains)**
- `skills/bug-bounty/` — Master workflow skill (1,200+ lines, recon → report, all vuln classes, LLM testing, bypass tables, A→B chains)
- `skills/web2-recon/` — Full recon pipeline with exact commands: Chaos API, subfinder, dnsx, httpx, katana, gf, nuclei. Includes 5-minute rule + tech stack map
- `skills/web2-vuln-classes/` — All 20 bug classes with bypass reference tables: SSRF (11 IP bypass techniques), open redirect (11 techniques for OAuth chaining), file upload (10 bypass techniques + magic bytes), Agentic AI ASI01–ASI10 framework, MFA bypass (7 patterns), SAML attacks (XSW/comment injection/signature stripping)
- `skills/security-arsenal/` — XSS/SSRF/SQLi/XXE/path traversal payloads, gf pattern names, never-submit list, conditionally-valid-with-chain table
- `skills/web3-audit/` — All 10 DeFi bug classes with code patterns, pre-dive kill signals (TVL formula), Foundry PoC template
- `skills/report-writing/` — H1/Bugcrowd/Intigriti/Immunefi report templates, CVSS 3.1, title formula, escalation language, human-tone rules
- `skills/triage-validation/` — 7-Question Gate (all 7 questions), 4 gates (Gate 0–3), never-submit list, conditionally-valid table

**Commands (8 slash commands)**
- `/recon target.com` — full asset discovery pipeline
- `/hunt target.com` — active vuln testing with scope load
- `/validate` — 7-Question Gate + 4 gates, outputs PASS/KILL/DOWNGRADE/CHAIN REQUIRED
- `/report` — submission-ready report in 60 seconds
- `/chain` — A→B→C exploit chain builder
- `/scope <asset>` — pre-hunt scope verification
- `/triage` — 2-minute go/no-go before deep validation
- `/web3-audit <contract.sol>` — 10-class smart contract checklist

**Agents (5 specialized subagents)**
- `recon-agent` (haiku — fast) — subfinder + Chaos API + dnsx + httpx + katana
- `report-writer` (opus — quality) — professional H1/Bugcrowd/Immunefi reports, impact-first, human tone
- `validator` (sonnet) — 7-Question Gate + 4-gate checklist
- `web3-auditor` (sonnet) — 10-class contract audit + Foundry PoC stubs
- `chain-builder` (sonnet) — systematic A→B→C exploit chaining

**Hooks & Rules**
- `hooks/hooks.json` — SessionStart/SessionStop hooks for hunt context
- `rules/hunting.md` — 17 critical hunting rules (always active)
- `rules/reporting.md` — 12 report quality rules (always active)

**Preserved**: all original Python/shell tools (`hunt.py`, `recon_engine.sh`, `validate.py`, `report_generator.py`, `learn.py`, all scanners) and the original monolithic `SKILL.md` are unchanged.

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
python3 hunt.py --target hackerone.com          # Full automated hunt
./recon_engine.sh target.com                     # Step 1: Recon
python3 learn.py --tech "nextjs,graphql,jwt"     # Step 2: Intel
python3 hunt.py --target target.com --scan-only  # Step 3: Scan
python3 validate.py                              # Step 4: Validate
python3 report_generator.py findings/            # Step 5: Report
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

8 slash commands covering the full hunting workflow.

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

---

## Agents

5 specialized agents, each with a specific role and appropriate model.

| Agent | Role | Model |
|:---|:---|:---|
| `recon-agent` | Runs full recon pipeline — subfinder, Chaos API, dnsx, httpx, katana, gf, nuclei | claude-haiku-4-5 (fast) |
| `report-writer` | Generates professional H1/Bugcrowd/Intigriti/Immunefi reports, human tone, impact-first | claude-opus-4-6 (quality) |
| `validator` | Applies 7-Question Gate + 4 gates — outputs PASS/KILL/DOWNGRADE/CHAIN REQUIRED | claude-sonnet-4-6 |
| `web3-auditor` | Checks 10 bug class checklist on Solidity contracts, generates Foundry PoC stubs | claude-sonnet-4-6 |
| `chain-builder` | Given bug A, finds B/C — knows all major chain patterns, applies 20-min time-box | claude-sonnet-4-6 |

---

## Tool Reference

### Core Pipeline

| Tool | Role |
|:---|:---|
| `hunt.py` | Master orchestrator — chains recon, scan, and report stages |
| `recon_engine.sh` | Subdomain enum, DNS resolution, live host detection, URL crawling |
| `learn.py` | Pulls CVEs and disclosed reports for detected tech stacks |
| `mindmap.py` | Generates prioritized attack mindmap with test checklist |
| `validate.py` | 4-gate validation — scope, impact, duplicate check, CVSS scoring |
| `report_generator.py` | Outputs formatted HackerOne/Bugcrowd/Intigriti reports |

### Vulnerability Scanners

| Tool | What It Hunts |
|:---|:---|
| `h1_idor_scanner.py` | Object-level and field-level IDOR via parameter swapping |
| `h1_mutation_idor.py` | GraphQL mutation IDOR — cross-account object access |
| `h1_oauth_tester.py` | OAuth misconfigs — PKCE, state bypass, redirect_uri abuse |
| `h1_race.py` | Race conditions — parallel timing, TOCTOU, limit overrun |
| `zero_day_fuzzer.py` | Smart fuzzer for logic bugs, edge cases, access control |
| `cve_hunter.py` | Tech stack fingerprinting matched against known CVEs |
| `vuln_scanner.sh` | Orchestrates nuclei + dalfox + sqlmap |

### AI / LLM Security

| Tool | What It Hunts |
|:---|:---|
| `hai_probe.py` | AI chatbot IDOR, prompt injection, data exfiltration |
| `hai_payload_builder.py` | Prompt injection payloads — direct, indirect, ASCII smuggling |
| `hai_browser_recon.js` | Browser-side recon of AI feature endpoints |

### Utilities

| Tool | Role |
|:---|:---|
| `sneaky_bits.py` | JS secret finder and endpoint extractor from bundles |
| `target_selector.py` | Scores and ranks bug bounty programs by ROI |
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
├── CLAUDE.md                   # Plugin guide — quick-start, commands, structure
├── README.md                   # This file
├── CHANGELOG.md                # Version history
├── install.sh                  # One-command skill installer
│
├── skills/                     # 7 skill domains
│   ├── bug-bounty/SKILL.md     # Master workflow (1,200+ lines)
│   ├── web2-recon/SKILL.md     # Recon pipeline
│   ├── web2-vuln-classes/SKILL.md  # 18 bug classes + bypass tables
│   ├── security-arsenal/SKILL.md   # Payloads + submission rules
│   ├── web3-audit/SKILL.md     # 10 DeFi bug classes + Foundry
│   ├── report-writing/SKILL.md # Report templates + CVSS
│   └── triage-validation/SKILL.md  # 7-Question Gate + 4 gates
│
├── commands/                   # 8 slash commands
│   ├── recon.md                # /recon target.com
│   ├── hunt.md                 # /hunt target.com
│   ├── validate.md             # /validate
│   ├── report.md               # /report
│   ├── chain.md                # /chain
│   ├── scope.md                # /scope <asset>
│   ├── triage.md               # /triage
│   └── web3-audit.md           # /web3-audit <contract>
│
├── agents/                     # 5 specialized agents
│   ├── recon-agent.md          # Runs recon pipeline (haiku)
│   ├── report-writer.md        # Generates reports (opus)
│   ├── validator.md            # Validates findings (sonnet)
│   ├── web3-auditor.md         # Audits contracts (sonnet)
│   └── chain-builder.md        # Builds exploit chains (sonnet)
│
├── hooks/hooks.json            # Session start/stop hooks
│
├── rules/                      # Always-active rules
│   ├── hunting.md              # 17 hunting rules
│   └── reporting.md            # 12 report quality rules
│
├── SKILL.md                    # Original monolithic skill (preserved)
├── hunt.py                     # Master orchestrator
├── recon_engine.sh             # Subdomain + URL discovery
├── learn.py                    # CVE + disclosure intel
├── mindmap.py                  # Attack surface mapper
├── validate.py                 # 4-gate validator
├── report_generator.py         # Report writer
├── h1_idor_scanner.py          # IDOR scanner
├── h1_mutation_idor.py         # GraphQL IDOR
├── h1_oauth_tester.py          # OAuth tester
├── h1_race.py                  # Race condition tester
├── zero_day_fuzzer.py          # Smart fuzzer
├── cve_hunter.py               # CVE matcher
├── vuln_scanner.sh             # Nuclei/Dalfox/SQLMap wrapper
├── hai_probe.py                # AI chatbot tester
├── hai_payload_builder.py      # Prompt injection generator
├── hai_browser_recon.js        # Browser AI recon
├── sneaky_bits.py              # JS secret finder
├── target_selector.py          # Program ROI scorer
├── docs/
│   ├── payloads.md             # Complete payload arsenal
│   ├── advanced-techniques.md  # A→B chaining, mobile, CI/CD
│   └── smart-contract-audit.md # Web3 audit guide
├── web3/                       # Smart contract skill chain (10 files)
├── scripts/
│   ├── dork_runner.py          # Google dork automation
│   └── full_hunt.sh            # Full pipeline wrapper
├── wordlists/                  # 5 wordlists
├── recon/                      # Recon output (per target)
├── findings/                   # Validated findings
└── reports/                    # Submission-ready reports
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
