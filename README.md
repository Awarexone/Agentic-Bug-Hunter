<p align="center">
  <img src="logo.png" alt="Claude Bug Bounty Logo" width="320"/>
</p>

<div align="center">

<img src="https://img.shields.io/badge/v3.0.0-Bionic_Hunter-blueviolet?style=for-the-badge" alt="v3.0.0">

# Claude Bug Bounty

### The AI-Powered Agent Harness for Professional Bug Bounty Hunting

*Your AI copilot that sees live traffic, remembers past hunts, and hunts autonomously.*

<sub>by <a href="https://shuvonsec.me">shuvonsec</a></sub>

<br>

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-129_passing-brightgreen.svg?style=flat-square)](tests/)
[![Claude Code](https://img.shields.io/badge/Claude_Code-Plugin-D97706.svg?style=flat-square&logo=anthropic&logoColor=white)](https://claude.ai/claude-code)

<br>

<a href="#-quick-start">Quick Start</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#-how-it-works">How It Works</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#-commands">Commands</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#-whats-new-in-v300">What's New</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#-installation">Install</a>

<br>

```
  13 commands  ·  7 AI agents  ·  8 skill domains
  20 web2 vuln classes  ·  10 web3 bug classes
  Burp MCP  ·  HackerOne MCP  ·  Autonomous Mode
```

</div>

<br>

---

<br>

## The Problem

Most bug bounty toolkits give you a bag of scripts. You still have to:
- Figure out **what** to test and **in what order**
- Waste hours on **false positives** that get rejected
- Write **reports from scratch** every time
- **Forget** what worked on previous targets
- **Context-switch** between 15 different terminal windows

<br>

## The Solution

Claude Bug Bounty is an **agent harness** — not just scripts. It reasons about what to test, validates findings before you waste time writing them up, remembers what worked across targets, and generates reports that actually get paid.

<br>

<div align="center">

| Before | After |
|:---|:---|
| Run scripts manually, hope for the best | AI orchestrates 25+ tools in the right order |
| Write reports from scratch (45 min each) | Report-writer agent generates submission-ready reports in 60s |
| Forget what worked last month | Persistent memory — patterns from target A inform target B |
| Can't see live traffic from Claude | Burp MCP integration — Claude reads your proxy history |
| Hunt one endpoint at a time | `/autopilot` runs full hunt loops with safety checkpoints |

</div>

<br>

---

<br>

## Quick Start

**Step 1 — Install**

```bash
git clone https://github.com/shuvonsec/claude-bug-bounty.git
cd claude-bug-bounty
chmod +x install.sh && ./install.sh
```

**Step 2 — Hunt**

```bash
claude                          # Start Claude Code

/recon target.com               # Discover attack surface
/hunt target.com                # Test for vulnerabilities
/validate                       # Check finding before writing
/report                         # Generate submission-ready report
```

**Step 3 — Go Autonomous** *(new in v3)*

```bash
/autopilot target.com --normal  # Full autonomous hunt loop
/intel target.com               # Fetch CVE + disclosure intel
/resume target.com              # Pick up where you left off
```

<br>

> **Or run tools directly** — no Claude needed:
> ```bash
> python3 tools/hunt.py --target target.com
> ./tools/recon_engine.sh target.com
> python3 tools/intel_engine.py --target target.com --tech nextjs
> ```

<br>

---

<br>

## How It Works

```
                         YOU
                          |
                    ┌─────▼─────┐
                    │   Claude   │ ◄── Burp MCP (sees your traffic)
                    │   Code     │ ◄── HackerOne MCP (program intel)
                    └─────┬─────┘
                          |
          ┌───────────────┼───────────────┐
          |               |               |
    ┌─────▼─────┐  ┌──────▼──────┐  ┌────▼────┐
    │   Recon    │  │    Hunt     │  │ Report  │
    │   Agent    │  │   Engine    │  │ Writer  │
    └─────┬─────┘  └──────┬──────┘  └────┬────┘
          |               |               |
    subfinder        scope check      H1/Bugcrowd
    httpx            vuln test        Intigriti
    katana           validate         Immunefi
    nuclei           chain A→B→C      CVSS 3.1
          |               |               |
    ┌─────▼───────────────▼───────────────▼─────┐
    │              Hunt Memory                   │
    │  journal · patterns · audit · rate limit   │
    └───────────────────────────────────────────-─┘
```

Each stage feeds the next. Claude orchestrates everything, or you run any stage independently.

<br>

---

<br>

## Commands

### Core Workflow

| Command | What It Does |
|:---|:---|
| `/recon target.com` | Full recon — subdomains, live hosts, URLs, nuclei scan |
| `/hunt target.com` | Active testing — scope check, tech detect, test highest-ROI bugs |
| `/validate` | 7-Question Gate + 4 gates — PASS / KILL / DOWNGRADE / CHAIN REQUIRED |
| `/report` | Submission-ready report for H1/Bugcrowd/Intigriti/Immunefi |
| `/chain` | Find B and C from bug A — systematic exploit chaining |
| `/scope <asset>` | Verify asset is in scope before testing |
| `/triage` | Quick 2-minute go/no-go before deep validation |
| `/web3-audit <contract>` | 10-class smart contract checklist + Foundry PoC |

### Autonomous & Memory *(new in v3)*

| Command | What It Does |
|:---|:---|
| `/autopilot target.com` | Full autonomous hunt loop with safety checkpoints |
| `/surface target.com` | AI-ranked attack surface from recon + memory |
| `/resume target.com` | Resume previous hunt — shows what's untested |
| `/remember` | Save finding or pattern to persistent memory |
| `/intel target.com` | CVEs + disclosures cross-referenced with your hunt history |

<br>

---

<br>

## AI Agents

7 specialized agents, each tuned for its role:

| Agent | What It Does | Model |
|:---|:---|:---|
| **recon-agent** | Subdomain enum, live hosts, URL crawl, nuclei | Haiku *(fast)* |
| **report-writer** | Professional reports, impact-first, human tone | Opus *(quality)* |
| **validator** | 7-Question Gate + 4-gate finding validation | Sonnet |
| **web3-auditor** | 10-class contract audit + Foundry PoC stubs | Sonnet |
| **chain-builder** | Systematic A-B-C exploit chaining | Sonnet |
| **autopilot** | Autonomous hunt loop with circuit breaker | Sonnet |
| **recon-ranker** | Attack surface ranking from recon + memory | Haiku *(fast)* |

<br>

---

<br>

## What's New in v3.0.0

> **The "brain in a jar" is now a bionic hacker.**

<details>
<summary><b>Autonomous Hunt Loop</b> — <code>/autopilot</code></summary>
<br>

7-step loop that runs continuously: **scope - recon - rank - hunt - validate - report - checkpoint**

Three checkpoint modes:
- `--paranoid` — stops after every finding for your review
- `--normal` — batches findings, checkpoints every few minutes
- `--yolo` — minimal stops (still requires approval for report submissions)

Built-in safety: circuit breaker stops hammering hosts after consecutive failures, per-host rate limiting, every request logged to `audit.jsonl`.

</details>

<details>
<summary><b>Persistent Hunt Memory</b> — remember everything</summary>
<br>

- **Journal** — append-only JSONL log of every hunt action (concurrent-safe writes)
- **Pattern DB** — what technique worked on which tech stack, sorted by payout
- **Target profiles** — tested/untested endpoints, tech stack, findings
- **Cross-target learning** — patterns from target A suggested when hunting target B

</details>

<details>
<summary><b>MCP Integrations</b> — Burp + HackerOne</summary>
<br>

**Burp Suite MCP** — Claude can read your proxy history, replay requests through Burp, use Collaborator payloads. Your AI copilot now sees the same traffic you do.

**HackerOne MCP** — Public API integration:
- `search_disclosed_reports` — search Hacktivity by keyword or program
- `get_program_stats` — bounty ranges, response times, resolved counts
- `get_program_policy` — scope, safe harbor, excluded vuln classes

</details>

<details>
<summary><b>On-Demand Intel</b> — <code>/intel</code></summary>
<br>

Wraps `learn.py` + HackerOne MCP + hunt memory:
- Flags **untested CVEs** matching the target's tech stack
- Shows **new endpoints** not in your tested list
- Surfaces **cross-target patterns** from your own hunt history
- Prioritizes: CRITICAL untested > HIGH untested > already tested

</details>

<details>
<summary><b>Deterministic Scope Safety</b></summary>
<br>

`scope_checker.py` uses anchored suffix matching — code check, not LLM judgment:
- `*.target.com` matches `api.target.com` but NOT `evil-target.com`
- Excluded domains always win over wildcards
- IP addresses rejected with warning (match by domain only)
- Every test filtered through scope before execution

</details>

<br>

---

<br>

## Vulnerability Coverage

<details>
<summary><b>20 Web2 Bug Classes</b> — click to expand</summary>
<br>

| Class | Key Techniques | Typical Payout |
|:---|:---|:---|
| **IDOR** | Object-level, field-level, GraphQL node(), UUID enum, method swap | $500 - $5K |
| **Auth Bypass** | Missing middleware, client-side checks, BFLA | $1K - $10K |
| **XSS** | Reflected, stored, DOM, postMessage, CSP bypass, mXSS | $500 - $5K |
| **SSRF** | Redirect chain, DNS rebinding, cloud metadata, 11 IP bypasses | $1K - $15K |
| **Business Logic** | Workflow bypass, negative quantity, price manipulation | $500 - $10K |
| **Race Conditions** | TOCTOU, coupon reuse, limit overrun, double spend | $500 - $5K |
| **SQLi** | Error-based, blind, time-based, ORM bypass, WAF bypass | $1K - $15K |
| **OAuth/OIDC** | Missing PKCE, state bypass, 11 redirect_uri bypasses | $500 - $5K |
| **File Upload** | Extension bypass, MIME confusion, polyglots, 10 bypasses | $500 - $5K |
| **GraphQL** | Introspection, node() IDOR, batching bypass, mutation auth | $1K - $10K |
| **LLM/AI** | Prompt injection, chatbot IDOR, ASI01-ASI10 framework | $500 - $10K |
| **API Misconfig** | Mass assignment, JWT attacks, prototype pollution, CORS | $500 - $5K |
| **ATO** | Password reset poisoning, token leaks, 9 takeover paths | $1K - $20K |
| **SSTI** | Jinja2, Twig, Freemarker, ERB, Thymeleaf -> RCE | $2K - $10K |
| **Subdomain Takeover** | GitHub Pages, S3, Heroku, Netlify, Azure | $200 - $5K |
| **Cloud/Infra** | S3 listing, EC2 metadata, Firebase, K8s, Docker API | $500 - $20K |
| **HTTP Smuggling** | CL.TE, TE.CL, TE.TE, H2.CL request tunneling | $5K - $30K |
| **Cache Poisoning** | Unkeyed headers, parameter cloaking, web cache deception | $1K - $10K |
| **MFA Bypass** | No rate limit, OTP reuse, response manipulation, race | $1K - $10K |
| **SAML/SSO** | XSW, comment injection, signature stripping, XXE | $2K - $20K |

</details>

<details>
<summary><b>10 Web3 Bug Classes</b> — click to expand</summary>
<br>

| Class | Frequency | Typical Payout |
|:---|:---|:---|
| **Accounting Desync** | 28% of Criticals | $50K - $2M |
| **Access Control** | 19% of Criticals | $50K - $2M |
| **Incomplete Code Path** | 17% of Criticals | $50K - $2M |
| **Off-By-One** | 22% of Highs | $10K - $100K |
| **Oracle Manipulation** | 12% of reports | $100K - $2M |
| **ERC4626 Attacks** | Moderate | $50K - $500K |
| **Reentrancy** | Classic | $10K - $500K |
| **Flash Loan** | Moderate | $100K - $2M |
| **Signature Replay** | Moderate | $10K - $200K |
| **Proxy/Upgrade** | Moderate | $50K - $2M |

</details>

<br>

---

<br>

## Tools & Architecture

<details>
<summary><b>Core Pipeline</b> — <code>tools/</code></summary>
<br>

| Tool | What It Does |
|:---|:---|
| `hunt.py` | Master orchestrator — chains recon, scan, report |
| `recon_engine.sh` | Subdomain enum + DNS + live hosts + URL crawl |
| `learn.py` | CVE + disclosure intel from NVD, GitHub Advisory, HackerOne |
| `intel_engine.py` | Memory-aware intel wrapper (learn.py + HackerOne MCP + memory) |
| `validate.py` | 4-gate validation — scope, impact, dedup, CVSS |
| `report_generator.py` | H1/Bugcrowd/Intigriti report output |
| `scope_checker.py` | Deterministic scope safety with anchored suffix matching |
| `mindmap.py` | Prioritized attack mindmap generator |

</details>

<details>
<summary><b>Vulnerability Scanners</b> — <code>tools/</code></summary>
<br>

| Tool | Target |
|:---|:---|
| `h1_idor_scanner.py` | Object-level and field-level IDOR |
| `h1_mutation_idor.py` | GraphQL mutation IDOR |
| `h1_oauth_tester.py` | OAuth misconfigs (PKCE, state, redirect_uri) |
| `h1_race.py` | Race conditions (TOCTOU, limit overrun) |
| `zero_day_fuzzer.py` | Logic bugs, edge cases, access control |
| `cve_hunter.py` | Tech fingerprinting + known CVE matching |
| `vuln_scanner.sh` | Orchestrates nuclei + dalfox + sqlmap |
| `hai_probe.py` | AI chatbot IDOR, prompt injection |
| `hai_payload_builder.py` | Prompt injection payload generator |

</details>

<details>
<summary><b>MCP Integrations</b> — <code>mcp/</code></summary>
<br>

| Server | Tools Provided |
|:---|:---|
| **Burp Suite** (`burp-mcp-client/`) | Read proxy history, replay requests, Collaborator payloads |
| **HackerOne** (`hackerone-mcp/`) | `search_disclosed_reports`, `get_program_stats`, `get_program_policy` |

</details>

<details>
<summary><b>Hunt Memory System</b> — <code>memory/</code></summary>
<br>

| Module | What It Does |
|:---|:---|
| `hunt_journal.py` | Append-only JSONL hunt log (concurrent-safe via `fcntl.flock`) |
| `pattern_db.py` | Cross-target pattern DB — matches by vuln class + tech stack |
| `audit_log.py` | Every outbound request logged + per-host rate limiter + circuit breaker |
| `schemas.py` | Schema validation for all entry types (versioned) |

</details>

<details>
<summary><b>Full Directory Structure</b> — click to expand</summary>
<br>

```
claude-bug-bounty/
├── skills/                     8 skill domains (SKILL.md files)
├── commands/                   13 slash commands
├── agents/                     7 specialized AI agents
├── tools/                      21 Python/shell tools
├── memory/                     Persistent hunt memory system
├── mcp/                        MCP server integrations
│   ├── burp-mcp-client/        Burp Suite proxy
│   └── hackerone-mcp/          HackerOne public API
├── tests/                      129 tests
├── rules/                      Always-active hunting + reporting rules
├── hooks/                      Session start/stop hooks
├── docs/                       Payload arsenal + technique guides
├── web3/                       Smart contract skill chain
├── scripts/                    Shell wrappers
└── wordlists/                  5 wordlists
```

</details>

<br>

---

<br>

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
```

### API Keys

<details>
<summary><b>Chaos API</b> (required for recon)</summary>
<br>

1. Sign up at [chaos.projectdiscovery.io](https://chaos.projectdiscovery.io)
2. Export your key:

```bash
export CHAOS_API_KEY="your-key-here"
echo 'export CHAOS_API_KEY="your-key-here"' >> ~/.zshrc
```

</details>

<details>
<summary><b>Optional API keys</b> (better subdomain coverage)</summary>
<br>

Configure in `~/.config/subfinder/config.yaml`:
- [VirusTotal](https://www.virustotal.com) — free
- [SecurityTrails](https://securitytrails.com) — free tier
- [Censys](https://censys.io) — free tier
- [Shodan](https://shodan.io) — paid

</details>

<br>

---

<br>

## The Golden Rules

These are always active. Non-negotiable.

```
 1. READ FULL SCOPE        verify every asset before the first request
 2. NO THEORETICAL BUGS    "Can attacker do this RIGHT NOW?" — if no, stop
 3. KILL WEAK FAST         Gate 0 is 30 seconds, saves hours
 4. NEVER OUT-OF-SCOPE     one request = potential ban
 5. 5-MINUTE RULE          nothing after 5 min = move on
 6. RECON ONLY AUTO        manual testing finds unique bugs
 7. IMPACT-FIRST           "worst thing if auth broken?" drives target selection
 8. SIBLING RULE           9 endpoints have auth? check the 10th
 9. A→B SIGNAL             confirming A means B exists nearby — hunt it
10. VALIDATE FIRST         7-Question Gate (15 min) before report (30 min)
```

<br>

---

<br>

## The Trilogy

| Repo | Purpose |
|:---|:---|
| **[claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)** | Full hunting pipeline — recon to report |
| **[web3-bug-bounty-hunting-ai-skills](https://github.com/shuvonsec/web3-bug-bounty-hunting-ai-skills)** | Smart contract security — 10 bug classes, Foundry PoCs |
| **[public-skills-builder](https://github.com/shuvonsec/public-skills-builder)** | Ingest 500+ writeups into Claude skill files |

<br>

---

<br>

## Contributing

PRs welcome. Best contributions:

- New vulnerability scanners or detection modules
- Payload additions to `skills/security-arsenal/SKILL.md`
- New agent definitions for specific platforms
- Real-world methodology improvements (with evidence from paid reports)
- Platform support (YesWeHack, Synack, HackenProof)

```bash
git checkout -b feature/your-contribution
git commit -m "Add: short description"
git push origin feature/your-contribution
```

<br>

---

<br>

<div align="center">

### Connect

[GitHub](https://github.com/shuvonsec) &nbsp;&nbsp;|&nbsp;&nbsp; [Twitter](https://x.com/shuvonsec) &nbsp;&nbsp;|&nbsp;&nbsp; [LinkedIn](https://linkedin.com/in/shuvonsec) &nbsp;&nbsp;|&nbsp;&nbsp; [Email](mailto:shuvonsec@gmail.com)

<br>

---

**For authorized security testing only.** Only test targets within an approved bug bounty scope.<br>
Never test systems without explicit permission. Follow responsible disclosure practices.

---

<br>

MIT License

**Built by bug hunters, for bug hunters.**

If this helped you find a bug, leave a star.

</div>
