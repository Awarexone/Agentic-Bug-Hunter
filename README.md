<p align="center">
  <img src="logo.png" alt="Claude Bug Bounty Logo" width="320"/>
</p>

<div align="center">

<img src="https://img.shields.io/badge/v4.2.0-Memory_Rotation-blueviolet?style=for-the-badge" alt="v4.2.0">

# Claude Bug Bounty

### Find security vulnerabilities, get paid — with AI doing the heavy lifting

*Your AI hunting partner that remembers past targets, spots vulnerabilities, and writes reports for you.*

<sub>by <a href="https://shuvonsec.me">shuvonsec</a></sub>

<br>

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-180_passing-brightgreen.svg?style=flat-square)](tests/)
[![Claude Code](https://img.shields.io/badge/Claude_Code-Plugin-D97706.svg?style=flat-square&logo=anthropic&logoColor=white)](https://claude.ai/claude-code)
[![$BUG](https://img.shields.io/badge/$BUG-pump.fun-9945FF?style=flat-square&logo=solana&logoColor=white)](https://pump.fun/coin/J6VzBAGnyyNEyzyHhauwg3ofRctFxnTLzQCcjUdGpump)

<br>

<a href="#-what-is-this">What Is This?</a>&nbsp;&nbsp;·&nbsp;&nbsp;<a href="#-quick-start">Quick Start</a>&nbsp;&nbsp;·&nbsp;&nbsp;<a href="#-commands">Commands</a>&nbsp;&nbsp;·&nbsp;&nbsp;<a href="#-whats-new">What's New</a>&nbsp;&nbsp;·&nbsp;&nbsp;<a href="#-installation">Install</a>&nbsp;&nbsp;·&nbsp;&nbsp;<a href="FAQ.md">FAQ</a>&nbsp;&nbsp;·&nbsp;&nbsp;<a href="TERMS.md">Terms</a>

<br>

![Commands](https://img.shields.io/badge/commands-15-D97706?style=flat-square)
![Agents](https://img.shields.io/badge/AI_agents-8-blueviolet?style=flat-square)
![Skills](https://img.shields.io/badge/skill_domains-9-3776AB?style=flat-square)
![Web2](https://img.shields.io/badge/web2_classes-20-brightgreen?style=flat-square)
![Web3](https://img.shields.io/badge/web3_classes-10-yellow?style=flat-square)

<sub>Burp MCP &nbsp;·&nbsp; HackerOne MCP &nbsp;·&nbsp; Autonomous Mode &nbsp;·&nbsp; CA: [`J6VzBAGnyy…UdGpump`](https://pump.fun/coin/J6VzBAGnyyNEyzyHhauwg3ofRctFxnTLzQCcjUdGpump)</sub>

</div>

<br>

## What Is This?

**Bug bounty hunting** is when companies pay you real money to find security vulnerabilities in their websites and apps before bad actors do. Platforms like HackerOne and Bugcrowd connect hunters with companies. Payouts range from $100 to $1,000,000+ depending on severity.

**This tool** is a plugin for [Claude Code](https://claude.ai/claude-code) (Anthropic's AI coding assistant) that turns it into a professional bug bounty hunting partner. Instead of juggling 15 different tools and writing reports from scratch, you just type a command and the AI handles the rest.

**In plain terms:**
- You give it a target website
- It automatically scans the site, finds vulnerabilities, validates they're real, and writes a professional report
- It remembers what you found on past targets and applies that knowledge to new ones
- You can even put it on autopilot and let it hunt on its own while you sleep

**Who is it for?**
- Security researchers who want to move faster
- Bug bounty hunters who are tired of the manual grind
- People learning security who want AI guidance at every step

<br>

## Before vs. After

Most hunters waste hours on things that shouldn't take that long. Here's the shift:

| Before | After |
|:---|:---|
| Run 10+ tools manually, hope for the best | AI orchestrates everything in the right order |
| Write reports from scratch (45 min each) | `report-writer` agent generates submission-ready reports in 60s |
| Forget what worked last month | **Memory system** — patterns from target A inform target B |
| Submit bugs without proper validation | **7-Question Gate** kills weak findings before you waste time reporting |
| Can't see live browser traffic | **Burp MCP** — AI reads your proxy history in real time |
| Hunt one endpoint at a time | **`/autopilot`** runs the full hunt loop while you watch |

<br>

## Quick Start

> **Prerequisite:** You need [Claude Code](https://claude.ai/claude-code) installed. It's Anthropic's free AI coding tool that runs in your terminal.

**Step 1 — Install tools + skills**

```bash
git clone https://github.com/shuvonsec/claude-bug-bounty.git
cd claude-bug-bounty
chmod +x install_tools.sh && ./install_tools.sh   # installs scanning tools (subfinder, httpx, nuclei...)
chmod +x install.sh && ./install.sh               # installs AI skills + commands into Claude Code
```

**Step 2 — Start hunting**

```bash
claude                          # open Claude Code in your terminal

/recon target.com               # step 1: map the target (subdomains, live pages, URLs)
/hunt target.com                # step 2: test for vulnerabilities
/validate                       # step 3: make sure the finding is real before writing it up
/report                         # step 4: generate a professional submission report
```

**That's the core loop.** Four commands, full workflow.

**Step 3 — Go autonomous**

```bash
/autopilot target.com --normal  # AI does the whole thing, pauses for your review at the end
/pickup target.com              # continue where you left off on a previous target
/intel target.com               # get CVEs + disclosed reports relevant to this target
```

<br>

> **Don't use Claude Code?** Run the Python tools directly:
> ```bash
> python3 tools/hunt.py --target target.com
> ./tools/recon_engine.sh target.com
> ```

<br>

## How It Works

A team of specialists, each doing one job. Claude orchestrates; memory persists across sessions.

```mermaid
flowchart TD
    You([You]) --> Claude[Claude Code]
    Burp[Burp MCP<br/>browser traffic] -.-> Claude
    H1[HackerOne MCP<br/>program intel] -.-> Claude
    Claude --> Recon[Recon<br/>subdomains · URLs · APIs]
    Claude --> Hunt[Hunt<br/>test &amp; validate]
    Claude --> Report[Report<br/>H1 · Bugcrowd · Immunefi]
    Recon --> Memory[(Hunt Memory<br/>persistent across sessions)]
    Hunt --> Memory
    Report --> Memory
    Memory -.feeds back.-> Claude
```

Run the whole loop, or any step on its own.

<br>

## Commands

### The Core 4 (start here)

| Command | Argument | What It Does | When |
|:---|:---|:---|:---|
| `/recon` | `target.com` | Maps subdomains, live pages, APIs, and runs basic scans | Always first |
| `/hunt` | `target.com` | Tests for vulns using the right technique per tech stack | After recon |
| `/validate` | — | 7-question check before you write the report | Pre-report |
| `/report` | — | Generates H1 · Bugcrowd · Intigriti · Immunefi report | Post-validation |

### Power Commands

| Command | What It Does |
|:---|:---|
| `/autopilot target.com` | AI runs the full loop autonomously — recon → hunt → validate → report |
| `/surface target.com` | Ranked list of the best places to test (informed by past findings) |
| `/pickup target.com` | Untested endpoints from last session — pick up where you left off |
| `/remember` | Saves the current finding or technique to memory for future use |
| `/intel target.com` | Pulls CVEs and disclosed reports relevant to this target |
| `/chain` | When you find bug A, finds the bugs B and C that usually come with it |
| `/scope <asset>` | Checks if a domain or URL is in scope before you test it |
| `/triage` | Quick 2-minute go/no-go check — keep investigating or move on? |
| `/web3-audit <contract>` | Full smart contract security audit, 10 bug class checklist |
| `/token-scan <contract>` | Scans a meme coin / token for rug pull signals (EVM + Solana) |
| `/memory-gc` | Inspect or rotate hunt-memory JSONL files (10 MB cap, keeps 3 backups) |

<br>

## AI Agents

8 specialized agents, each built for one job:

| Agent | What It Does |
|:---|:---|
| **recon-agent** | Finds all subdomains, live hosts, and URLs for a target |
| **report-writer** | Writes professional, impact-first reports that get paid |
| **validator** | Runs the 7-Question Gate — kills weak findings before you waste time |
| **web3-auditor** | Audits smart contracts for 10 common vulnerability classes |
| **chain-builder** | When you find one bug, finds the chain of related bugs |
| **autopilot** | Runs the whole hunt loop autonomously with safety checkpoints |
| **recon-ranker** | Ranks the attack surface so you test the highest-value targets first |
| **token-auditor** | Fast meme coin / token rug pull and security analysis |

<br>

## What's New

### v4.2.0 — Memory Rotation (Apr 2026)

- **Auto-rotation for hunt memory** — `audit.jsonl`, `patterns.jsonl`, and `journal.jsonl` no longer grow forever. Files rotate at 10 MB and keep 3 backups, fully transparent to writers (safe under `fcntl.LOCK_EX` for concurrent processes).
- **`/memory-gc`** — new slash command to inspect, force-rotate, or purge backup files in the hunt-memory tree.
- **22 new tests** covering rotation primitives, multi-process concurrent writes, and disk-full `OSError` propagation.

### v4.1.0 — Auto-Memory + README (Apr 2026)

- **Auto-memory at session end** — the AI now automatically logs what it tested and found after every hunt session. Memory used to stay empty until you manually ran `/remember`. Now the flywheel starts on day 1.
- README badge and stats updated, `install_tools.sh` added to Quick Start (was missing)
- `hunt-memory/` added to `.gitignore` (contains full URL history, shouldn't be committed)

### v4.0.0 — Meme Coin Security Module (Apr 2026)

- **`/token-scan <contract>`** — automated rug pull scanner for EVM and Solana tokens
- **`skills/meme-coin-audit/`** — 8 token bug classes: mint authority, freeze authority, LP locks, honeypot detection, bonding curve exploits, Solana SPL checks
- **New agent:** `token-auditor`

### v3.1.1 — CI/CD Scanner (Mar 2026)

- **GitHub Actions security scanning** built into the recon pipeline
- Auto-detects GitHub orgs from recon data and scans their workflow files
- 52 rules, 81.6% GHSA coverage — catches expression injection, secret leaks, supply chain attacks

<details>
<summary><b>Older releases (v3.1.0, v3.0.0, v2.x)</b></summary>
<br>

**v3.1.0 — Hunting Methodology Skill**
- `skills/bb-methodology/` — mindset + 5-phase non-linear workflow, decision trees per vuln class, 20-min rotation clock

**v3.0.0 — The Bionic Hunter**
- `/autopilot` — full autonomous hunt loop with `--paranoid`, `--normal`, `--yolo` modes
- Hunt memory — journal, pattern DB, target profiles, cross-target learning
- Burp MCP — AI reads your proxy history in real time
- HackerOne MCP — search disclosed reports, get program stats and policy
- `/intel`, `/pickup`, `/remember`, `/surface` commands

**v2.1.0 — 20 Vuln Classes**
- MFA/2FA bypass and SAML/SSO attacks added (classes 19 and 20)
- NoSQL injection, command injection, SSTI, HTTP smuggling, WebSocket payloads added to arsenal

</details>

<br>

## What It Can Find

<details>
<summary><b>20 Web2 Vulnerability Classes</b> — click to expand</summary>
<br>

These are the types of security bugs it looks for in regular websites and APIs:

| Vulnerability | What It Means | Typical Payout |
|:---|:---|:---|
| **IDOR** | Accessing another user's data by changing a number in the URL | $500 - $5K |
| **Auth Bypass** | Getting into accounts or admin panels without permission | $1K - $10K |
| **XSS** | Injecting malicious scripts into web pages | $500 - $5K |
| **SSRF** | Making the server fetch internal resources it shouldn't | $1K - $15K |
| **Business Logic** | Exploiting flaws in how the app is supposed to work | $500 - $10K |
| **Race Conditions** | Sending requests at the same time to get double rewards/credits | $500 - $5K |
| **SQL Injection** | Manipulating the database through user inputs | $1K - $15K |
| **OAuth/OIDC** | Breaking the "Login with Google/GitHub" flows | $500 - $5K |
| **File Upload** | Uploading malicious files that get executed | $500 - $5K |
| **GraphQL** | Auth bypass and data leaks through GraphQL APIs | $1K - $10K |
| **LLM/AI** | Prompt injection and IDOR in AI-powered features | $500 - $10K |
| **API Misconfig** | Mass assignment, JWT attacks, broken CORS | $500 - $5K |
| **Account Takeover** | Taking over someone else's account | $1K - $20K |
| **SSTI** | Template injection that leads to code execution | $2K - $10K |
| **Subdomain Takeover** | Claiming expired subdomains (GitHub Pages, S3, Heroku) | $200 - $5K |
| **Cloud/Infra** | Exposed S3 buckets, EC2 metadata, Firebase, Kubernetes | $500 - $20K |
| **HTTP Smuggling** | Confusing front-end and back-end servers to bypass security | $5K - $30K |
| **Cache Poisoning** | Poisoning CDN caches to serve malicious content to others | $1K - $10K |
| **MFA Bypass** | Getting past two-factor authentication | $1K - $10K |
| **SAML/SSO** | Breaking enterprise single sign-on implementations | $2K - $20K |

</details>

<details>
<summary><b>10 Web3 / Smart Contract Bug Classes</b> — click to expand</summary>
<br>

These are bugs in blockchain smart contracts, common on Immunefi:

| Vulnerability | What It Means | Typical Payout |
|:---|:---|:---|
| **Accounting Desync** | Contract's math gets out of sync with reality | $50K - $2M |
| **Access Control** | Functions that should be admin-only aren't | $50K - $2M |
| **Incomplete Code Path** | Edge cases that drain funds | $50K - $2M |
| **Off-By-One** | Math errors that let attackers take more than they should | $10K - $100K |
| **Oracle Manipulation** | Manipulating price feeds to exploit DeFi protocols | $100K - $2M |
| **ERC4626 Attacks** | Vault share inflation attacks | $50K - $500K |
| **Reentrancy** | Calling back into a contract before it finishes | $10K - $500K |
| **Flash Loan** | Using uncollateralized loans to manipulate prices | $100K - $2M |
| **Signature Replay** | Reusing signed transactions | $10K - $200K |
| **Proxy/Upgrade** | Exploiting upgradeable contract patterns | $50K - $2M |

</details>

<br>

## Installation

### What You Need First

```bash
# macOS
brew install go python3 node jq

# Linux (Ubuntu/Debian)
sudo apt install golang python3 nodejs jq
```

You also need [Claude Code](https://claude.ai/claude-code) installed and a free account.

### Install

```bash
git clone https://github.com/shuvonsec/claude-bug-bounty.git
cd claude-bug-bounty
chmod +x install_tools.sh && ./install_tools.sh   # scanning tools (subfinder, httpx, nuclei, etc.)
chmod +x install.sh && ./install.sh               # AI skills + commands into Claude Code
```

### API Keys

<details>
<summary><b>Chaos API</b> (recommended for better subdomain discovery)</summary>
<br>

1. Sign up free at [chaos.projectdiscovery.io](https://chaos.projectdiscovery.io)
2. Add your key:

```bash
export CHAOS_API_KEY="your-key-here"
echo 'export CHAOS_API_KEY="your-key-here"' >> ~/.zshrc
```

</details>

<details>
<summary><b>Optional keys</b> (even better subdomain coverage)</summary>
<br>

Add to `~/.config/subfinder/config.yaml`:
- [VirusTotal](https://www.virustotal.com) — free
- [SecurityTrails](https://securitytrails.com) — free tier
- [Censys](https://censys.io) — free tier
- [Shodan](https://shodan.io) — paid

</details>

<br>

## The Rules (Always Active)

These apply every session, no exceptions:

```
 1. READ FULL SCOPE FIRST   — only test what the program says you can
 2. ONLY REAL BUGS          — "Can an attacker do this RIGHT NOW?" if no, stop
 3. KILL WEAK FINDINGS FAST — 30-second check saves hours of wasted reporting
 4. NEVER GO OUT OF SCOPE   — one wrong request can get you banned
 5. 5-MINUTE RULE           — no progress after 5 min? move to the next target
 6. VALIDATE BEFORE REPORT  — run /validate before you spend 30 min writing
 7. IMPACT FIRST            — start with the bugs that have the worst consequences
```

<br>

## Related Projects

| Repo | What It's For |
|:---|:---|
| **[claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)** | This — full hunting pipeline from recon to report |
| **[web3-bug-bounty-hunting-ai-skills](https://github.com/shuvonsec/web3-bug-bounty-hunting-ai-skills)** | Smart contract security — 10 bug classes, Foundry PoC templates |
| **[public-skills-builder](https://github.com/shuvonsec/public-skills-builder)** | Turns 500+ public bug writeups into Claude skill files |

<br>

## Contributing

PRs welcome. Best contributions:
- New vulnerability scanners or detection modules
- Payload additions to `skills/security-arsenal/SKILL.md`
- Real-world methodology improvements (with evidence from paid reports)
- Support for more platforms (YesWeHack, Synack, HackenProof)

```bash
git checkout -b feature/your-contribution
git commit -m "Add: short description"
git push origin feature/your-contribution
```

---

<div align="center">

### Connect

[GitHub](https://github.com/shuvonsec) &nbsp;·&nbsp; [Twitter](https://x.com/shuvonsec) &nbsp;·&nbsp; [LinkedIn](https://linkedin.com/in/shuvonsec) &nbsp;·&nbsp; [shuvonsec@gmail.com](mailto:shuvonsec@gmail.com)

<br>

**Built by bug hunters, for bug hunters.** &nbsp;·&nbsp; If this helped you find a bug, [leave a star ⭐](https://github.com/shuvonsec/claude-bug-bounty)

<br>

<sub>MIT License · For authorized security testing only. Test only within an approved bug bounty program scope. Never test systems without explicit written permission. Follow responsible disclosure.</sub>

</div>
