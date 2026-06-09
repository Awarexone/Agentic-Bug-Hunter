<p align="center">
  <img src="logo.png" alt="Claude Bug Bounty" width="280"/>
</p>

<h1 align="center">Claude Bug Bounty</h1>

<p align="center">
  <b>AI-powered bug bounty hunting — recon to report, in your terminal.</b><br>
  <sub>Find vulnerabilities. Validate them. Get paid.</sub>
</p>

<p align="center">
  <a href="https://github.com/shuvonsec/claude-bug-bounty/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB.svg?style=flat-square&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/Tests-passing-brightgreen.svg?style=flat-square" alt="Tests">
  <a href="https://claude.ai/claude-code"><img src="https://img.shields.io/badge/Claude_Code-Plugin-D97706.svg?style=flat-square" alt="Claude Code"></a>
  <a href="#contributing"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square" alt="PRs Welcome"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> · <a href="#commands">Commands</a> · <a href="#what-it-finds">What It Finds</a> · <a href="#installation">Install</a> · <a href="FAQ.md">FAQ</a>
</p>

---

## What Is This?

A [Claude Code](https://claude.ai/claude-code) plugin that turns your AI assistant into a professional bug bounty hunting partner. Give it a target — it handles recon, tests for vulnerabilities, validates findings through a strict gate, and writes submission-ready reports for HackerOne, Bugcrowd, Intigriti, and Immunefi.

**It remembers everything.** Patterns found on one target inform the next. Sessions pick up where they left off.

> Requires [Claude Code](https://claude.ai/claude-code) with a Claude Pro / Max plan or an Anthropic API key.

---

## Quick Start

**Option A — let Claude install it** *(recommended)*

Open your terminal, run `claude`, then paste:

```text
Install the Claude Bug Bounty toolkit from https://github.com/shuvonsec/claude-bug-bounty
into ~/tools/. Clone the repo, run ./install_tools.sh then ./install.sh.
Verify /recon /hunt /validate /report are available. If anything breaks, tell me
which tool failed and the exact one-line fix.
```

**Option B — manual**

```bash
git clone https://github.com/shuvonsec/claude-bug-bounty.git
cd claude-bug-bounty
chmod +x install_tools.sh && ./install_tools.sh   # subfinder · httpx · nuclei · katana · ffuf · dalfox
chmod +x install.sh      && ./install.sh          # skills + commands → ~/.claude/
```

**Then start hunting:**

```bash
claude
/recon target.com        # map the attack surface
/hunt target.com         # test for vulnerabilities
/validate                # run the 7-Question Gate
/report                  # write the submission
```

---

## Commands

### Core Workflow

| Command | What It Does |
|:---|:---|
| `/recon target.com` | Subdomain enum · live host probing · URL crawl · nuclei sweep |
| `/hunt target.com` | Tests IDOR · auth bypass · SSRF · XSS · SQLi · logic flaws and more |
| `/validate` | 7-Question Gate — kills weak findings before you waste time reporting |
| `/report` | Generates an H1 · Bugcrowd · Intigriti · Immunefi submission in 60s |
| `/autopilot target.com` | Full loop, autonomous — scope → recon → hunt → validate → report |

### Recon & Enumeration

| Command | What It Does |
|:---|:---|
| `/surface target.com` | Ranked attack surface from recon data + memory |
| `/scope-aggregate <program>` | All in-scope assets across H1 · Bugcrowd · Intigriti · YWH · Immunefi |
| `/cloud-recon --keyword <name>` | Public S3 · Azure · GCP buckets + CloudFlare-bypass origin IPs |
| `/param-discover <url>` | Hidden HTTP parameters via Arjun · x8 |
| `/secrets-hunt --js-bundle <dir>` | Leaked credentials in source, JS bundles, or a GitHub org |
| `/takeover --recon <dir>` | Subdomain takeover candidates via dnsReaper · subjack |
| `/scan-cves <host>` | Focused nuclei high/critical sweep + optional log4j-scan |
| `/bypass-403 <url>` | Header · method · encoding tricks against 403/401 |

### Smart Contract (Web3)

| Command | What It Does |
|:---|:---|
| `/web3-audit <contract.sol>` | 10-class smart contract audit with Foundry PoC template |
| `/token-scan <contract>` | Rug pull scanner — mint authority · LP lock · honeypot · bonding curve |

### Session & Utility

| Command | What It Does |
|:---|:---|
| `/pickup target.com` | Resume from last session — untested endpoints first |
| `/intel target.com` | CVEs + disclosed reports relevant to this target |
| `/chain` | Bug A found → finds bugs B and C that chain with it |
| `/scope <asset>` | Checks if a domain or URL is in scope before you test it |
| `/triage` | Quick 2-minute go/no-go check |
| `/remember` | Logs the current finding or technique to hunt memory |
| `/memory-gc` | Inspect or rotate hunt-memory JSONL files (10 MB cap, 3 backups) |
| `/arsenal [tool]` | Lists installed external tools or prints an install hint |

---

## What It Finds

<details>
<summary><b>20 Web2 Vulnerability Classes</b></summary>
<br>

| Vulnerability | Typical Payout |
|:---|:---|
| IDOR / BOLA | $500 – $5K |
| Auth Bypass | $1K – $10K |
| XSS (Stored / Reflected / DOM) | $500 – $5K |
| SSRF | $1K – $15K |
| Business Logic | $500 – $10K |
| Race Conditions | $500 – $5K |
| SQL Injection | $1K – $15K |
| OAuth / OIDC | $500 – $5K |
| File Upload → RCE | $500 – $10K |
| GraphQL Auth Bypass | $1K – $10K |
| LLM / Prompt Injection | $500 – $10K |
| API Misconfiguration (mass assignment · JWT · CORS) | $500 – $5K |
| Account Takeover | $1K – $20K |
| SSTI | $2K – $10K |
| Subdomain Takeover | $200 – $5K |
| Cloud / Infra Exposure | $500 – $20K |
| HTTP Request Smuggling | $5K – $30K |
| Cache Poisoning | $1K – $10K |
| MFA / 2FA Bypass | $1K – $10K |
| SAML / SSO Attack | $2K – $20K |

</details>

<details>
<summary><b>10 Web3 / Smart Contract Bug Classes</b></summary>
<br>

| Vulnerability | Typical Payout |
|:---|:---|
| Accounting Desync | $50K – $2M |
| Access Control | $50K – $2M |
| Incomplete Code Path | $50K – $2M |
| Off-By-One | $10K – $100K |
| Oracle Manipulation | $100K – $2M |
| ERC4626 Share Inflation | $50K – $500K |
| Reentrancy | $10K – $500K |
| Flash Loan Attack | $100K – $2M |
| Signature Replay | $10K – $200K |
| Proxy / Upgrade | $50K – $2M |

</details>

---

## AI Agents

Nine specialists, each built for one job:

| Agent | Role |
|:---|:---|
| `recon-agent` | Subdomain enum · live host discovery · URL crawl |
| `report-writer` | Impact-first reports that get paid, not N/A'd |
| `validator` | Runs the 7-Question Gate — kills weak findings |
| `web3-auditor` | Smart contract audit across 10 bug classes |
| `chain-builder` | Bug A → finds bugs B and C that chain with it |
| `autopilot` | Full hunt loop with safety checkpoints |
| `recon-ranker` | Ranks attack surface by highest-value targets first |
| `token-auditor` | Meme coin / token rug pull and security scan |
| `credential-hunter` | Wordlist gen → OSINT → breach-check → spray (hard-stop before spray) |

---

## How It Works

```
You  →  /recon  →  /hunt  →  /validate  →  /report
              ↓                     ↓
         Hunt Memory          7-Question Gate
      (persists across      (kills weak findings
          sessions)          before you submit)
```

Every tool in the pipeline is gated on whether it's installed — missing tools are skipped, not errors. Auth headers set once carry through httpx · katana · ffuf · nuclei · dalfox automatically.

---

## Installation

**Prerequisites:**

```bash
# macOS
brew install go python3 jq

# Linux (Ubuntu/Debian)
sudo apt install golang python3 jq
```

**Scanning tools** (installs subfinder · httpx · nuclei · katana · ffuf · gau · dnsx · nmap · dalfox and more):

```bash
chmod +x install_tools.sh && ./install_tools.sh
```

**AI skills + commands** into Claude Code:

```bash
chmod +x install.sh && ./install.sh
```

**Other agent harnesses:**

```bash
./install.sh --agent opencode    # OpenCode
./install.sh --agent pi          # Pi Agent
./install.sh --agent codex       # Codex
./install.sh --agent all         # every supported target
```

**Optional: Chaos API key** (better subdomain coverage)

```bash
export CHAOS_API_KEY="your-key"
echo 'export CHAOS_API_KEY="your-key"' >> ~/.zshrc
```

---

## Rules

These run every session, no exceptions:

```
1. Read full scope first — only test what the program says you can
2. Real bugs only       — "Can an attacker do this RIGHT NOW?" if no, stop
3. Kill weak findings   — 30-second check saves hours of wasted reporting
4. Never go out of scope — one wrong request can get you banned
5. 5-minute rule        — no progress after 5 min? move to the next target
6. Validate before report — /validate before spending 30 min writing
7. Impact first         — test the bugs with the worst consequences first
```

---

## Contributing

PRs welcome. Most valuable:
- New scanner modules or detection techniques
- Payload additions to `skills/security-arsenal/SKILL.md`
- Methodology improvements backed by paid reports
- Platform support (YesWeHack · Synack · HackenProof)

```bash
git checkout -b feature/your-contribution
git commit -m "feat: short description"
git push origin feature/your-contribution
```

---

## Star History

<a href="https://www.star-history.com/?repos=shuvonsec%2Fclaude-bug-bounty&type=date&legend=top-left">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=shuvonsec/claude-bug-bounty&type=date&theme=dark&legend=top-left" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=shuvonsec/claude-bug-bounty&type=date&legend=top-left" />
    <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=shuvonsec/claude-bug-bounty&type=date&legend=top-left" />
  </picture>
</a>

---

<div align="center">

[GitHub](https://github.com/shuvonsec) · [Twitter](https://x.com/shuvonsec) · [shuvonsec@gmail.com](mailto:shuvonsec@gmail.com)

<br>

**Built by bug hunters, for bug hunters.**

<br>

<sub>MIT License · For authorized security testing only. Always test within an approved bug bounty program scope.</sub>

</div>
