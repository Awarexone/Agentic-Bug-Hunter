<div align="center">

<img src="https://img.shields.io/badge/Claude-AI%20Co--Pilot-orange?style=for-the-badge&logo=anthropic&logoColor=white" />
<img src="https://img.shields.io/badge/Bug%20Bounty-HackerOne%20%7C%20Bugcrowd%20%7C%20Intigriti-red?style=for-the-badge" />
<img src="https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-blue?style=for-the-badge&logo=linux&logoColor=white" />

# Claude Bug Bounty Hunter

**The AI-native bug bounty framework.** Claude acts as your co-pilot — mapping attack surfaces, guiding hunts, validating findings, and writing your reports. You focus on the target. Claude handles the rest.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![Stars](https://img.shields.io/github/stars/shuvonsec/claude-bug-bounty?style=social)](https://github.com/shuvonsec/claude-bug-bounty/stargazers)

[Quick Start](#quick-start) · [Tools](#tool-reference) · [Pipeline](#full-hunt-pipeline) · [Claude Prompts](#claude-prompts) · [Install](#installation)

</div>

---

## What It Does

```
Target → Recon → Intel → Hunt → Validate → Report → Submit
```

Every step is Claude-assisted. Drop into Claude Code, point it at a target, and it will:

- Enumerate subdomains, live hosts, and crawl endpoints
- Pull CVEs and disclosed H1 reports for the detected tech stack
- Generate a prioritized attack mindmap
- Run scanners for IDOR, SSRF, XSS, SQLi, OAuth, GraphQL, LLM injection
- Walk you through the 4-gate validation checklist
- Write a submission-ready HackerOne or Bugcrowd report

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/shuvonsec/claude-bug-bounty.git
cd claude-bug-bounty
chmod +x install_tools.sh && ./install_tools.sh

# Run a full hunt
python3 hunt.py --target hackerone.com

# Or step by step
./recon_engine.sh target.com
python3 learn.py --tech "nextjs,graphql,jwt" --target target.com
python3 hunt.py --target target.com --scan-only
python3 validate.py
python3 report_generator.py findings/
```

### With Claude Code (Recommended)

```bash
npm install -g @anthropic-ai/claude-code
cd claude-bug-bounty
claude
```

Then just talk:
> *"Run recon on target.com and tell me what to hunt"*
> *"I found a potential IDOR — validate it"*
> *"Write a HackerOne report for this SSRF"*

Claude reads your recon files, reasons about the attack surface, and drives the tools.

---

## Tool Reference

### Core Pipeline

| Tool | What It Does |
|------|-------------|
| `hunt.py` | Master orchestrator — chains recon → scan → report |
| `recon_engine.sh` | Subdomain enum, DNS resolution, live host detection, URL crawling |
| `learn.py` | Pulls CVEs + disclosed reports for a tech stack from GitHub Advisory + NVD |
| `mindmap.py` | Generates a Mermaid attack mindmap with a prioritized test checklist |
| `validate.py` | Interactive 4-gate validator — scope, impact, duplicate check, CVSS score |
| `report_generator.py` | Outputs a formatted HackerOne/Bugcrowd markdown report |

### Vulnerability Scanners

| Tool | Targets |
|------|---------|
| `h1_idor_scanner.py` | Object-level + field-level IDOR via parameter swapping |
| `h1_mutation_idor.py` | GraphQL mutation IDOR — cross-account object access |
| `h1_oauth_tester.py` | OAuth flows — PKCE enforcement, state bypass, redirect_uri abuse |
| `h1_race.py` | Race conditions — parallel request timing, TOCTOU |
| `zero_day_fuzzer.py` | Smart fuzzer for novel bugs scanners miss (logic, edge cases, access control) |
| `cve_hunter.py` | Fingerprints tech stack and matches against known CVEs |
| `vuln_scanner.sh` | Orchestrates nuclei + dalfox + sqlmap |

### AI / LLM Testing

| Tool | Targets |
|------|---------|
| `hai_probe.py` | Probes AI chatbot features for IDOR, prompt injection, data exfil |
| `hai_payload_builder.py` | Generates prompt injection payloads (direct, indirect, ASCII smuggling) |
| `hai_browser_recon.js` | Browser-side recon of AI feature endpoints |

### Utilities

| Tool | What It Does |
|------|-------------|
| `sneaky_bits.py` | JS secret finder + endpoint extractor from JS bundles |
| `target_selector.py` | Scores and ranks bug bounty programs by ROI |
| `scripts/dork_runner.py` | Google dork automation for passive recon |
| `scripts/full_hunt.sh` | Shell wrapper for the full pipeline |

---

## Full Hunt Pipeline

```bash
# 1. Recon — enumerate subdomains, resolve DNS, find live hosts, crawl URLs
./recon_engine.sh target.com
# → recon/target.com/{subs.txt, live-hosts.txt, urls.txt}

# 2. Intel — pull CVEs and prior disclosures for the tech stack
python3 learn.py --tech "nextjs,graphql,jwt" --target target.com
# → recon/target.com/intel.md

# 3. Attack map — generate prioritized hunting checklist
python3 mindmap.py --target target.com --type api --tech "graphql,jwt"

# 4. Hunt — run all scanners
python3 hunt.py --target target.com --scan-only

# 5. Validate — 4-gate check before writing anything
python3 validate.py --output findings/target-finding.md

# 6. Report — generate submission-ready markdown
python3 report_generator.py findings/
```

---

## Vulnerability Classes Covered

<details>
<summary><strong>Web2 (click to expand)</strong></summary>

| Class | Techniques |
|-------|-----------|
| **IDOR** | Object-level, field-level, GraphQL mutation, UUID enumeration |
| **SSRF** | Redirect chain bypass, DNS rebinding, cloud metadata (169.254.x), protocol abuse |
| **XSS** | Reflected, stored, DOM, postMessage, CSP bypass, mXSS |
| **SQLi** | Error-based, blind, time-based, ORM bypass, second-order |
| **OAuth** | Missing PKCE, state parameter bypass, redirect_uri abuse, implicit flow downgrade |
| **Race Conditions** | Parallel requests, TOCTOU, limit overrun, coupon reuse |
| **Cache Poisoning** | Unkeyed headers, parameter cloaking, fat GET |
| **Business Logic** | Price manipulation, workflow skip, negative quantity, role escalation |
| **File Upload** | Extension bypass, MIME confusion, polyglots, path traversal in filename |
| **XXE** | Classic entity injection, blind OOB via DNS/HTTP |
| **HTTP Smuggling** | CL.TE, TE.CL, TE.TE, H2.CL request tunneling |

</details>

<details>
<summary><strong>AI / LLM Features (click to expand)</strong></summary>

| Class | Techniques |
|-------|-----------|
| **Prompt Injection** | Direct override, indirect via document/URL, jailbreak chains |
| **Chatbot IDOR** | Cross-account history access, conversation ID enumeration |
| **System Prompt Leak** | Extraction via roleplay, encoding bypass, token boundary probing |
| **LLM RCE** | Code execution via AI tool use, sandboxed environment escape |
| **ASCII Smuggling** | Invisible unicode characters as covert exfil channels |

</details>

<details>
<summary><strong>Web3 / DeFi (click to expand)</strong></summary>

| Class | Techniques |
|-------|-----------|
| **Reentrancy** | Single-function, cross-function, cross-contract, read-only |
| **Flash Loan Attacks** | Price oracle manipulation, collateral inflation |
| **Access Control** | Missing `onlyOwner`, misconfigured roles, function visibility |
| **Integer Issues** | Overflow, underflow, precision loss, division before multiplication |
| **Signature Replay** | Missing nonce, chain ID not included, front-running signatures |

</details>

---

## Claude Prompts

Copy-paste these into Claude Code after running recon:

```
# Map the attack surface
"I've run recon on [target]. Here's live-hosts.txt and urls.txt.
What are the highest-priority endpoints to test for IDOR and why?"

# Tech-stack guided hunting
"Target uses NextJS + GraphQL + JWT auth. Rank the top 5 bug classes
I should hunt, ordered by payout likelihood on HackerOne."

# Validate a finding
"I found [vuln]. Here's the request and response. Walk me through
the 4 validation gates. What's the CVSS 3.1 score and business impact?"

# Write the report
"Write a HackerOne report for this [vuln type].
PoC steps: [1, 2, 3]. Target: [URL]. Impact: [what attacker can do]."

# Chain a low finding
"I have an open redirect at [URL]. How can I chain this into
an OAuth code theft or ATO? What conditions do I need?"
```

---

## Installation

**Prerequisites**

```bash
# macOS
brew install go python3 node jq

# Linux (Debian/Ubuntu)
sudo apt install golang python3 nodejs jq
```

**One-command install**

```bash
chmod +x install_tools.sh && ./install_tools.sh
```

Installs: `subfinder` `httpx` `dnsx` `nuclei` `katana` `waybackurls` `gau` `dalfox` `ffuf` `anew` `qsreplace` `assetfinder` `gf` `interactsh-client` `sqlmap` `XSStrike` `SecretFinder` `LinkFinder` + nuclei-templates

**Configuration**

```bash
cp config.example.json config.json
# Add your ProjectDiscovery Chaos API key and HackerOne token
```

---

## Output Structure

```
claude-bug-bounty/
├── recon/
│   └── target.com/
│       ├── subs.txt           # All subdomains
│       ├── live-hosts.txt     # Live HTTP(S) hosts with status codes
│       ├── urls.txt           # Crawled URLs
│       └── intel.md           # CVE + disclosed report intel
├── findings/
│   └── target-vuln-type.md   # Validated finding notes
└── reports/
    └── h1-report-YYYYMMDD.md # Submission-ready report
```

---

## Resources

- [HackerOne Hacktivity](https://hackerone.com/hacktivity) — Disclosed reports
- [Bugcrowd Crowdstream](https://bugcrowd.com/crowdstream) — Public findings
- [ProjectDiscovery Chaos](https://chaos.projectdiscovery.io) — Free subdomain datasets
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Payload reference
- [HackTricks](https://book.hacktricks.xyz) — Attack technique bible
- [PortSwigger Web Academy](https://portswigger.net/web-security) — Free vuln labs

---

## Legal

**For authorized security testing only.**

Only test targets within an approved bug bounty scope. Never test systems without explicit permission. Follow responsible disclosure — report to the vendor, not publicly. Read each program's rules of engagement before hunting.

---

## Contributing

PRs welcome — especially new vuln scanners, Claude prompt templates, and platform support (YesWeHack, Synack).

```bash
git checkout -b feature/my-scanner
git commit -m "Add: scanner for X vuln class"
git push origin feature/my-scanner
# Open a PR
```

---

<div align="center">

MIT License · Built by bug hunters, for bug hunters

**Star ⭐ if this helped you find a bug**

</div>
