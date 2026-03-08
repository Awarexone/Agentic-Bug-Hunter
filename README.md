# Claude Bug Bounty Hunter 🎯

> **AI-powered bug bounty hunting toolkit** — Run Claude as your co-pilot for recon, vulnerability discovery, validation, and report generation. Built for HackerOne, Bugcrowd, Intigriti, and Immunefi hunters.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![Platform: macOS/Linux](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)]()

---

## What Is This?

A modular, Claude-assisted bug bounty framework that chains together:

- **Recon** — subdomain enumeration, live host detection, URL crawling, JS analysis
- **Intelligence** — CVE lookup, disclosed report analysis, tech stack mapping
- **Hunting** — IDOR, SSRF, XSS, SQLi, race conditions, OAuth flaws, GraphQL, zero-days
- **Validation** — 4-gate finding validator with CVSS scoring
- **Reporting** — Auto-generates HackerOne/Bugcrowd-ready markdown reports

Claude reads your target, suggests attack vectors, validates findings, and writes your report. You click submit.

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/claude-bug-bounty.git
cd claude-bug-bounty

# 2. Install all external tools (subfinder, httpx, nuclei, ffuf, etc.)
chmod +x install_tools.sh
./install_tools.sh

# 3. Full hunt on a target
python3 hunt.py --target hackerone.com

# 4. Quick recon only
./recon_engine.sh hackerone.com --quick

# 5. Validate a finding before submitting
python3 validate.py

# 6. Generate a report
python3 report_generator.py findings/
```

---

## Tool Overview

| Script | Purpose | Usage |
|--------|---------|-------|
| `hunt.py` | Full pipeline orchestrator | `python3 hunt.py --target example.com` |
| `recon_engine.sh` | Subdomain + live host + URL recon | `./recon_engine.sh example.com` |
| `learn.py` | Fetch CVEs + disclosed reports for tech stack | `python3 learn.py --tech "nextjs,graphql"` |
| `mindmap.py` | Generate Mermaid attack mindmap | `python3 mindmap.py --target example.com --tech "react,jwt"` |
| `validate.py` | 4-gate bug validator + CVSS scorer | `python3 validate.py` |
| `report_generator.py` | Auto-generate H1/Bugcrowd reports | `python3 report_generator.py findings/` |
| `cve_hunter.py` | Detect tech and match known CVEs | `python3 cve_hunter.py example.com` |
| `zero_day_fuzzer.py` | Smart fuzzer for novel bugs | `python3 zero_day_fuzzer.py https://example.com` |
| `h1_idor_scanner.py` | IDOR detection via parameter swap | `python3 h1_idor_scanner.py --target example.com` |
| `h1_oauth_tester.py` | OAuth flow tester (PKCE, state, redirect) | `python3 h1_oauth_tester.py --target example.com` |
| `h1_race.py` | Race condition detector | `python3 h1_race.py --url https://example.com/api/redeem` |
| `h1_mutation_idor.py` | GraphQL mutation IDOR scanner | `python3 h1_mutation_idor.py --target example.com` |
| `hai_probe.py` | LLM/AI feature vulnerability prober | `python3 hai_probe.py --target example.com` |
| `hai_payload_builder.py` | Prompt injection payload generator | `python3 hai_payload_builder.py` |
| `vuln_scanner.sh` | Nuclei + dalfox + sqlmap orchestrator | `./vuln_scanner.sh example.com` |
| `sneaky_bits.py` | JS secret finder + endpoint extractor | `python3 sneaky_bits.py --url https://example.com` |
| `install_tools.sh` | Install all Go + Python dependencies | `./install_tools.sh` |

### Support Scripts (`scripts/`)

| Script | Purpose |
|--------|---------|
| `dork_runner.py` | Google dork automation for target recon |
| `full_hunt.sh` | End-to-end hunt shell wrapper |

---

## Using Claude as Your Co-Pilot

This toolkit is designed to be used **inside Claude Code** (or with the Claude API). Claude reads your recon output and tells you what to hunt.

### With Claude Code (Recommended)

```bash
# Install Claude Code
npm install -g @anthropic-ai/claude-code

# Start a session
claude

# Then just tell Claude what you want:
# "Run recon on hackerone.com and find IDORs"
# "Validate this finding before I submit"
# "Write a HackerOne report for this SSRF"
```

Claude will use the tools in this repo automatically.

### With the Claude API

See [`CLAUDE_INTEGRATION.md`](CLAUDE_INTEGRATION.md) for building your own Claude-powered hunting agent.

---

## Full Hunt Pipeline

```bash
# Step 1 — Recon
./recon_engine.sh target.com
# Output: recon/target.com/{subs.txt, live-hosts.txt, urls.txt}

# Step 2 — Learn what bugs exist for this tech
python3 learn.py --tech "nextjs,graphql,jwt" --target target.com

# Step 3 — Generate attack mindmap
python3 mindmap.py --target target.com --type api --tech "graphql,jwt"

# Step 4 — Hunt
python3 hunt.py --target target.com --scan-only

# Step 5 — Validate findings
python3 validate.py --output findings/target-finding.md

# Step 6 — Generate report
python3 report_generator.py findings/
```

---

## Vulnerability Classes Covered

### Web2
- **IDOR** — object-level + field-level, GraphQL mutation IDOR
- **SSRF** — redirect chain bypass, DNS rebinding, cloud metadata
- **XSS** — reflected, stored, DOM, postMessage, CSP bypass
- **SQLi** — error-based, blind, time-based, ORM bypass
- **OAuth flaws** — missing PKCE, state bypass, redirect_uri abuse
- **Race conditions** — parallel requests, TOCTOU
- **Cache poisoning** — header injection, unkeyed parameters
- **Business logic** — price manipulation, workflow bypass
- **File upload** — extension bypass, polyglots, path traversal
- **XXE** — entity injection, out-of-band exfil
- **HTTP smuggling** — CL.TE, TE.CL, request tunneling

### AI / LLM Features
- **Prompt injection** — direct + indirect
- **Chatbot IDOR** — accessing other users' conversation history
- **System prompt extraction** — leaking confidential instructions
- **LLM-assisted RCE** — code execution via AI tool use
- **ASCII smuggling** — invisible unicode exfiltration channels

### Web3 / DeFi
- **Reentrancy** — single + cross-function + cross-contract
- **Flash loan attacks** — price oracle manipulation
- **Access control** — missing onlyOwner, role bypass
- **Integer overflow/underflow** — Solidity math bugs
- **Signature replay** — missing nonce/chain ID checks

---

## Installation

### Prerequisites

```bash
# macOS
brew install go python3 node jq

# Linux (Ubuntu/Debian)
sudo apt install golang python3 nodejs jq
```

### Auto-Install All Tools

```bash
chmod +x install_tools.sh
./install_tools.sh
```

This installs:
- **Go tools**: subfinder, httpx, dnsx, nuclei, katana, waybackurls, gau, dalfox, ffuf, anew, qsreplace, assetfinder, gf, interactsh-client
- **Python tools**: sqlmap, XSStrike, SecretFinder, LinkFinder
- **nuclei-templates**: ProjectDiscovery template library

### Manual Install (if auto-install fails)

```bash
# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/gf@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Python tools
git clone https://github.com/sqlmapproject/sqlmap ~/tools/sqlmap
git clone https://github.com/s0md3v/XSStrike ~/tools/XSStrike
git clone https://github.com/m4ll0k/SecretFinder ~/tools/SecretFinder
git clone https://github.com/GerbenJavado/LinkFinder ~/tools/LinkFinder

# Nuclei templates
nuclei -update-templates
```

---

## Wordlists (`wordlists/`)

| File | Use case |
|------|----------|
| `common.txt` | General directory fuzzing |
| `api-endpoints.txt` | REST API endpoint discovery |
| `params.txt` | Parameter fuzzing |
| `raft-medium-dirs.txt` | Medium-size directory list (RAFT) |
| `sensitive-files.txt` | Backup files, configs, secrets |

---

## Configuration

Copy and edit the config template:

```bash
cp config.example.json config.json
```

Key settings:
```json
{
  "chaos_api_key": "YOUR_PROJECTDISCOVERY_KEY",
  "h1_api_token": "YOUR_HACKERONE_API_TOKEN",
  "output_dir": "./findings",
  "recon_dir": "./recon"
}
```

Get your ProjectDiscovery Chaos API key free at: https://chaos.projectdiscovery.io

---

## Output Structure

```
claude-bug-bounty/
├── recon/
│   └── target.com/
│       ├── subs.txt          # All subdomains
│       ├── live-hosts.txt    # Live HTTP(S) hosts
│       ├── urls.txt          # Crawled URLs
│       └── intel.md          # CVE + disclosed report intel
├── findings/
│   └── target-vuln-type.md  # Validated findings
└── reports/
    └── h1-report-YYYYMMDD.md # Ready-to-submit report
```

---

## Claude Prompts for Hunters

Use these prompts directly in Claude Code after running recon:

```
# Attack surface mapping
"I've run recon on [target]. Here's my live-hosts.txt and urls.txt.
What are the highest-priority endpoints to test for IDOR?"

# Finding validation
"I found [vuln]. Here's the request/response. Is this submittable?
What's the CVSS score and business impact?"

# Report writing
"Write a HackerOne report for this [vuln type] finding.
Here's the PoC: [steps]. Target: [platform]."

# Tech stack hunting
"Target uses NextJS + GraphQL + JWT. What are the top 5 bug classes
I should test, in order of payout likelihood?"
```

---

## Ethical Use & Legal Notice

**This toolkit is for authorized security testing only.**

- Only test targets within your approved scope (HackerOne, Bugcrowd, Intigriti, Immunefi programs)
- Never test systems you don't have explicit permission to test
- Follow responsible disclosure — report findings to the vendor, not publicly
- Read and follow each program's rules of engagement before hunting

By using this toolkit, you agree to use it only for legal, authorized security testing.

---

## Contributing

PRs welcome. Especially interested in:
- New vulnerability-specific scanners
- Better Claude prompt templates
- Support for more platforms (YesWeHack, Synack, etc.)

```bash
git clone https://github.com/YOUR_USERNAME/claude-bug-bounty.git
cd claude-bug-bounty
# Make your changes
git checkout -b feature/my-scanner
git commit -m "Add: my-scanner for X vuln class"
git push origin feature/my-scanner
# Open a PR
```

---

## Related Resources

- [HackerOne Hacktivity](https://hackerone.com/hacktivity) — Disclosed reports
- [Bugcrowd Crowdstream](https://bugcrowd.com/crowdstream) — Public findings
- [ProjectDiscovery Chaos](https://chaos.projectdiscovery.io) — Free subdomain datasets
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Payload reference
- [HackTricks](https://book.hacktricks.xyz) — Attack technique reference
- [PortSwigger Web Academy](https://portswigger.net/web-security) — Free labs

---

## License

MIT — Free to use, modify, and distribute. See [LICENSE](LICENSE) for details.

---

*Built by bug hunters, for bug hunters. Star ⭐ if this helped you find a bug.*
