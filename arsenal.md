---
description: Show which external bug-bounty tools are installed on this machine and print install hints for the missing ones. Curated from high-signal repos. Use to bootstrap a fresh box or audit which optional capabilities are wired in. Usage: /arsenal | /arsenal <tool-name>
---

# /arsenal

Inspect the external tool inventory used by this plugin.

## Usage

```
/arsenal                       # full status table (installed vs missing)
/arsenal nuclei                # show install hint for a single tool
```

## What it covers

`tools/external_arsenal.sh` knows about ~50 tools across:

- **Recon** — subfinder, amass, assetfinder, bbot, theHarvester, dnsrecon, massdns, puredns, shuffledns, knockpy
- **Probing** — httpx, dnsx, naabu, smap, aquatone, eyewitness
- **Crawling** — katana, gau, waybackurls, waymore, hakrawler, gospider, cariddi
- **Fuzzing** — ffuf, feroxbuster, gobuster, arjun, x8
- **Scanning** — nuclei, dalfox, xsstrike, ghauri, sqlmap, fuxploider, log4j-scan, linkfinder
- **Secrets** — trufflehog, noseyparker, gitleaks, shhgit, git-hound
- **Cloud** — s3scanner, cloud_enum, cloudfail, scoutsuite
- **Takeover** — dnsreaper, subjack
- **Bypass** — byp4xx, whatwaf, unwaf
- **JWT/auth** — jwt_tool
- **Scope** — bbscope
- **Mobile** — mobsf, apkleaks, objection, jadx
- **OSINT** — maigret, pywhat, sublert
- **Misc** — gf, qsreplace, anew, interactsh-client

## Sourcing the helper

Other scripts source `external_arsenal.sh` to gate optional code paths:

```bash
. "$(dirname "$0")/external_arsenal.sh"
if _have nuclei; then nuclei -l hosts.txt -severity high; fi
```

Use `_have <tool>` rather than `command -v` so the install-hint table stays the
single source of truth for what is and isn't wired in.
