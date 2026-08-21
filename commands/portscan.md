---
description: Scan a host for open ports and flag the NON-HTTP services the HTTP-only recon pipeline can't see (SSH, databases, Redis, Docker API, RDP). Usage: /portscan <host> [--top 1000] [-p 22,6379] | /portscan -l hosts.txt
---

# /portscan

The main recon pipeline is HTTP-only (httpx / nuclei / katana), so open ports
that don't speak HTTP are invisible. This maps the full service surface and
pulls the interesting, often-forgotten ports to the top — the ones that turn
into instant wins.

## Usage

```
/portscan target.com                 # top-100 ports
/portscan target.com --top 1000
/portscan target.com -p 22,6379,27017
/portscan -l recon/target.com/subdomains/resolved.txt --json
/portscan target.com --smap          # passive (Shodan) — no packets sent
```

Run directly:

```bash
tools/port_scanner.py target.com --top 1000
```

## Tooling

Wraps ProjectDiscovery's **naabu** (fast SYN/CONNECT scan), falling back to
**smap** (Shodan-backed, sends no packets — handy when active scanning is out of
scope). Both are registered in `tools/external_arsenal.sh`. If neither is
installed the command prints install hints and exits cleanly.

## What it flags

Any open, non-web port with a known attack surface, e.g.:

| Port | Service | Why it matters |
|---|---|---|
| 6379 | redis | unauth → RCE / full data dump |
| 2375 | docker | unauth Docker API → instant host RCE |
| 27017 | mongodb | unauth → database dump |
| 9200 | elasticsearch | unauth → index dump |
| 3306 / 5432 / 1433 | mysql / postgres / mssql | database exposed to the internet |
| 3389 | rdp | weak creds / BlueKeep-class |
| 445 | smb | null session / EternalBlue-class |

Web ports (80/443/8080/…) are counted but not flagged — the rest of the
pipeline already covers those.

## Chain

`/portscan` → non-web service found → pivot with the matching technique (e.g.
unauth Redis → `CONFIG SET` webshell, exposed DB → dump, Docker API → container
escape). Feed resolved subdomains from `/recon` straight in with `-l`.
