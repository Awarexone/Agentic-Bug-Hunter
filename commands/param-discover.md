---
description: Discover hidden HTTP parameters on a URL or list of URLs using Arjun (or x8 fallback). Hidden params are gold for IDOR, SSRF, LFI, redirect, and authorization bypass — often missed by automated scanners. Usage: /param-discover <url> | /param-discover -l <urls-file>
---

# /param-discover

Find HTTP parameters the application accepts but doesn't link from any visible
endpoint. Useful when an endpoint looks unreachable or returns a generic
response — often a hidden `id`, `user`, `redirect`, `file`, or `debug` param
unlocks the real surface.

## Usage

```
/param-discover https://api.target.com/v2/user
/param-discover -l recon/target.com/live/urls.txt
```

## Tools

`tools/param_discovery.sh` prefers `arjun` (richer JSON output, ML-driven diffing) and
falls back to `x8` (Rust, faster on huge wordlists). Install hint:

```
pipx install arjun
# or
cargo install x8
```

## Why it pays

- Hidden `redirect=` / `next=` → open redirect, SSRF, OAuth code theft chain.
- Hidden `id=` / `user_id=` → IDOR.
- Hidden `file=` / `path=` / `template=` → LFI, SSTI, RFI.
- Hidden `debug=` / `admin=` → privilege escalation toggles.
- Hidden `callback=` / `jsonp=` → reflected XSS via JSONP.

After discovery, feed the URL+param into `/hunt --vuln-class <best-fit>` for
targeted testing.

## Output

`findings/params/<timestamp>/`:
- `arjun.json` / `arjun_summary.txt` — endpoint → discovered params
- `x8.txt` — diff-based hits when arjun is unavailable
