---
description: Run full recon pipeline on a target by invoking tools/recon_engine.sh — subdomain enum (Chaos API + subfinder + amass + crt.sh + wayback), httpx live host probing with tech detection, nmap port scan, gau URL collection, JS analysis, ffuf directory fuzzing, parameter discovery, config exposure check, CI/CD workflow scan. Auto-emits structured JSON inventory. Outputs to recon/<target>/. Usage: /recon target.com
---

# /recon

Run the full recon pipeline on a target. **Always invoke the production script directly** — do not re-implement the steps inline.

## Usage

```
/recon target.com
/recon target.com --quick         # skip amass + reduce ffuf coverage
/recon 192.0.2.0/24               # CIDR — skips subdomain enum, runs nmap sweep
/recon 192.0.2.10                 # single IP — skips subdomain enum
/recon path/to/scope.txt          # Domain list — skips subdomain enum, uses file contents
```

The domain-list form is for programs without wildcard scope: pre-resolved hosts go in a text file (one per line, `#` comments allowed) and recon jumps straight to live-host probing + URL crawl + nuclei against just those entries.

Or with specific focus:
```
/recon target.com --focus api
/recon target.com --focus auth
/recon target.com --fast     (skip historical URLs)
```

The pipeline is fully implemented in [tools/recon_engine.sh](../tools/recon_engine.sh). Run it like this — **always with absolute paths to avoid cwd-shift bugs**:

```bash
# Use the project root as the anchor — never cd into recon/<target>/ first
PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
TARGET="target.com"

bash "$PROJECT_ROOT/tools/recon_engine.sh" "$TARGET"
# Optional: bash "$PROJECT_ROOT/tools/recon_engine.sh" "$TARGET" --quick

# Emit structured JSON inventory (machine-readable, queryable with jq)
python3 "$PROJECT_ROOT/tools/recon_to_json.py" "$PROJECT_ROOT/recon/$TARGET"
```

The script runs 8 phases automatically:

| Phase | What it does | Output |
|---|---|---|
| 1 | Subdomain enum (subfinder + amass + crt.sh + wayback) | `subdomains/{subfinder,amass,crtsh,wayback_subs,all}.txt` |
| 2 | httpx live host probing (status + title + tech + length) | `live/{httpx_full,urls,status_200,status_3xx,status_403,status_401}.txt` |
| 2.5 | wafw00f fingerprint on top live hosts | `waf/fingerprint.txt` (per-host WAF vendor: cloudflare/aws/imperva/f5/none) |
| 3 | nmap port scan (top 1000 ports) | `ports/{nmap_results,nmap_greppable,open_ports}.txt` |
| 4 | URL collection (gau + wayback fallback) | `urls/{gau,all,with_params,js_files,api_endpoints,sensitive_paths}.txt` |
| 5 | JS endpoint extraction + secret grep | `js/{endpoints,potential_secrets}.txt` |
| 6 | ffuf directory fuzzing (top 5 hosts) | `dirs/ffuf_*.json` |
| 6.5 | Config file exposure check (.env, env.js, config.js) | `exposure/config_files.txt` |
| 7 | Parameter discovery (frequency + interesting params) | `params/{param_frequency,unique_params,interesting_params}.txt` |
| 8 | CI/CD workflow scan (sisakulint on detected GitHub orgs) | `cicd/<org>/scan_results.txt` |

After the script, [tools/recon_to_json.py](../tools/recon_to_json.py) emits:
- `inventory/subdomains.json` — structured asset inventory with hostname / IP / CDN / status / title / tech / discovery_method per live host

## Important — Common Mistakes to Avoid

1. **DO NOT** re-implement the recon pipeline inline. The script handles trap-on-exit cleanup, GNU/macOS timeout shimming, CIDR expansion, scope-lock for IP targets, source-attribution preservation. Re-implementing inline loses all of these.

2. **DO NOT** `cd recon/$TARGET` first. The script computes `RECON_DIR` from the script's own location (`$BASE_DIR/recon/$TARGET`). If you `cd` first and then call `mkdir -p recon/$TARGET` in any subsequent step, you create the double-nested `recon/<target>/recon/<target>/` directory bug.

3. **DO NOT** skip the JSON inventory step. It's needed for cross-run diff, attack-surface ranking, and hunt memory integration.

## Output Layout

After both commands run, you have at `recon/<target>/`:

```
recon/<target>/
├── subdomains/
│   ├── subfinder.txt        Per-source files (preserve attribution)
│   ├── amass.txt
│   ├── crtsh.txt
│   ├── wayback_subs.txt
│   └── all.txt              Merged & deduped
├── live/
│   ├── httpx_full.txt       URL [status] [title] [tech] [length]
│   ├── urls.txt             Just URLs
│   └── status_{200,3xx,401,403}.txt
├── ports/
│   ├── nmap_results.txt
│   ├── nmap_greppable.txt
│   └── open_ports.txt
├── urls/
│   ├── all.txt              Merged
│   ├── with_params.txt      Potential injection points
│   ├── js_files.txt
│   ├── api_endpoints.txt
│   └── sensitive_paths.txt
├── js/
│   ├── endpoints.txt        Extracted from JS files
│   └── potential_secrets.txt  ⚠️ Review immediately
├── dirs/ffuf_*.json
├── exposure/
│   └── config_files.txt     ⚠️ Exposed .env/env.js/config.js
├── params/
│   ├── param_frequency.txt
│   ├── unique_params.txt
│   └── interesting_params.txt   ⚠️ url/redirect/file/path/etc
├── cicd/<org>/scan_results.txt
└── inventory/
    └── subdomains.json      ✨ Structured JSON inventory (queryable with jq)
```

## What to Do Next

After recon completes, prioritize in this order:

1. **Check `exposure/config_files.txt`** — exposed config = instant high-severity finding
2. **Check `js/potential_secrets.txt`** — leaked API keys / tokens
3. **Query `inventory/subdomains.json`** with `jq` for high-value targets:
   ```bash
   # Subdomains NOT behind a CDN (likely direct origin servers)
   jq '.live_subdomains[] | select(.cdn == null) | {hostname, ip, status, tech}' \
      recon/$TARGET/inventory/subdomains.json

   # Subdomains running specific tech (e.g., admin panels, dev tools)
   jq '.live_subdomains[] | select(.tech | any(test("WordPress|Jenkins|Grafana|Kibana"; "i")))' \
      recon/$TARGET/inventory/subdomains.json

   # 401/403 hosts (auth gates worth poking)
   jq '.live_subdomains[] | select(.status == 401 or .status == 403)' \
      recon/$TARGET/inventory/subdomains.json
   ```
4. **Open `live/status_200.txt`** in browser — explore interesting ones manually
5. **Check `params/interesting_params.txt`** — injection candidates
6. **Run `/hunt $TARGET`** to start active vulnerability testing

## 5-Minute Rule

If after running this pipeline you see:
- All hosts return 403 even after `tools/bypass_403.sh` + wafw00f bypass, or return only static marketing pages
- No API endpoints visible
- nuclei returns 0 medium/high findings
- `inventory/subdomains.json` shows all assets behind CDN with no direct IPs

→ **Move on to a different target.**

## Troubleshooting

- **Script fails immediately** — check `which subfinder httpx nmap dnsx ffuf gau` and install missing Go tools (`~/go/bin/` should be in PATH).
- **`subdomains/all.txt` is empty for IP/CIDR target** — expected; the script skips subdomain enum and writes the IP directly. Check `subdomains/all.txt` is just the IP/CIDR hosts.
- **JSON inventory shows `total_discovered: 0`** — likely the `recon_engine.sh` script failed mid-way; re-run, or check the script's `echo` summary at the end for which phase ran. Use `--no-dns` flag if DNS is blocked.
- **Need to skip DNS lookup** — `python3 tools/recon_to_json.py recon/$TARGET --no-dns` is faster but produces no IP/CDN fields.
- **`TypeError: unsupported operand type(s) for |: 'type' and 'NoneType'`** — your `python3` is < 3.10. The schema layer uses modern union syntax (`str | None`). Run with `python3.13 tools/recon_to_json.py ...` (or any 3.10+) instead. macOS users: `/usr/bin/python3` is 3.9; install via Homebrew with `brew install python@3.13` then use `python3.13` explicitly.
