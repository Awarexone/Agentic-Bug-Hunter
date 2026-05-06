---
description: Run full recon pipeline on a target by invoking tools/recon_engine.sh — subdomain enum (subfinder + amass + crt.sh + wayback), httpx live host probing with tech detection, nmap port scan, gau URL collection, JS analysis, ffuf directory fuzzing, parameter discovery, config exposure check, CI/CD workflow scan. Outputs to recon/<target>/. Usage: /recon target.com
---

# /recon

Run the full recon pipeline on a target. **Always invoke the production script directly** — do not re-implement the steps inline.

## Usage

```
/recon target.com
/recon target.com --quick         (skip amass + reduce ffuf coverage)
/recon 10.0.0.0/24                (CIDR — skips subdomain enum, runs nmap sweep)
/recon path/to/scope.txt          (Domain list — skips subdomain enum, uses file contents)
```

The domain-list form is for programs without wildcard scope: pre-resolved hosts go in a text file (one per line, `#` comments allowed) and recon jumps straight to live-host probing + URL crawl + nuclei against just those entries.

## What This Does (One Step)

The pipeline is fully implemented in [tools/recon_engine.sh](../tools/recon_engine.sh). Run it like this — **always with absolute paths to avoid cwd-shift bugs**:

```bash
# Use the project root as the anchor — never cd into recon/<target>/ first
PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
TARGET="target.com"

bash "$PROJECT_ROOT/tools/recon_engine.sh" "$TARGET"
# Optional: bash "$PROJECT_ROOT/tools/recon_engine.sh" "$TARGET" --quick
```

The script runs 8 phases automatically:

| Phase | What it does | Output |
|---|---|---|
| 1 | Subdomain enum (subfinder + amass + crt.sh + wayback) | `subdomains/{subfinder,amass,crtsh,wayback_subs,all}.txt` |
| 2 | httpx live host probing (status + title + tech + length) | `live/{httpx_full,urls,status_200,status_3xx,status_403,status_401}.txt` |
| 3 | nmap port scan (top 1000 ports) | `ports/{nmap_results,nmap_greppable,open_ports}.txt` |
| 4 | URL collection (gau + wayback fallback) | `urls/{gau,all,with_params,js_files,api_endpoints,sensitive_paths}.txt` |
| 5 | JS endpoint extraction + secret grep | `js/{endpoints,potential_secrets}.txt` |
| 6 | ffuf directory fuzzing (top 5 hosts) | `dirs/ffuf_*.json` |
| 6.5 | Config file exposure check (.env, env.js, config.js) | `exposure/config_files.txt` |
| 7 | Parameter discovery (frequency + interesting params) | `params/{param_frequency,unique_params,interesting_params}.txt` |
| 8 | CI/CD workflow scan (sisakulint on detected GitHub orgs) | `cicd/<org>/scan_results.txt` |

## Important — Common Mistakes to Avoid

1. **DO NOT** re-implement the recon pipeline inline. The script handles trap-on-exit cleanup, GNU/macOS timeout shimming, CIDR expansion, scope-lock for IP targets, and source-attribution preservation. Re-implementing inline loses all of these.

2. **DO NOT** `cd recon/$TARGET` first. The script computes `RECON_DIR` from the script's own location (`$BASE_DIR/recon/$TARGET`). If you `cd` first and then call `mkdir -p recon/$TARGET` in any subsequent step, you create the double-nested `recon/<target>/recon/<target>/` directory bug.

## Output Layout

After the script runs, you have at `recon/<target>/`:

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
└── cicd/<org>/scan_results.txt
```

## What to Do Next

After recon completes, prioritize in this order:

1. **Check `exposure/config_files.txt`** — exposed config = instant high-severity finding
2. **Check `js/potential_secrets.txt`** — leaked API keys / tokens
3. **Open `live/status_200.txt`** in browser — explore interesting ones manually
4. **Check `params/interesting_params.txt`** — injection candidates (url/redirect/file/path)
5. **Run `/hunt $TARGET`** to start active vulnerability testing

## 5-Minute Rule

If after running this pipeline you see:
- All hosts return 403 or static marketing pages
- No API endpoints visible in `urls/api_endpoints.txt`
- No interesting parameters in `params/interesting_params.txt`
- nuclei returns 0 medium/high findings (if run separately)

→ **Move on to a different target.**

## Troubleshooting

- **Script fails immediately** — check `which subfinder httpx nmap dnsx ffuf gau` and install missing Go tools (`~/go/bin/` should be in PATH).
- **`subdomains/all.txt` is empty for IP/CIDR target** — expected; the script skips subdomain enum and writes the IP/expanded hosts directly.
- **`subdomains/all.txt` is empty for domain-list target** — check the file is readable and contains valid hostnames (one per line, `#` comments allowed).
