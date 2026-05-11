---
description: Run a focused nuclei CVE sweep against a host or recon directory, optionally filtered by year. Runs log4j-scan in parallel when installed for legacy enterprise stacks. Usage: /scan-cves <host-or-file> [--year 2024] | /scan-cves --recon <recon-dir>
---

# /scan-cves

Targeted nuclei scan of the `cve/` template directory plus optional log4j-scan.

## Usage

```
/scan-cves https://target.com
/scan-cves --recon recon/target.com
/scan-cves --year 2024 recon/target.com/live/urls.txt
```

## Why a separate command

`/recon` already runs a broad nuclei phase across every severity — this command
narrows to **known CVEs only**, which:

- Cuts the runtime by an order of magnitude (high/critical CVE templates only).
- Surfaces signals that pay even on dormant programs (CVE-2021-44228 still hits
  on legacy enterprise hosts).
- Lets you re-scan one or two URLs without rerunning the full pipeline.

Set `NUCLEI_NO_UPDATE=1` to skip the template update on each run when
iterating quickly.

## Output

`findings/cve/<timestamp>/`:
- `nuclei_cve.jsonl` — one finding per line (template ID, host, severity)
- `log4j.txt` — optional log4j-scan output when the scanner is installed

## After a hit

1. Confirm the version manually (don't trust the template — show the response).
2. Check program scope and reward table; many CVEs are explicitly out-of-scope
   if the program already disclosed them or is mid-patch.
3. Provide a non-destructive PoC: a single request that proves the version is
   vulnerable, not a working exploit chain.
