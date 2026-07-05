---
description: Pull every in-scope asset for a bug bounty program across HackerOne, Bugcrowd, Intigriti, YesWeHack, and Immunefi in one shot. Uses bbscope when authenticated, otherwise the public bounty-targets-data dump. Output is one host per line, ready to feed into /recon. Usage: /scope-aggregate <program-handle> [--platform h1|bc|it|ywh|imf|all]
---

# /scope-aggregate

Aggregate the full in-scope asset list for a public program without copy-pasting
from the program page.

## Usage

```
/scope-aggregate shopify
/scope-aggregate yelp --platform h1
/scope-aggregate --list-programs --platform h1
```

## What it does

`tools/scope_aggregator.sh` runs in two strategies:

1. **bbscope** (`sw33tLie/bbscope`) — authenticated multi-platform pull. Best
   freshness, but needs platform tokens in env (`H1_USERNAME`, `H1_API_KEY`,
   `BUGCROWD_EMAIL`, etc.). Tries it first when installed.
2. **bounty-targets-data dump** (`arkadiyt/bounty-targets-data`) — hourly
   public dump of every public program. No auth needed; fallback if bbscope
   returns nothing.

Output: `~/.cache/bbhunt/scope/<program>.scope.txt` (one host per line, with
wildcards stripped to bare domains).

## Next steps

```
/scope ~/.cache/bbhunt/scope/<program>.scope.txt   # human verification
/recon ~/.cache/bbhunt/scope/<program>.scope.txt   # feed into recon (domain-list mode)
```

`recon_engine.sh` already supports passing a file in place of a domain — it
reads each line as a pre-resolved scope entry and skips subdomain enumeration
(programs without wildcards benefit hugely).

## When NOT to use

- Programs with `*.target.com`-style wildcards: aggregator gives you the
  *seed*; still run `/recon target.com` to brute the wildcard.
- Private programs you cannot install bbscope creds for: bounty-targets-data
  only covers public scope, so private invites won't appear.
