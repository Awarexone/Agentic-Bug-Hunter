---
description: Scan subdomains for takeover candidates (dangling CNAMEs to GitHub Pages, S3, Heroku, Shopify, etc.). Wraps dnsReaper (best signal) and subjack (fast Go fallback). With no scanner installed, runs a built-in fingerprint grep over a curated set of providers. Usage: /takeover <subdomains-file> | /takeover --recon <recon-dir>
---

# /takeover

Find subdomains pointing at services you can claim and serve content from.

## Usage

```
/takeover recon/target.com/subdomains/all.txt
/takeover --recon recon/target.com           # equivalent
```

## How it works

`tools/takeover_scanner.sh` tries each strategy in turn:

1. **dnsReaper** (`punk-security/dnsReaper`) — broadest fingerprint set, JSON output.
2. **subjack** (`haccer/subjack`) — fast Go scanner.
3. **Curl + fingerprint grep** fallback — minimal coverage but always runs.

## Scoring & submission

Subdomain takeover sits high on most program reward tables — typically
**$500–$5,000** depending on what the parent brand uses the subdomain for.
Before submitting:

- Confirm the dangling target service is actually claimable today (Heroku and
  GitHub Pages are easy; some providers now block re-claims by name).
- Take **only** the screenshot you need to prove control — never serve real
  content or interact with users from the claimed subdomain.
- Cross-reference `EdOverflow/can-i-take-over-xyz` for the per-provider claim
  instructions and known-good fingerprints.

## Output

`findings/takeover/<timestamp>/` with raw scanner JSON / text plus a
`fingerprint_grep.txt` summary of suspicious responses.
