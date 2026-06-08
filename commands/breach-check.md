---
description: HIBP k-anonymity check on a password wordlist. Enriches each password with its breach count, ranks DESC. Free API (no key), only first 5 chars of SHA-1 sent. Output -> <input>-ranked.txt. Usage /breach-check <wordlist> [--min-count N] [--max-count N] [--with-counts]
---

# /breach-check

Rank a password wordlist by HaveIBeenPwned breach count. Used between `/wordlist-gen` and spray to surface which candidates have **proven human use**.

## Usage

```
/breach-check recon/target.com/wordlists/ranked.txt
/breach-check ranked.txt --with-counts                              # also dump TSV
/breach-check ranked.txt --max-count 1000000                        # drop generic passwords (>1M)
/breach-check ranked.txt --min-count 1                              # only keep proven-real passwords
/breach-check ranked.txt --limit 5000                               # test/preview first 5k (lex-sorted slice)
/breach-check ranked.txt --limit 5000 --shuffle                     # random 5k sample (avoid ASCII-sort bias)
```

## What this does

For each password in the wordlist:
1. Compute SHA-1 hash
2. Send only the **first 5 chars** to `api.pwnedpasswords.com/range/{prefix}` (k-anonymity)
3. HIBP returns ~500 candidate suffix-count pairs
4. Match locally to get exact breach count for your password

**Privacy**: HIBP never sees the full password. Add-Padding header is used to obscure prefix distribution from network observers.

## Why rank by breach count

| Range | Meaning | Spray strategy |
|---|---|---|
| **0** | Never leaked | Could be company-specific OR truly random — context-dependent |
| **1–1000** | "Sweet spot" — proven human use but not yet in every spray list | **Prioritize** — high signal/cost ratio |
| **1k–1M** | Mainstream password | Usually already tried by previous attackers |
| **>1M** | Generic ("password", "123456") | Skip — every WAF expects these, lockout risk |

## Example (real HIBP results)

```
209,972,844    123456                ← generic, drop
 52,256,179    password              ← generic, drop
 30,799,395    qwerty                ← generic, drop
  1,505,362    Password123           ← generic-ish
  1,406,394    letmein               ← generic-ish
        180    flexdemo              ← SWEET SPOT — real but rare
          0    twilio2025            ← company-specific, untested
          0    xpkqwmnvbzabc12345    ← random, untested
```

`flexdemo` = 180 means real humans have used this exact password 180 times across known breaches. It's a real password pattern, but not generic enough to be in every spray list. Highest value for spray.

## Pipeline position

```
/wordlist-gen target.com           -> ranked.txt (cewler+hashcat, 100k-300k candidates)
/osint-employees target.com        -> usernames.txt + personal-passwords.txt
/breach-check ranked.txt           -> ranked-ranked.txt (HIBP-enriched, sorted by breach count)
                                       └─ filter --max-count 1000000 to drop boring generic
[PR #5] /spray <login> -u users -p ranked-ranked.txt
```

## Output

- **`<input>-ranked.txt`** — passwords sorted by breach count DESC (most-leaked first; one per line)
- **`<input>-ranked-counts.tsv`** *(with `--with-counts`)* — `count\tpassword` for analysis

## Performance

HIBP allows ~25 req/sec; default 20 concurrent threads ~= 1500 req/min.

- 1,000 passwords  → ~50 seconds
- 10,000           → ~5 minutes
- 100,000          → ~50 minutes
- 300,000+         → consider `--limit` or pre-shrink with `/wordlist-gen --mode minimal`

Grouping by SHA-1 prefix reduces API calls. For a 300k wordlist, expect ~270k unique prefixes (10% collision typical).

## Dependencies

Pure Python 3.9+, no external deps (uses urllib + hashlib + ThreadPoolExecutor from stdlib).

## Underlying tool

`tools/breach_checker.py <wordlist> [flags]` — call directly if you prefer a non-slash interface.
