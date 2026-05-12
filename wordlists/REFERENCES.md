# Wordlist & Payload References

The lists in this directory are intentionally compact. For full hunts pull from the
upstream collections below — they ship orders of magnitude more entries plus
context-specific lists (graphql, cloud, mobile, etc.) you can swap into ffuf/nuclei.

## Bigger wordlists

| Source | Why | Install |
|---|---|---|
| `danielmiessler/SecLists` | The de-facto reference; web/discovery/passwords/usernames/payloads | `git clone https://github.com/danielmiessler/SecLists $HOME/SecLists` |
| `six2dez/OneListForAll` | "rockyou for web fuzzing" — single 5M-entry merged list | `git clone https://github.com/six2dez/OneListForAll` |
| `0xPugal/fuzz4bounty` | Curated 1337 lists for bounty fuzzing (params, sub, dirs) | `git clone https://github.com/0xPugal/fuzz4bounty` |
| `n0kovo/n0kovo_subdomains` | 3M subdomains scraped from SSL CT logs | `git clone https://github.com/n0kovo/n0kovo_subdomains` |
| `BrownBearSec/SDTO-realworld-subdomains` | Real-world subdomain takeover wordlist | `git clone https://github.com/BrownBearSec/SDTO-realworld-subdomains` |
| `Bo0oM/fuzz.txt` | Potentially dangerous files & paths | `curl -O https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt` |
| `glitchedgitz/cook` | Wordlist *generator* — combine known prefixes/suffixes/patterns | `go install github.com/glitchedgitz/cook@latest` |
| `D4Vinci/CWFF` | Generates a custom wordlist per target from its own pages | `pipx install cwff` |
| `musana/fuzzuli` | Generates dynamic backup-file wordlists from a domain | `go install github.com/musana/fuzzuli@latest` |

## Payload collections

| Source | Why | Install |
|---|---|---|
| `swisskyrepo/PayloadsAllTheThings` | The authoritative payload + bypass library (every class) | `git clone https://github.com/swisskyrepo/PayloadsAllTheThings` |
| `ZephrFish/Wordlists` | Mixed payload wordlists (XSS, XXE, CMD, traversal) | `git clone https://github.com/ZephrFish/Wordlists` |
| `thegsoinfosec/BurpSuite_payloads` | Burp Intruder payloads ripped from PayloadsAllTheThings | `git clone https://github.com/thegsoinfosec/BurpSuite_payloads` |
| `0xacb/recollapse` | Black-box regex fuzzer for normalisation/validation bypasses | `pipx install recollapse` |

## Nuclei templates (vuln signatures)

Nuclei ships its own community templates, but these add value:

| Source | Why |
|---|---|
| `projectdiscovery/nuclei-templates` | Default community templates — auto-updated by `nuclei -update-templates` |
| `0xKayala/NucleiFuzzer` | Wraps nuclei + ParamSpider for one-shot vuln fuzz |
| `trickest/cve` | Updated CVE PoCs (often ahead of nuclei templates) |

## Suggested layout

```
$HOME/wordlists/
  SecLists/          # full reference
  OneListForAll/
  fuzz4bounty/
  PayloadsAllTheThings/
nuclei-templates/    # `nuclei -update-templates` writes here by default
```

Set `WORDLIST_BASE=$HOME/wordlists` and most hunting scripts will pick them up.
