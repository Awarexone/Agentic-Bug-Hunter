---
description: Gather employee names + email patterns for password spray prep. Pipeline theHarvester (search engines + CT logs) -> derive names from email local-parts -> username-anarchy expansion. LinkedIn search is opt-in via --with-linkedin. Output -> recon/<target>/osint/. Usage /osint-employees <target.com> [--with-linkedin] [--with-pydictor-social]
---

# /osint-employees

Gather employee names and email patterns for the spray-prep phase. Read-only OSINT — no auth probing.

## Usage

```
/osint-employees target.com
/osint-employees target.com --with-linkedin                    # add CrossLinked LinkedIn search
/osint-employees target.com --with-pydictor-social             # add personal-style password candidates
/osint-employees target.com --company "Acme Corp"              # override auto-detected company name
/osint-employees target.com --sources duckduckgo,crtsh --limit 200
```

## Pipeline

1. **theHarvester** — emails + names from search engines + CT logs
   - Default sources: `duckduckgo,brave,yahoo,mojeek,crtsh,certspotter,hackertarget,otx`
   - All free, no API keys required, no LinkedIn-specific scraping
2. **Derive names** from email local-parts (`john.smith@x.com` → `John Smith`)
   - Ambiguous patterns (`jsmith@x.com`) are skipped — not enough signal
3. **(opt) CrossLinked** — LinkedIn employee names via Google/Bing dorks
   - `--with-linkedin` opts in
   - Uses search engines only; no LinkedIn auth required
4. **username-anarchy** — expand "First Last" into 32+ username permutations
   - `john`, `j.smith`, `jsmith`, `smithj`, `js`, `john.smith`, etc.
5. **(opt) pydictor --extend** — personal-style password candidates
   - `--with-pydictor-social` opts in
   - Generates `firstname2025!`, `firstname123` style mutations

## Output

```
recon/<target>/osint/
├── theharvester.json      # raw theHarvester output
├── emails.txt             # extracted emails (unique)
├── employee-names.txt     # "First Last" per line
├── usernames.txt          # all username permutations
└── (personal-passwords.txt if --with-pydictor-social)
```

## Why opt-in for LinkedIn

CrossLinked queries Google/Bing for `site:linkedin.com "Company Name"` — public search, no LinkedIn auth required. But some BBP programs classify LinkedIn-based employee identification under "social engineering reconnaissance" which they don't permit. **Read the program scope before running with `--with-linkedin`**.

## Why the default is conservative

For mature, security-conscious targets (Twilio, Stripe, etc.) the default sources often return very few emails — that's expected. These companies have good email hygiene. Add `--with-linkedin` for those targets if scope permits.

## What this does NOT do

- **No LinkedIn auth scraping** — LinkedInDumper was intentionally excluded from PR #1 (requires LinkedIn account, OPSEC cost).
- **No paid OSINT** — DeHashed, IntelX, Shodan, Censys all skipped (no API key required by default).
- **No spray execution** — PR #5 will add `/spray` (with mandatory scope check and lockout warning).
- **No automated combining** — `usernames.txt` and `wordlists/ranked.txt` are kept separate; you manually combine before spray.

## Dependencies

Install once: `./install_tools.sh --with-credential-attack`

## Underlying tool

`tools/osint_employees.sh <target> [flags]` — call directly if you prefer a non-slash interface.
