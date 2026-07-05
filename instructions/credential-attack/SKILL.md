---
name: credential-attack
description: Password spray methodology for bug bounty — when to do it vs web-vuln hunting, the wordlist-gen + breach-check + osint-employees + spray pipeline, mode selection (http-form / oauth / o365 / okta), rate-limit + lockout tactics, BBP legal guardrails, success detection, and the spray → authenticated /hunt chain pattern. Use when assessing whether credential attack is worth running on a target, picking the right mode, or recovering from common pitfalls.
---

# CREDENTIAL ATTACK PIPELINE

Real-world initial-access vector. Verizon DBIR consistently ranks Stolen Credentials in the top 3 incident types. Most BB hunters skip this because they only try `rockyou.txt` and get rate-limited.

**Core principle:** humans pick lazy passwords. `{CompanyName}{Year}!`, `{ProductName}{Season}`, `{City}123`. Harvesting company-specific vocabulary (product names, office cities, internal project codes) before spraying is what makes the hit-rate go from 0.01% to 1%+.

This skill covers WHEN to use credential attack, HOW to chain the 4 commands, and the legal/operational guardrails.

---

## WHEN TO RUN CREDENTIAL ATTACK

Credential attack is a **parallel branch** to `/hunt`, not a replacement. Both come after `/recon`:

```
/recon ──┬──▶ /hunt (web vuln scan)         ──┐
         │                                     ├──▶ /validate ──▶ /report
         └──▶ /wordlist-gen → ... → /spray  ──┘
```

**Run it when:**
- Target has a discoverable login endpoint (web form / O365 / Okta / OAuth)
- Program scope **explicitly permits** authentication testing or credential testing
- You can stomach a 30-min-to-multi-hour run (with conservative defaults)

**Skip it when:**
- Program policy lists "credential stuffing", "brute force", or "password attacks" as out-of-scope (this is the majority)
- Target only has SSO via a provider you don't control (e.g., "Login with Google")
- The login endpoint is rate-limited so aggressively that even 1 attempt/30min triggers alerts

**KILL signals (don't even start):**
- No login surface in recon output
- WAF (Cloudflare with Bot Management, Akamai) on every auth endpoint
- Program runs an active red-team — they'll see your spray immediately
- You don't have a clean wordlist yet (running rockyou.txt is a waste of lockouts)

---

## THE 4-STAGE PIPELINE

```
/wordlist-gen     ──▶  /breach-check     ──▶  /osint-employees   ──▶  /spray
(company words)        (rank by HIBP)         (real usernames)         (live attempts)
```

You can run stages 1+2 in parallel with stage 3 (they share no inputs).

### Stage 1 — `/wordlist-gen <target>`

Crawls the target website with `cewler`, deduplicates, applies hashcat rules to mutate (`flexdemo` → `flexdemo!`, `Flexdemo`, `flexdemo123`, `flexdemo2025`...).

**Mode selection:**

| Mode | Rules | When |
|---|---|---|
| `minimal` | top10_2025 (10 rules) | Cautious spray, paranoid program |
| `balanced` *(default)* | best66 (66 rules) | Standard — best signal/noise |
| `aggressive` | OneRuleToRuleThemAll (52k) | **Offline cracking only**, NOT spray (too many candidates) |

**Filter selection:**

| Filter | When |
|---|---|
| `strict` *(default)* | API-doc-heavy sites (Twilio, Stripe). Drops CSS hex colors, URL slugs, random API tokens that cewler harvests as "words" |
| `loose` | Marketing sites without API examples — keeps everything cewler found |

**Output:** `recon/<target>/wordlists/ranked.txt` — typically 50k-500k candidates depending on site size.

---

### Stage 2 — `/breach-check <wordlist>`

Sends only first 5 chars of SHA-1 to HIBP (k-anonymity), enriches each password with its real-world breach count. **Free, no API key, full passwords never leave your machine.**

**Breach-count interpretation:**

| Range | Meaning | Spray strategy |
|---|---|---|
| **0** | Never leaked | Could be company-specific OR truly random |
| **1-1000** | "Sweet spot" — proven human use, not yet in every spray list | **Prioritize** |
| **1k-1M** | Mainstream | Usually already tried by previous attackers |
| **>1M** | Generic (`password`, `123456`) | Skip — every WAF expects these |

**Standard filter for spray prep:** `--max-count 1000000` drops the boring generic stuff while keeping the sweet spot.

**Performance:** ~5 minutes for 10k passwords, ~50 minutes for 100k. Use `--limit N --shuffle` to sample if your wordlist is huge.

---

### Stage 3 — `/osint-employees <target>`

`theHarvester` (search engines + CT logs) → derive names from email local-parts → `username-anarchy` permutations.

**Default mode is conservative:**
- Sources: `duckduckgo,brave,yahoo,mojeek,crtsh,certspotter,hackertarget,otx`
- No LinkedIn-specific scraping
- No paid OSINT (DeHashed, IntelX, Shodan)

**Opt-in flags:**
- `--with-linkedin` — adds CrossLinked (Google/Bing dorks against `site:linkedin.com`). **Read program policy first** — some BBPs forbid employee identification.
- `--with-pydictor-social` — pydictor generates name-derived password candidates (`john2025`, `john!2024`).

**Realistic expectations:**

| Target type | Expected emails | Expected names |
|---|---|---|
| US/EU SaaS (Twilio, Stripe) | 5-50 | depends — many CTOs are public |
| State utility (Taipower, etc.) | **0** | 0 (no English-named LinkedIn profiles) |
| Local SME | 0-10 | 0-5 |

For mature security-conscious targets, expect very few emails. The CT-log hostnames theHarvester finds are **separate value** — feed them back into `/recon` for more attack surface (this happened in our Taipower run: 0 emails but 59 new subdomains).

---

### Stage 4 — `/spray <login-url> --mode <mode>`

The **most dangerous** command. Real auth attempts against live accounts. Read [HARD GUARDS](#hard-guards) before running.

**Mode selection:**

| Mode | Use case | Engine |
|---|---|---|
| `http-form` | Custom login page (most BB targets) | Pure Python urllib |
| `oauth` | OAuth password grant (`grant_type=password`) | Pure Python urllib |
| `o365` | Microsoft 365 / Azure AD | `trevorspray` |
| `okta` | Okta SSO | `trevorspray` |

**Hard guards (no override possible without `--i-understand`):**

1. **Typed-hostname confirmation** — you must type the target hostname back. Defeats wrong-target slips.
2. **Lockout warning** — calculates per-user failed-attempt count from `--passes` size, warns if it exceeds typical thresholds.
3. **Audit log JSONL** — every attempt appended to `recon/<host>/spray/attempts-<ts>.jsonl`. **Passwords logged as SHA-256 prefix only, never plaintext.**
4. **Spray order** — `pass[i] × all_users` per round. Each user sees at most 1 failed attempt per round, well under typical 5-10 lockout threshold.

---

## HARD GUARDS — WHY THEY EXIST

### Lockout policy reality check

Default rate-limit: `--delay 1800 --jitter 60` (30 min/round + ±60s).

| Lockout policy (typical) | Threshold | Reset window |
|---|---|---|
| Azure AD smart lockout | 10 failed in 10 min sliding | 10-min window |
| Okta default | 10 in 10 min | configurable |
| Custom apps | usually 5-10 per hour | varies wildly |

A spray with default delay tries 1 password per user per 30 min — keeps every user at 0 strikes within any sliding window.

**`--aggressive` (60s/10s) is fast spray:** use ONLY with explicit program permission. Against O365, it almost certainly triggers smart lockout.

### Spray order — why pass[i] × all_users, NOT brute per-user

```
WRONG (brute-force order, will lockout):
  alice: pass1, pass2, pass3, ...  ← alice gets 8 failed attempts in seconds, lockout
  bob:   pass1, pass2, pass3, ...

RIGHT (spray order, distributes failures):
  Round 1:  pass1 → alice, bob, charlie  (1 failed each)
  [delay 30 min]
  Round 2:  pass2 → alice, bob, charlie  (2 failed total each, still under threshold)
  ...
```

Our `tools/_spray_http_form.py` and `_spray_oauth.py` enforce spray order.

---

## SUCCESS DETECTION

### http-form mode

Checked in this order:
1. `--success-regex <body-regex>` matches response → success
2. `--fail-regex <body-regex>` set AND body does NOT match → success
3. HTTP redirect (3xx) to a path that is NOT the login page → success (heuristic)
4. None of the above → not success

**False positive risk:** Without `--success-regex` or `--fail-regex`, heuristic 3 can mis-fire on sites that always redirect even on failure. **Always supply `--fail-regex "Invalid|incorrect|wrong"` for production sprays.**

### oauth mode

- HTTP 200 with `"access_token"` field in JSON body → success
- HTTP 4xx (typically 400 `invalid_grant` / 401) → fail

This is unambiguous; no regex needed.

### o365 / okta (TREVORspray)

Output parsing. Less granular than our http-form / oauth handlers but well-tested upstream.

---

## CHAIN PATTERN: SPRAY → AUTHENTICATED /HUNT

The real payout play:

```
/spray finds valid creds (low-payout finding by itself if reported as ATO)
   ↓
   Re-run /hunt with the session cookie or bearer token
   ↓
   Authenticated /hunt sees admin pages, internal APIs, IDOR on user data
   ↓
   Find a P1/P2 IDOR or business-logic bug behind the login wall
   ↓
   Chain report: "ATO via spray + IDOR exposes all user PII"  (high payout)
```

The spray-only finding alone is **usually rejected** by mature BBPs (they treat it as "user's bad password choice, not our bug"). The chain is what pays.

**Not yet wired in this branch:** `/hunt --authenticated-session <cookie>` is a future PR. For now, after spray finds creds, manually feed the session into Burp / curl-based probing.

---

## LEGAL GUARDRAILS

Before running `/spray` against ANY target, verify:

1. **Program policy explicitly allows credential testing.** Look for keywords:
   - ✅ "Credential testing permitted with rate-limit X"
   - ✅ "Brute-force allowed against test accounts"
   - ❌ "Credential stuffing", "brute force", "password attacks" listed under prohibited
   - ⚠️ Silent — assume disallowed, ASK the program first

2. **The wordlist does not contain plaintext breach data.** Using DeHashed-style plaintext passwords from real breaches to log into real accounts is illegal in most jurisdictions even with BB scope. **HIBP hash-prefix is fine** (we use this); **plaintext breach corpus is not** (we don't bundle this).

3. **Stop on first hit by default.** Don't keep spraying after you have one valid set of creds — that's not testing, it's grinding for lulz. `--continue-on-hit` exists but should only be used to evidence multiple users sharing a default password.

4. **Report the lockout impact.** If your spray locked accounts, **tell the program immediately** with timestamps from the audit log. Don't make them discover it themselves.

---

## COMMON PITFALLS (learned the hard way)

### Pitfall 1 — Generic wordlist = no signal

`/wordlist-gen` with `--filter loose` against an API-heavy site gives you 500k candidates, 95% of which are CSS selectors, URL slugs, and example API tokens from docs.

**Fix:** Stick with the default `--filter strict`. Verified on Twilio: 56k loose → 34k strict (-39%), all noise dropped, real terms (`flexdemo`, `webhook`, `programmable`) preserved.

### Pitfall 2 — `--limit N` biases the sample

The wordlist is `sort -u`'d alphabetically (ASCII order: digits < uppercase < lowercase). Naïve `--limit 5000` samples ONLY digit/symbol-prefix entries.

**Fix:** Always use `--shuffle` when sampling. Verified on Twilio: without shuffle, top 5000 were 100% l33t variants (`1nc0rr3t0`, `$m@rt`...); with shuffle, you get representative coverage including `a-z` prefix candidates.

### Pitfall 3 — `{PASSWORD}` vs `{PASS}` placeholder

Natural user instinct is `--post-data "username={USER}&password={PASSWORD}"`. Our code accepts BOTH aliases (`{USER}/{USERNAME}` and `{PASS}/{PASSWORD}`). Unknown placeholders stay literal in the request — visible to you, not a crash.

### Pitfall 4 — theHarvester silently writes JSON to cwd

`theHarvester -f recon/<target>/osint/theharvester` does NOT write to that path. It writes `theharvester.json` to `$PWD` (the directory you ran the command from).

**Fix:** `tools/osint_employees.sh` wraps the call in `(cd "$OUT_DIR" && theHarvester ... -f theharvester)`. If you invoke theHarvester directly, `cd` first.

### Pitfall 5 — CrossLinked / theHarvester returning 0 emails

Two distinct scenarios:
- **Twilio-style:** mature security → no public emails in search engines → 0 result is **expected**. The 59 hostnames theHarvester finds in CT logs are the consolation prize — feed them to `/recon`.
- **Taipower-style:** state utility, employees on LinkedIn under Chinese names → English dorks return 0 → switch to manual browser search OR drop this pipeline for this target.

### Pitfall 6 — Pure Python urllib quirks (Python 3.9)

`urllib.request.urlopen()` accepts `context=` kwarg. `opener.open()` does NOT. If you customize a build_opener, attach the SSL context to an `HTTPSHandler` instead. Our http-form handler does this; this bug bit us during live test.

---

## OPERATIONAL CHECKLIST

Before pressing enter on `/spray`:

- [ ] `/scope <login-host>` returns IN SCOPE
- [ ] Program policy reviewed for credential-testing rules
- [ ] Wordlist filtered (`--filter strict`) and HIBP-ranked (`--max-count 1000000`)
- [ ] Usernames file has REAL usernames (from `/osint-employees`) — not `users.txt` from a tutorial
- [ ] Default delay (`--delay 1800 --jitter 60`) unless program permits faster
- [ ] You can stomach the duration estimate (printed in pre-flight)
- [ ] `--dry-run` passed once to verify post-data template is correct
- [ ] You're ready to STOP and report immediately if a hit lands

During spray:
- [ ] Monitor audit log JSONL for HTTP 429 / 503 / response-time spikes (WAF kicking in)
- [ ] If status codes get weird (all 503, all 200), assume detection and abort

After spray:
- [ ] If hit: STOP, document the find, do NOT log in further
- [ ] If no hit after N rounds: archive audit log, move on
- [ ] If lockouts likely happened: notify program with audit log timestamps

---

## TOOL LADDER & ALTERNATIVES

When our default tool fails or you want to swap, here's the practical ladder. Tools marked ❌ were deliberately rejected — don't try them as drop-in subs.

### Stage 1 — Wordlist crawl

| Tool | Status | Why |
|---|---|---|
| **cewler** | ✓ Primary | Python rewrite of CeWL; Scrapy-backed; faster on JS-heavy sites |
| CeWL | ⚠ Backup | Ruby; not in brew on macOS; older but more battle-tested. Use only if cewler fails on a specific site |
| dirtywords | Alternative | Newer, BB-focused; try if cewler misses dynamic content |
| getjswords | Complement | Pulls words from JS bundles specifically — useful when target has rich SPA |

### Stage 1 — Wordlist mutation

| Tool | Status | Why |
|---|---|---|
| **hashcat top10_2025.rule / best66.rule / OneRuleToRuleThemAll** | ✓ Primary | Industry standard, modes selectable in `/wordlist-gen` |
| pydictor (`-extend`) | Reserved for Stage 3 | Best with OSINT inputs (birthdays/names); overlaps hashcat on raw words |
| wister | ❌ Dropped | Variant logic overlaps pydictor; no clear advantage |
| Mentalist | ❌ Dropped | GUI-only — not scriptable for CI |
| rsmangler | Minor alt | Simple prefix/suffix mutation; less complete than hashcat rules |

### Stage 2 — Breach corpus / ranking

| Tool | Status | Why |
|---|---|---|
| **HIBP Pwned Passwords (k-anonymity)** | ✓ Primary | Free, no API key, hash-prefix only — safe legal posture |
| HIBP Breach API v3 | Optional ($3.50/mo) | Per-email leak lookup; useful for high-priority account triage |
| DeHashed / Intelligence Security | ❌ NOT for spray | Contains plaintext passwords from real breaches. **Using plaintext breach credentials against live accounts is illegal in most jurisdictions even with BB scope.** Use only for reading, never for login attempts |
| weakpass.com (28GB dump) | Offline cracking only | Too large for spray; usable for hash cracking after a hit |
| SecLists Passwords/ | Generic fallback | Use ONLY when target has no website to crawl from |

### Stage 3 — OSINT employees

| Tool | Status | Why |
|---|---|---|
| **theHarvester** | ✓ Primary | Multi-source (search engines + CT logs + DNS), free, ~43 sources available |
| **CrossLinked** | ✓ Opt-in via `--with-linkedin` | Google/Bing dorks against LinkedIn — no LinkedIn auth needed |
| **username-anarchy** | ✓ Primary | Expands names into 30+ username formats |
| LinkedInDumper | ❌ Dropped | Requires LinkedIn account auth — OPSEC cost, account ban risk |
| NameSpi | Alternative | Combines LinkedIn + Hunter.io — useful if you have Hunter.io |
| Hunter.io | Optional (paid) | Best email-format inference (`{first}.{last}@`); valuable for high-value targets |
| Kerbrute | Internal-network only | Validates AD usernames via Kerberos pre-auth — useless against external BB targets |

### Stage 4 — Spray engines

| Tool | Status | Why |
|---|---|---|
| **Built-in http-form / oauth modules** | ✓ Primary | Pure Python urllib; under our full control; auditable JSONL |
| **TREVORspray** (`o365`, `okta`) | ✓ Primary for enterprise SSO | Most complete O365/Okta engine; built-in SSH proxy rotation; mature |
| CredMaster | Alternative | AWS FireProx IP rotation — useful if program rate-limits per-IP heavily |
| MSOLSpray | ❌ Dropped | TREVORspray already covers O365 with better tooling |
| Spray365 | ❌ Dropped | Only M365; TREVORspray + CredMaster covers spray needs |
| SprayingToolkit | Alternative | Lync / S4B / OWA niche — try only if you hit those specific targets |

### Decision shortcuts

- **Modern SaaS target** (Twilio, Stripe, GitLab): start with `cewler` + `hashcat top10_2025` + `theHarvester` (no LinkedIn) + `/spray http-form`
- **Enterprise with Azure/M365**: `cewler` + `theHarvester` + `--with-linkedin` + `/spray o365`
- **Mobile API target**: `cewler` (depth 1, JS bundles often have the wordlist) + `/spray oauth`
- **Internal network pentest** (out of scope for BB but for completeness): add `kerbrute userenum` before spray

### Legal red lines (non-negotiable)

1. **Never use plaintext breach passwords against live accounts** — even if you have DeHashed access. HIBP hash-prefix is the only legally clean leak-source.
2. **Stop on first valid creds** — don't keep grinding for multiple hits; that's testing, not lulz.
3. **Notify the program if lockouts happened** — proactive disclosure with audit timestamps.

---

## DEEP DIVE

For the underlying tools' own docs:
- `tools/wordlist_engine.sh -h`
- `tools/osint_employees.sh -h`
- `tools/breach_checker.py -h`
- `tools/spray_orchestrator.sh -h`

---

## RELATED SKILLS

- `bug-bounty` — master workflow (this skill is a sub-pipeline)
- `web2-recon` — produces the URL list that surfaces login endpoints
- `triage-validation` — run 7-Question Gate on any spray-discovered creds before reporting
- `report-writing` — ATO-via-spray report templates (H1/Bugcrowd format)
