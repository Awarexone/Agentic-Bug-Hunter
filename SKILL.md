---
name: bug-bounty
description: Complete bug bounty workflow — recon (subdomain enumeration, asset discovery, fingerprinting, HackerOne scope, source code audit), pre-hunt learning (disclosed reports, tech stack research, mind maps, threat modeling), vulnerability hunting (IDOR, SSRF, XSS, auth bypass, CSRF, race conditions, SQLi, XXE, file upload, business logic, GraphQL, HTTP smuggling, cache poisoning, OAuth, timing side-channels, OIDC, smart contracts, SDK audit, SIWE), LLM/AI security testing (chatbot IDOR, prompt injection, indirect injection, ASCII smuggling, exfil channels, RCE via code tools, system prompt extraction), and reporting (4 validation gates, human-tone writing, templates by vuln class, CVSS 3.1, PoC generation, submission checklist). Use for ANY bug bounty task — starting a new target, doing recon, hunting specific vulns, auditing source code, testing AI features, validating findings, or writing reports.
---

# Bug Bounty Master Workflow

Full pipeline: Recon → Learn → Hunt → Validate → Report. One skill for everything.

## THE ONLY QUESTION THAT MATTERS

> **"Can an attacker do this RIGHT NOW against a real user who has taken NO unusual actions — and does it cause real harm (stolen money, leaked PII, account takeover, code execution)?"**
>
> If the answer is NO — **STOP. Do not write. Do not explore further. Move on.**

### Theoretical Bug = Wasted Time. Kill These Immediately:

| Pattern | Kill Reason |
|---|---|
| "Could theoretically allow..." | Not exploitable = not a bug |
| "An attacker with X, Y, Z conditions could..." | Too many preconditions |
| "Wrong implementation but no practical impact" | Wrong but harmless = not a bug |
| Dead code with a bug in it | Not reachable = not a bug |
| Source maps without secrets | No impact |
| SSRF with DNS-only callback | Need data exfil or internal access |
| Open redirect alone | Need ATO or OAuth chain |
| "Could be used in a chain if..." | Build the chain first, THEN report |

**You must demonstrate actual harm. "Could" is not a bug. Prove it works or drop it.**

---

## CRITICAL RULES

1. **READ FULL SCOPE FIRST** — verify every asset/domain is owned by the target org
2. **NO THEORETICAL BUGS** — "Can an attacker steal funds, leak PII, takeover account, or execute code RIGHT NOW?" If no, STOP.
3. **KILL WEAK FINDINGS FAST** — run Gate 0 BEFORE writing any report
4. **Validate before writing** — check CHANGELOG, design docs, deployment scripts FIRST
5. **One bug class at a time** — go deep, don't spray
6. **Verify data isn't already public** — check web UI in incognito before reporting API "leaks"
7. **5-MINUTE RULE** — if a target shows nothing after 5 min probing (all 401/403/404), MOVE ON
8. **IMPACT-FIRST HUNTING** — ask "what's the worst thing if auth was broken?" If nothing valuable, skip target
9. **CREDENTIAL LEAKS need exploitation proof** — finding keys isn't enough, must PROVE what they access
10. **STOP SHALLOW RECON SPIRALS** — don't probe 403s, don't grep for analytics keys, don't check staging domains that lead nowhere
11. **BUSINESS IMPACT over vuln class** — severity depends on CONTEXT, not just vuln type
12. **UNDERSTAND THE TARGET DEEPLY** — before hunting, learn the app like a real user
13. **DON'T OVER-RELY ON AUTOMATION** — automated scans hit WAFs, trigger rate limits, find the same bugs everyone else finds
14. **HUNT LESS-SATURATED VULN CLASSES** — XSS/SSRF/XXE have the most competition. Expand into: cache poisoning, Android/mobile vulns, business logic, race conditions, OAuth/OIDC chains
15. **ONE-HOUR RULE** — stuck on one target for an hour with no progress? SWITCH CONTEXT
16. **TWO-EYE APPROACH** — combine systematic testing (checklist) with anomaly detection (watch for unexpected behavior)
17. **T-SHAPED KNOWLEDGE** — go DEEP in one area and BROAD across everything else

---

# TOP 1% HACKER MINDSET

## How Elite Hackers Think Differently

**Average hunter**: Runs tools, checks checklist, gives up after 30 min.
**Top 1%**: Builds a mental model of the app's internals. Asks "why does this work the way it does?" Not "what does this endpoint do?" but "what business decision led a developer to build it this way, and what shortcut might they have taken?"

## Pre-Hunt Mental Framework

### Step 1: Crown Jewel Thinking
Before touching anything, ask: "If I were the attacker and I could do ONE thing to this app, what causes the most damage?"
- Financial app → drain funds, transfer to attacker account
- Healthcare → PII leak, HIPAA violation
- SaaS → tenant data crossing, admin takeover
- Auth provider → full SSO chain compromise

### Step 2: Developer Empathy
Think like the developer who built the feature:
- What was the simplest implementation?
- What shortcut would a tired dev take at 2am?
- Where is auth checked — controller? middleware? DB layer?
- What happens when you call endpoint B without going through endpoint A first?

### Step 3: Trust Boundary Mapping
```
Client → CDN → Load Balancer → App Server → Database
         ↑               ↑              ↑
    Where does app STOP trusting input?
    Where does it ASSUME input is already validated?
```

### Step 4: Feature Interaction Thinking
- Does this new feature reuse old auth, or does it have its own?
- Does the mobile API share auth logic with the web app?
- Was this feature built by the same team or a third-party?

## The Top 1% Mental Checklist
- [ ] I know the app's core business model
- [ ] I've used the app as a real user for 15+ minutes
- [ ] I know the tech stack (language, framework, auth system, caching)
- [ ] I've read at least 3 disclosed reports for this program
- [ ] I have 2 test accounts ready (attacker + victim)
- [ ] I've defined my primary target: ONE crown jewel I'm hunting for today

## Mindset Rules from Top Hunters

**"Hunt the feature, not the endpoint"** — Find all endpoints that serve a feature, then test the INTERACTION between them.

**"Authorization inconsistency is your friend"** — If the app checks auth in 9 places but not the 10th, that's your bug.

**"New == unreviewed"** — Features launched in the last 30 days have lowest security maturity.

**"Think second-order"** — Second-order SSRF: URL saved in DB, fetched by cron job. Second-order XSS: stored clean, rendered unsafely in admin panel.

**"Follow the money"** — Any feature touching payments, billing, credits, refunds is where developers make the most security shortcuts.

**"The API the mobile app uses"** — Mobile apps often call older/different API versions. Same company, different attack surface, lower maturity.

**"Diffs find bugs"** — Compare old API docs vs new. Compare mobile API vs web API. Compare what a free user can request vs what a paid user gets in response.

---

# TOOLS

## Go Binaries
| Tool | Use |
|------|-----|
| subfinder | Passive subdomain enum |
| httpx | Probe live hosts |
| dnsx | DNS resolution |
| nuclei | Template scanner |
| katana | Crawl |
| waybackurls | Archive URLs |
| gau | Known URLs |
| dalfox | XSS scanner |
| ffuf | Fuzzer |
| anew | Dedup append |
| qsreplace | Replace param values |
| assetfinder | Subdomain enum |
| gf | Grep patterns (xss, sqli, ssrf, redirect) |
| interactsh-client | OOB callbacks |

## Tools to Install When Needed
| Tool | Use | Install |
|------|-----|---------|
| arjun | Hidden parameter discovery | `pip3 install arjun` |
| paramspider | URL parameter mining | `pip3 install paramspider` |
| kiterunner | API endpoint brute | `go install github.com/assetnote/kiterunner/cmd/kr@latest` |
| cloudenum | Cloud asset enumeration | `pip3 install cloud_enum` |
| trufflehog | Secret scanning | `brew install trufflehog` |
| gitleaks | Secret scanning | `brew install gitleaks` |
| XSStrike | Advanced XSS scanner | `pip3 install xsstrike` |
| SecretFinder | JS secret extraction | `pip3 install secretfinder` |
| sqlmap | SQL injection | `pip3 install sqlmap` |
| subzy | Subdomain takeover | `go install github.com/LukaSikic/subzy@latest` |

## Static Analysis
```bash
semgrep --config=p/security-audit ./
semgrep --config=p/owasp-top-ten ./
semgrep --config=p/javascript ./
```

## AI-Assisted Tools
- **strix** (usestrix.com) — open-source AI scanner for automated initial sweep

---

# PHASE 1: RECON

## Standard Recon Pipeline
```bash
# Step 1: Subdomains
subfinder -d TARGET -silent | anew /tmp/subs.txt
assetfinder --subs-only TARGET | anew /tmp/subs.txt

# Step 2: Resolve + live hosts
cat /tmp/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect -o /tmp/live.txt

# Step 3: URL collection
cat /tmp/live.txt | awk '{print $1}' | katana -d 3 -silent | anew /tmp/urls.txt
echo TARGET | waybackurls | anew /tmp/urls.txt
gau TARGET | anew /tmp/urls.txt

# Step 4: Nuclei scan
nuclei -l /tmp/live.txt -severity critical,high,medium -silent -o /tmp/nuclei.txt

# Step 5: JS secrets
cat /tmp/urls.txt | grep "\.js$" | sort -u > /tmp/jsfiles.txt
# Run SecretFinder on each JS file

# Step 6: GitHub dorking (if target has public repos)
# GitDorker -org TARGET_ORG -d dorks/alldorksv3
```

## Cloud Asset Enumeration
```bash
# Manual S3 brute
for suffix in dev staging test backup api data assets static cdn; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://${TARGET}-${suffix}.s3.amazonaws.com/")
  [ "$code" != "404" ] && echo "$code ${TARGET}-${suffix}.s3.amazonaws.com"
done
```

## API Endpoint Discovery
```bash
# ffuf API endpoint brute
ffuf -u https://TARGET/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,301,302,403
```

## HackerOne Scope Retrieval
```bash
curl -s "https://hackerone.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { team(handle: \"PROGRAM_HANDLE\") { name url policy_scopes(archived: false) { edges { node { asset_type asset_identifier eligible_for_bounty instruction } } } } }"}' \
  | jq '.data.team.policy_scopes.edges[].node'
```

## Quick Wins Checklist
- [ ] Subdomain takeover (`subjack`, `subzy`)
- [ ] Exposed `.git` (`/.git/config`)
- [ ] Exposed env files (`/.env`, `/.env.local`)
- [ ] Default credentials on admin panels
- [ ] JS secrets (SecretFinder, jsluice)
- [ ] Open redirects (`?redirect=`, `?next=`, `?url=`)
- [ ] CORS misconfig (test `Origin: https://evil.com` + credentials)
- [ ] S3/cloud buckets
- [ ] GraphQL introspection enabled
- [ ] Spring actuators (`/actuator/env`, `/actuator/heapdump`)
- [ ] Firebase open read (`https://TARGET.firebaseio.com/.json`)

## Technology Fingerprinting

| Signal | Technology |
|---|---|
| Cookie: `XSRF-TOKEN` + `*_session` | Laravel |
| Cookie: `PHPSESSID` | PHP |
| Header: `X-Powered-By: Express` | Node.js/Express |
| Response: `wp-json`/`wp-content` | WordPress |
| Response: `{"errors":[{"message":` | GraphQL |
| Header: `X-Powered-By: Next.js` | Next.js |

## Framework Quick Wins

**Laravel**: `/horizon`, `/telescope`, `/.env`, `/storage/logs/laravel.log`
**WordPress**: `/wp-json/wp/v2/users`, `/xmlrpc.php`, `/?author=1`
**Node.js**: `/.env`, `/graphql` (introspection), `/_debug`
**AWS Cognito**: `/oauth2/userInfo` (leaks Pool ID), CORS reflects arbitrary origins

## Source Code Recon
```bash
# Security surface
cat SECURITY.md 2>/dev/null; cat CHANGELOG.md | head -100 | grep -i "security\|fix\|CVE"
git log --oneline --all --grep="security\|CVE\|fix\|vuln" | head -20

# Dev breadcrumbs
grep -rn "TODO\|FIXME\|HACK\|UNSAFE" --include="*.ts" --include="*.js" | grep -iv "test\|spec"

# Dangerous patterns (JS/TS)
grep -rn "eval(\|innerHTML\|dangerouslySetInner\|execSync" --include="*.ts" --include="*.js" | grep -v node_modules
grep -rn "===.*token\|===.*secret\|===.*hash" --include="*.ts" --include="*.js"
grep -rn "fetch(\|axios\." --include="*.ts" | grep "req\.\|params\.\|query\."

# Dangerous patterns (Solidity)
grep -rn "tx\.origin\|delegatecall\|selfdestruct\|block\.timestamp" --include="*.sol"
```

---

# PHASE 2: LEARN (Pre-Hunt Intelligence)

## Read Disclosed Reports
```bash
# By program on HackerOne
curl -s "https://hackerone.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ hacktivity_items(first:25, order_by:{field:popular, direction:DESC}, where:{team:{handle:{_eq:\"PROGRAM\"}}}) { nodes { ... on HacktivityDocument { report { title severity_rating } } } } }"}' \
  | jq '.data.hacktivity_items.nodes[].report'
```

## "What Changed" Method
1. Find disclosed report for similar tech
2. Get the fix commit
3. Read the diff — identify the anti-pattern
4. Grep your target for that same anti-pattern

## Threat Model Template
```
TARGET: _______________
CROWN JEWELS: 1.___ 2.___ 3.___
ATTACK SURFACE:
  [ ] Unauthenticated: login, register, password reset, public APIs
  [ ] Authenticated: all user-facing endpoints, file uploads, API calls
  [ ] Cross-tenant: org/team/workspace ID parameters
  [ ] Admin: /admin, /internal, /debug
HIGHEST PRIORITY (crown jewel × easiest entry):
  1.___ 2.___ 3.___
```

## 6 Key Patterns from Top Reports
1. **Feature Complexity = Bug Surface** — imports, integrations, multi-tenancy, multi-step workflows
2. **Developer Inconsistency = Strongest Evidence** — `timingSafeEqual` in one place, `===` elsewhere
3. **"Else Branch" Bug** — proxy/gateway passes raw token without validation in else path
4. **Import/Export = SSRF** — every "import from URL" feature has historically had SSRF
5. **Secondary/Legacy Endpoints = No Auth** — `/api/v1/` guarded but `/api/` isn't
6. **Race Windows in Financial Ops** — check-then-deduct as two DB operations = double-spend

---

# PHASE 3: HUNT

## Note-Taking System (Never Hunt Without This)
```markdown
# TARGET: company.com — SESSION 1

## Interesting Leads (not confirmed bugs yet)
- [14:22] /api/v2/invoices/{id} — no auth check visible in source, testing...

## Dead Ends (don't revisit)
- /admin → IP restricted, confirmed by trying 15+ bypass headers

## Anomalies
- GET /api/export returns 200 even when session cookie is missing
- Response time: POST /api/check-user → 150ms (exists) vs 8ms (doesn't)

## Rabbit Holes (time-boxed, max 15 min each)
- [ ] 10 min: JWT kid injection on auth endpoint

## Confirmed Bugs
- [15:10] IDOR on /api/invoices/{id} — read+write
```

## Subdomain Type → Hunt Strategy
- **dev/staging/test**: Debug endpoints, disabled auth, verbose errors
- **admin/internal**: Default creds, IP bypass headers (`X-Forwarded-For: 127.0.0.1`)
- **api/api-v2**: Enumerate with kiterunner, check older unprotected versions
- **auth/sso**: OAuth misconfigs, open redirect in `redirect_uri`
- **upload/cdn**: CORS, path traversal, stored XSS

## CVE-Seeded Audit Approach
1. **Build a CVE eval set** — collect 5-10 prior CVEs for the target codebase
2. **Reproduce old bugs** — verify you can find the pattern in older code
3. **Pattern-match forward** — search for the same anti-pattern in current code
4. **Focus on wide attack surfaces** — JS engines, parsers, anything processing untrusted external input

## Rust/Blockchain Source Code (Hard-Won Lessons)

**Panic paths: encoding vs decoding** — `.unwrap()` on an encoding path is NOT attacker-triggerable. Only panics on deserialization/decoding of network input are exploitable.

**"Known TODO" is not a mitigation** — A comment like `// Votes are not signed for now` doesn't mean safe.

**Pattern-based hunting from confirmed findings** — If `verify_signed_vote` is broken, check `verify_signed_proposal` and `verify_commit_signature`.

```bash
# Rust dangerous patterns (network-facing)
grep -rn "\.unwrap()\|\.expect(" --include="*.rs" | grep -v "test\|encode\|to_bytes\|serialize"
grep -rn "if let Ok\|let _ =" --include="*.rs" | grep -i "verify\|sign\|cert\|auth"
grep -rn "TODO\|FIXME\|not signed\|not verified\|for now" --include="*.rs" | grep -i "sign\|verify\|cert\|auth"
```

---

# PHASE 4: VALIDATE (4 Gates)

## Gate 0 — Pre-Write Check (Run BEFORE Writing Report)

| Gate | Question | Pass Condition |
|------|----------|---------------|
| G0 | Is this actually exploitable RIGHT NOW? | Yes, with real PoC |
| G1 | Is the endpoint in scope? | Confirmed on program page |
| G2 | Is this a known/duplicate? | Searched Hacktivity, changelog, known issues |
| G3 | Does it cause real harm? | Fund theft, PII, ATO, or RCE |

If any gate fails → **STOP. Move on.**

## CVSS 3.1 Quick Guide

| Factor | Low (0-3.9) | Medium (4-6.9) | High (7-8.9) | Critical (9-10) |
|--------|-------------|----------------|--------------|-----------------|
| Attack Vector | Physical | Local | Adjacent | Network |
| Privileges | High | Low | None | None |
| User Interaction | Required | Required | None | None |
| Impact | Partial | Partial | High | High (all 3) |

---

# PHASE 5: REPORT

## HackerOne Report Template

```
Title: [Vuln Class] in [endpoint/feature] leads to [Impact]

## Summary
[2-3 sentences: what it is, where it is, what attacker can do]

## Steps To Reproduce
1. Log in as attacker (account A)
2. Send request: [paste exact request]
3. Observe: [exact response showing the bug]
4. Confirm: [what the attacker gained]

## Supporting Material
[Screenshot / video of exploitation]
[Burp Suite request/response]

## Impact
An attacker can [specific action] resulting in [specific harm].
[Quantify if possible: "This affects all X users" or "Attacker can access Y data"]

## Severity Assessment
CVSS 3.1 Score: X.X ([Severity label])
Attack Vector: Network | Complexity: Low | Privileges: None | User Interaction: None
```

## Human Tone Rules (Avoid AI-Sounding Writing)
- Start sentences with the impact, not the vulnerability name
- Write like you're explaining to a smart developer, not a textbook
- Use "I" and active voice: "I found that..." not "A vulnerability was discovered..."
- One concrete example beats three abstract sentences
- No em dashes, no "comprehensive/leverage/seamless/ensure"

## Bugcrowd Report Template

```
Title: [Vuln] at [endpoint] — [Impact in one line]

Bug Type: [IDOR/SSRF/XSS/etc]
Target: [URL or component]
Severity: [P1/P2/P3/P4]

Description:
[Root cause + exact location]

Reproduction:
1. [step]
2. [step]
3. [step]

Impact:
[Concrete business impact]

Fix Suggestion:
[Specific remediation]
```

---

# VULNERABILITY HUNTING CHECKLISTS

## IDOR
- [ ] Try victim's object ID as authenticated attacker
- [ ] Test all HTTP methods (GET, PUT, PATCH, DELETE)
- [ ] Try UUIDs, integers, and encoded IDs
- [ ] Test indirect reference (user ID in request body, not URL)
- [ ] Test via GraphQL mutations
- [ ] Check batch endpoints (can you request multiple IDs?)

## SSRF
- [ ] Try cloud metadata: `http://169.254.169.254/latest/meta-data/`
- [ ] Try internal services: `http://127.0.0.1:6379/` (Redis), `:9200` (Elasticsearch), `:27017` (MongoDB)
- [ ] Test IP bypass: decimal, hex, octal, IPv6
- [ ] Test protocol bypass: `file://`, `dict://`, `gopher://`
- [ ] Look in: webhook URLs, import from URL, profile picture URL, PDF generators, XML parsers

## OAuth
- [ ] Missing `state` parameter → CSRF
- [ ] `redirect_uri` accepts wildcards → ATO
- [ ] Missing PKCE → code theft
- [ ] Implicit flow → token leakage in referrer
- [ ] Open redirect in post-auth redirect → OAuth token theft chain

## Race Conditions
- [ ] Coupon codes / promo codes
- [ ] Gift card redemption
- [ ] Fund transfer / withdrawal
- [ ] Voting / rating limits
- [ ] OTP verification brute via race

```bash
seq 20 | xargs -P 20 -I {} curl -s -X POST https://TARGET/redeem \
  -H "Authorization: Bearer $TOKEN" -d 'code=PROMO10' &
wait
```

## Business Logic
- [ ] Negative quantities in cart
- [ ] Price parameter tampering
- [ ] Workflow skip (e.g., pay without checkout)
- [ ] Role escalation via registration fields
- [ ] Privilege persistence after downgrade

## LLM / AI Features
- [ ] Prompt injection via user input passed to LLM
- [ ] Indirect injection via document/URL the AI processes
- [ ] IDOR in chat history (enumerate conversation IDs)
- [ ] System prompt extraction via roleplay/encoding
- [ ] RCE via code execution tool abuse
- [ ] ASCII smuggling (invisible unicode in LLM output)

---

# RESOURCES

## Bug Bounty Platforms
- [HackerOne Hacktivity](https://hackerone.com/hacktivity) — Disclosed reports
- [Bugcrowd Crowdstream](https://bugcrowd.com/crowdstream) — Public findings
- [Intigriti Leaderboard](https://www.intigriti.com/researcher/leaderboard)

## Learning
- [PortSwigger Web Academy](https://portswigger.net/web-security) — Free vuln labs (best)
- [HackTricks](https://book.hacktricks.xyz) — Attack technique reference
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Payload reference
- [Solodit](https://solodit.cyfrin.io) — 50K+ searchable audit findings (Web3)
- [ProjectDiscovery Chaos](https://chaos.projectdiscovery.io) — Free subdomain datasets

## Wordlists
- [SecLists](https://github.com/danielmiessler/SecLists) — Comprehensive wordlists
- [HowToHunt](https://github.com/KathanP19/HowToHunt) — Step-by-step vuln hunting
- [DefaultCreds](https://github.com/ihebski/DefaultCreds-cheat-sheet) — Default credentials

## Payload Databases
- [XSSHunter](https://xsshunter.trufflesecurity.com/) — Blind XSS detection
- [interactsh](https://app.interactsh.com) — OOB callback server

---

# INSTALLATION (Claude Code Skill)

To use this as a Claude Code skill, copy this file to your skills directory:

```bash
# Option A: Clone the repo and link the skill
git clone https://github.com/shuvonsec/claude-bug-bounty.git ~/.claude/skills/bug-bounty
ln -s ~/.claude/skills/bug-bounty/SKILL.md ~/.claude/skills/bug-bounty/SKILL.md

# Option B: Direct copy
mkdir -p ~/.claude/skills/bug-bounty
curl -s https://raw.githubusercontent.com/shuvonsec/claude-bug-bounty/main/SKILL.md \
  -o ~/.claude/skills/bug-bounty/SKILL.md
```

Then in Claude Code, this skill loads automatically when you ask about bug bounty, recon, or vulnerability hunting.
