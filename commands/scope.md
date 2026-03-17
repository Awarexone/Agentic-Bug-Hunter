---
description: Check if a target asset is in scope for the program before hunting or submitting. Reads program scope page, checks asset against in-scope and out-of-scope lists, verifies the asset is owned by the target organization. Usage: /scope <asset>
---

# /scope

Verify an asset is in scope before hunting or submitting a finding.

## Why This Matters

Out-of-scope reports are immediately closed. Testing out-of-scope assets can get you banned.
Always check scope BEFORE the first request.

**Real example:** City of Vienna explicitly excludes `/advuew/*`. Submitting XSS on that path = instant close.

## Usage

```
/scope api.target.com
/scope https://target.com/api/v2/users
/scope target-staging.company.com
/scope *.company.com
```

## Scope Check Process

### Step 1: Read In-Scope List

Go to the program page and extract:
```
In-scope:
- *.target.com
- target.com
- api.target.com
- mobile.target.com (iOS + Android apps)

Out-of-scope:
- staging.target.com (explicitly excluded)
- target.com/help/* (documentation only)
- partners.target.com (third-party managed)
```

### Step 2: Asset Ownership Check

Verify the asset is actually owned by the target company (not a third party):

```bash
# WHOIS
whois api.target.com | grep -iE "registrant|admin|tech|org"

# DNS — is it CNAME to a third party?
dig +short api.target.com CNAME
# If CNAME to salesforce.com, zendesk.com, etc. → not in scope

# Check if it's a known third-party service:
# intercom.io, freshdesk.com, zendesk.com, hubspot.com, etc.
```

### Step 3: Wildcard Interpretation

| Scope Pattern | Covers | Does NOT Cover |
|---|---|---|
| `*.target.com` | `api.target.com`, `app.target.com` | `target.com` itself |
| `target.com` | `target.com` only | `api.target.com` |
| `*.target.com` + `target.com` | Both | Sub-subdomains like `a.api.target.com` (depends on program) |

### Step 4: Path Exclusions

Some programs exclude specific paths on in-scope domains:
```
Domain: target.com (in scope)
But: target.com/terms, target.com/privacy, target.com/help/* = usually excluded

Check for:
- Wildcard exclusions: /admin/* excluded
- Path-specific exclusions: /api/v1/* excluded (use v2 only)
- Feature exclusions: "Do not test file upload feature"
```

### Step 5: Staging / Dev Check

Unless the program explicitly includes staging:
```
staging.target.com     → NOT in scope (usually)
dev.target.com         → NOT in scope (usually)
qa.target.com          → NOT in scope (usually)
test.target.com        → NOT in scope (usually)

Always confirm: does scope say "*.target.com" or only list production domains?
```

## Output

**IN SCOPE:** "asset.target.com is covered by the *.target.com wildcard. Owned by TargetCorp (WHOIS confirms). No path exclusions apply. Clear to test."

**OUT OF SCOPE:** "target.com/admin/* is explicitly excluded in the program rules under 'Out of Scope: Internal admin panel.' Do not test. Move to a different endpoint."

**UNCLEAR:** "third-party.target.com appears to be a CNAME to Zendesk. This is a third-party service not owned by TargetCorp. Most programs exclude third-party services even if they're in the scope wildcard. Do not test without explicit confirmation."

## Safe Harbor Check

Before testing, confirm the program has a safe harbor clause:
```
Look for: "We will not pursue legal action against security researchers who..."
If no safe harbor → be more careful → stick strictly to documented scope
```
