# Reporting Rules

Report quality directly impacts payout. Triagers are busy. Make their job easy.

---

## 1. NEVER USE THEORETICAL LANGUAGE

```
NEVER: "could potentially allow"
NEVER: "may allow an attacker to"
NEVER: "might be possible"
NEVER: "could lead to"
NEVER: "could be chained with X to cause Y"

ALWAYS: "An attacker can [exact action] by [exact method]"
```

If you can't write a concrete statement → you don't have a bug yet.

## 2. RUN 7-QUESTION GATE BEFORE WRITING

Every finding must pass all 7 questions before spending time on a report.

One NO = kill it immediately. N/A hurts your validity ratio more than missing a bug.

## 3. ALWAYS INCLUDE PROOF OF CONCEPT

- IDOR → show victim's actual data in the response (not just 200 OK)
- XSS → show actual cookie exfil (not just alert(document.domain))
- SSRF → show actual internal service response (not just DNS callback)
- SQLi → show actual database content (not just error message)

A "technically possible" finding without PoC is an Informational at best.

## 4. CVSS MUST MATCH ACTUAL IMPACT

Don't claim Critical for a Medium bug. Triagers trust you less for every overclaim.
Don't claim Medium for a Critical — you're leaving money on the table.

Use the CVSS 3.1 formula. Common scoring:
- IDOR read PII (auth required): 6.5 Medium
- Auth bypass → admin: 9.8 Critical
- SSRF → cloud metadata: 9.1 Critical

## 5. NEVER SUBMIT FROM THE ALWAYS-REJECTED LIST

These are always N/A. Never submit them standalone:

```
Missing headers (CSP, HSTS, X-Frame-Options)
GraphQL introspection alone
Self-XSS
Open redirect alone
SSRF DNS-only
Logout CSRF
Missing cookie flags alone
Rate limit on non-critical forms
Banner/version disclosure without working exploit
```

Build the chain first. Prove it works. Then report.

## 6. VERIFY DATA ISN'T ALREADY PUBLIC

Before submitting an information disclosure finding:
1. Open the target in an incognito browser (not logged in)
2. Can you see the same data without authentication?
3. If yes → not a bug

## 7. TWO TEST ACCOUNTS FOR IDOR

Never test IDOR with only one account (testing yourself).
- Account A = attacker (your account doing the request)
- Account B = victim (whose data you're reading)

Report must show: "I sent request with Account A's token but Account B's ID, and received Account B's private data."

## 8. REPORT FORMAT BY PLATFORM

**HackerOne:** Impact-first summary → CVSS → Steps to Reproduce → Impact → Fix
**Bugcrowd:** VRT category in title → Description → Expected vs Actual → Severity Justification
**Intigriti:** CVSS prominent → Clear steps → Business impact
**Immunefi:** Root cause in code → Foundry PoC → $ impact quantified

## 9. UNDER 600 WORDS

Triagers skim. Long reports get skimmed harder.

Structure:
- Sentence 1: What attacker can do (impact)
- Sentence 2-3: How (endpoint, parameter, method)
- Steps to reproduce: numbered, with exact HTTP request
- Impact: one paragraph, quantified
- Fix: 1-2 sentences

## 10. ESCALATION LANGUAGE (WHEN PAYOUT IS DOWNGRADED)

```
"This requires only a free account — no special privileges."
"The data includes [PII type], subject to GDPR/CCPA requirements."
"An attacker can automate this — all [N] records in minutes."
"This is externally exploitable with no internal access required."
"Impact equivalent to a full breach of [feature/data type]."
```

## 11. DON'T COMBINE SEPARATE BUGS

If A and B are independent bugs (different endpoints, different impact):
- Report them as SEPARATE reports = separate payouts
- Only combine if they're part of ONE attack chain that requires both

## 12. TITLE FORMULA — NEVER DEVIATE

```
[Bug Class] in [Exact Endpoint/Feature] allows [attacker role] to [impact] [scope]
```

Examples:
```
IDOR in /api/v2/invoices/{id} allows authenticated user to read any customer's invoice
Missing auth on POST /api/admin/users allows unauthenticated creation of admin accounts
Stored XSS in profile bio field executes in admin panel — privilege escalation possible
```

Bad (never use):
```
IDOR vulnerability found
Security issue in API
XSS in user input
```
