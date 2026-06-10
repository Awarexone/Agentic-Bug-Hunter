---
description: Validate a finding — runs 7-Question Gate + 4-gate checklist. Kills weak findings before report writing. Prevents N/A submissions that hurt validity ratio. Usage: /validate
---

# /validate

Run full validation on the current finding before writing a report.

## What This Does

1. Runs 7-Question Gate (one wrong answer = kill it)
2. Checks against the always-rejected list
3. Runs 4 pre-submission gates
4. Outputs: PASS (write the report) or KILL (move on)

## Usage

```
/validate
```

Describe the finding when prompted. Include:
- The endpoint
- The bug class
- What the PoC shows
- The target program

If you already ran the scanner, pass its `summary.json` with
`--scanner-summary findings/<target>/summary.json` so the validation record
captures the scanner tiering that led to this finding.

## The 7-Question Gate

Answer each. ONE wrong answer = STOP.

### Q1: Can I demonstrate this step-by-step RIGHT NOW?

Write this out:
```
1. Setup:   I need [own account / another user's ID / no account]
2. Request: [exact HTTP method, URL, headers, body]
3. Result:  Response shows [exact data / action completed]
4. Impact:  Real consequence is [account takeover / PII exposed / money stolen]
5. Cost:    Time: [X min], Capital: [$0 / $X]
```

If step 2 is "I need to look at the code more" → KILL IT.

### Q2: Is the impact accepted by this program?

Check program scope page. Is your bug class listed? Is it excluded?

### Q3: Is the vulnerable asset in scope?

Exact domain in scope? Not staging/dev? Not a third-party service?

### Q4: Does it need admin or privileged access that an attacker can't get?

"Admin can do X" → KILL IT.
"Regular user can do X that only admin should" → valid.

### Q5: Is this known or documented behavior?

Search disclosed reports + changelog + API docs.

### Q6: Can you prove impact beyond "technically possible"?

- XSS → actual cookie value in exfil request, not just alert()
- SSRF → response body from internal service, not just DNS callback
- IDOR → actual other-user's private data in response, not just 200 status

### Q7: Is this on the never-submit list?

```
Missing headers, GraphQL introspection alone, clickjacking without PoC,
self-XSS, open redirect alone, SSRF DNS-only, logout CSRF, banner disclosure,
rate limit on non-critical forms, missing cookie flags alone...
```

If yes → KILL IT unless you have a chain.

### Auth-related findings need cross-identity proof

For IDOR, BOLA, auth bypass, ATO, and privilege escalation:
- Session A must reach Session B's data or action
- A fresh session must still reproduce the result
- Anonymous vs authenticated behavior must be different

Blank identity answers fail automatically.

## Check: Conditionally Valid?

If it's on the never-submit list, can you chain it?

| You Have | Chain Available? |
|---|---|
| Open redirect | + OAuth code theft → ATO? |
| SSRF DNS-only | + internal service data? |
| Clickjacking | + sensitive action + PoC? |
| CORS wildcard | + credentialed data exfil? |
| Prompt injection | + IDOR → other user's data? |

If no chain → KILL IT. If chain confirmed → report both together.

## Common N/A Classes

Kill these before writing a report unless you have a proven chain or data delta:

- Reflected XSS without impact beyond alert-level proof
- SSRF DNS callback only
- IDOR on your own account
- SQLi error only, no data returned
- CORS wildcard without credentialed exfil
- Open redirect without token theft
- MFA no lockout without OTP bypass
- SAML metadata exposure without signature abuse

## 4 Gates — All Must Pass

**Gate 0 (30 sec):**
```
[ ] Confirmed with real HTTP requests (not just code reading)
[ ] In scope (checked program page)
[ ] Reproducible from scratch
[ ] Evidence captured
```

**Gate 1 — Impact (2 min):**
```
[ ] Can answer "What does attacker walk away with?"
[ ] More than "sees non-sensitive data"
[ ] Real victim exists
[ ] No unlikely preconditions
```

**Gate 2 — Dedup (5 min):**
```
[ ] Searched HackerOne Hacktivity for endpoint + bug class
[ ] Searched GitHub issues
[ ] Read 5 most recent disclosed reports
[ ] Not in changelog as known issue
```

**Gate 3 — Report quality (10 min):**
```
[ ] Title formula: [Class] in [Endpoint] allows [actor] to [impact]
[ ] Steps have exact HTTP request
[ ] Evidence shows actual impact
[ ] CVSS calculated
[ ] Fix: 1-2 concrete sentences
```

## Output

**PASS:** "All 7 questions pass. All 4 gates pass. Proceed to /report."

**KILL:** "Q[N] fails because [reason]. Kill this finding. Reason: [explanation]. Move on."

**DOWNGRADE:** "Q6 only shows technical possibility. Downgrade from High to Medium. Requires showing actual data exfil in PoC."
