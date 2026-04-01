# Unico IDTech — Program-Specific Rules

These rules override or supplement the general hunting rules when working the Unico IDTech program.

---

## Rule U1: SEMPRE incluir Transaction ID e Process ID em reports de liveness

Every liveness bypass report MUST include:
- `Transaction ID` — from the successful bypass attempt
- `Process ID` — from the successful bypass attempt

**Without these fields, the backend team cannot validate the bypass chain.**
A report missing these fields will be marked as Needs More Info immediately.

How to get them:
- Web: DevTools → Network → SDK API response JSON → `transactionId`, `processId`
- Android: `result.getTransactionId()`, `result.getProcessId()` in SDK callback
- iOS: `result.transactionId`, `result.processId` in delegate method

---

## Rule U2: SEMPRE adicionar headers obrigatórios em requests web

All HTTP requests to Unico's assets must include:
```
X-HackerOne-Research: [YOUR_H1_USERNAME]
User-Agent: [YOUR_H1_USERNAME]
```

Set these in Burp Suite once:
- Proxy → Options → Match and Replace → Add rule:
  - Type: Request Header
  - Match: (empty)
  - Replace: `X-HackerOne-Research: your_username`

---

## Rule U3: NUNCA testar o wrapper app — apenas o SDK biométrico

**In scope**: The biometric capture and processing ENGINE (the SDK)
**Out of scope**: The wrapper test applications (app UI, buttons, navigation)

If a bug is in the test app's interface only (e.g., a UI bug, an app crash, bad error message), do NOT report it. The test apps serve solely to facilitate SDK testing.

Signs a bug is in the SDK (reportable):
- SDK returns a positive liveness result it shouldn't
- SDK processes tampered/forged data without detecting manipulation
- SDK's decision logic is manipulated in memory

Signs a bug is in the wrapper only (not reportable):
- App crashes but SDK decision is not affected
- App UI shows wrong information
- App has XSS/CSRF/other web bugs in its interface (the app is not the scope)

---

## Rule U4: Critérios mínimos de reporte por tipo de ataque

Do NOT report a liveness finding unless it meets the program's threshold:

| Attack Type | Minimum Threshold to Report |
|---|---|
| Photo Attack | Bypass rate >1% over 100 attempts |
| Video Replay | Bypass successful on 3+ different face samples |
| 3D Mask/Model | Any mask achieves >5% success rate |
| Deepfake | Real-time bypass with <500ms latency |
| Memory Manipulation | Persistence across engine restarts |
| Template Injection | Bypass works on multiple formats |
| Timing Attacks | Reproducible >50% of attempts |
| Capture Relay | Bypass works across different sessions |
| Stream Manipulation | Manipulation undetected by engine |
| Session Hijacking | State can be copied between instances |

**Below threshold = kill the lead. N/A hurts your validity ratio.**

---

## Rule U5: Mobile testing requer physical device

The mobile SDK apps DO NOT work on:
- Android emulators (AVD, Genymotion, etc.)
- iOS simulators (Xcode Simulator)

You MUST use physical devices:
- Android: API 23 (Android 6.0) or higher
- iOS: iOS 14.0 or higher

Recommended for testing: **Android Native** and **iOS Native** apps (direct SDK integration, smoother performance). Flutter apps use native SDK as bridge.

---

## Rule U6: Apps expiram após 30 dias

Mobile test apps have a 30-day TTL. If the app shows errors or stops working:
1. Go to https://sdk-h1.unico.io/mobile-sdks
2. Download and install the latest version
3. Do NOT report app expiration as a bug

Web application does not expire.

---

## Rule U7: Scope exclusions específicas da Unico

These are explicitly excluded by Unico — do not report, do not spend time on:

**Always rejected (instant close):**
- Clickjacking (even on sensitive pages, unless extraordinary impact)
- CSRF on any form
- Missing security headers (HSTS, CSP, X-Frame-Options)
- Missing HttpOnly or Secure cookie flags
- SSL/TLS misconfiguration
- SPF/DKIM/DMARC issues
- Self-XSS
- DOM XSS without demonstrated impact
- Open redirect without demonstrated real impact chain
- Rate limiting on unauthenticated endpoints
- DoS/availability attacks
- Content spoofing without HTML/CSS modification
- Subdomain takeover
- Version disclosure / banner grabbing / descriptive errors
- CSV injection without demonstrated impact
- Expired or invalid credentials that don't provide access
- MITM or physical access attacks
- Vulnerabilities requiring unlikely user interaction
- Bugs affecting outdated/unpatched browsers only
- Vulnerable libraries without functional PoC
- Social engineering (phishing, vishing, smishing) — strictly prohibited

---

## Rule U8: Dois accounts de teste para IDOR

For any IDOR testing in the web scope, you MUST use two separate accounts:
- **Account A (attacker)**: your account — authenticated requests from here
- **Account B (victim)**: second account — whose data you're attempting to access

Never test IDOR using only one account or using real user data.
Never interact with accounts you don't own.

---

## Rule U9: Disclosure policy

Do NOT publicly disclose vulnerabilities until:
1. Unico has resolved the issue
2. Unico has given explicit consent for disclosure

Follow HackerOne's standard disclosure timeline.
Program response efficiency is above 90% — they are responsive.
