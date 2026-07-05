# Title: Reflected Cross-Site Scripting (XSS) on Google Acquisition Domain

- **Platform**: Google VRP
- **Program**: Google Vulnerability Reward Program
- **Severity**: High
- **Date**: 2024-11-25
- **Researcher**: Akbar Kustirama
- **Bounty**: $3,133.70

## Summary
A reflected cross-site scripting vulnerability was discovered on span.sproute.net, a domain associated with a Google acquisition. The `email` parameter in the sign-in page reflected user input directly into the HTML without proper sanitization.

## Technical Details
The vulnerability was found on the sign-in page at `https://span.sproute.net/signin/`. The `email` query parameter was taken from the URL and reflected directly into the page HTML without any encoding or sanitization. This allowed an attacker to break out of the existing HTML context and inject arbitrary JavaScript.

The parameter was likely used to pre-fill the email field in the sign-in form, but the implementation simply concatenated the parameter value into the HTML string. No output encoding functions were applied.

## Steps to Reproduce
1. Access the affected URL with the payload embedded in the query parameter:
   `https://span.sproute.net/signin/?email=asdf"><script>alert(document.domain)</script>`
2. Observe that the payload is reflected in the HTML response without sanitization
3. The JavaScript executes, displaying an alert with the domain name

## Proof of Concept
```
Request:
GET /signin/?email=asdf"><script>alert(document.domain)</script> HTTP/1.1
Host: span.sproute.net

Response snippet:
<input type="email" name="email" value="asdf"><script>alert(document.domain)</script>" ...
```

## Impact
An attacker could craft a malicious link and trick a user into clicking it. Upon clicking, the injected script executes in the victim's browser, potentially allowing:
- Theft of session cookies
- Redirection to phishing pages
- Performing actions on behalf of the victim
- Defacement of the page
- Data exfiltration

## Remediation
Google fixed the issue by properly encoding the email parameter output. The fix involved using contextual output escaping (HTML entity encoding) for the reflected value, preventing script injection.

## References
- https://bughunters.google.com/reports/vrp/qZmd7EJHp
