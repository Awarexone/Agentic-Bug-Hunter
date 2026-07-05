# Title: Stored Cross-Site Scripting on terryberry.com

- **Platform**: OpenBugBounty
- **Program**: terryberry.com
- **Severity**: Medium
- **Date**: 2024-10-15
- **Researcher**: Dipu1A
- **Bounty**: N/A (Coordinated Disclosure)

## Summary
A stored Cross-Site Scripting (XSS) vulnerability was discovered on terryberry.com, an employee recognition and rewards platform. The vulnerability allowed an attacker to inject malicious JavaScript payloads into input fields that were persistently stored on the server and executed in the browsers of other users viewing the affected pages.

## Technical Details
The application failed to properly sanitize user-supplied input before storing it in the database and rendering it back to users. The vulnerability existed in the message/comment fields of the recognition submission form. User input was directly embedded into HTML without proper encoding or validation.

## Steps to Reproduce
1. Navigate to the recognition submission page on terryberry.com
2. Enter a malicious payload in the message/comment field
3. Submit the form
4. When another user (including administrators) views the recognition, the script executes

## Proof of Concept
The following payload was submitted in the message field:
```html
<script>alert('XSS')</script>
```
Alternatively, using an image-based payload to bypass potential filters:
```html
<IMG SRC=x onerror=alert(document.cookie)>
```

## Impact
An attacker could:
- Steal session cookies of authenticated users
- Deface pages for other users
- Perform actions on behalf of other users (CSRF chaining)
- Steal sensitive information displayed on the page

## Remediation
Implement proper output encoding and Content Security Policy (CSP) headers. All user-supplied input should be sanitized server-side using HTML encoding libraries appropriate for the technology stack.

## References
- https://www.openbugbounty.org/reports/4504129/
