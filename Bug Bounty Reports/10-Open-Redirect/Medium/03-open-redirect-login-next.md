# Title: Open Redirect via URL Parameter Injection

- **Platform**: Medium
- **Program**: Cryptocurrency Exchange
- **Severity**: Medium
- **Date**: 2024
- **Researcher**: N/A
- **Bounty**: $750

## Summary
An open redirect vulnerability was discovered in a cryptocurrency exchange's login page where the `next` parameter after login redirected users without proper validation, enabling phishing attacks.

## Technical Details
The cryptocurrency exchange had a login page at `/login?next=/dashboard` that redirected users to the specified path after successful authentication. The `next` parameter accepted full URLs (including `http://` and `https://` schemes) and did not validate the destination against an allowed domain whitelist.

An attacker could craft:
```
https://exchange.com/login?next=https://phishing-site.com/login
```

A victim logging in would be redirected to the phishing site after authentication, which could be a convincing replica of the exchange's dashboard.

## Steps to Reproduce
1. Navigate to the exchange's login page
2. Append `?next=https://evil.com` to the URL
3. Note that the application processes the redirect parameter
4. Log in (or simulate a session) and observe the redirect to evil.com

## Proof of Concept
```
GET /login?next=https://phishing-attacker.com/authenticate HTTP/1.1
Host: exchange.com

Response: 302 Found
Location: https://phishing-attacker.com/authenticate
```

## Impact
- Phishing attacks targeting cryptocurrency users
- Credential theft via fake login pages
- Loss of user funds if combined with session token theft

## Remediation
The exchange:
- Implemented a whitelist of allowed redirect destinations
- Validated that the redirect URI is a relative path (starting with `/`)
- Used server-side validation instead of client-side redirects

## References
- https://medium.com/bug-bounty-hunting/open-redirect-via-url-parameter-injection-7c4b2q2e1f2a
