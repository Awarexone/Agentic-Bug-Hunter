# Title: Open Redirect in OAuth Logout Flow

- **Platform**: Bugcrowd
- **Program**: Social Media Platform
- **Severity**: Medium
- **Date**: 2024
- **Researcher**: N/A
- **Bounty**: N/A

## Summary
An open redirect vulnerability was discovered in a social media platform's OAuth logout flow where the `redirect_uri` parameter was not properly validated, allowing an attacker to redirect users to arbitrary external domains.

## Technical Details
The platform's OAuth logout endpoint at `/oauth/logout` accepted a `redirect_uri` parameter to return the user to a specific page after logout. The validation logic only checked if the redirect URI contained the platform's domain as a substring, rather than requiring an exact match or validating against a whitelist.

An attacker could craft a URL like:
```
https://target.com/oauth/logout?redirect_uri=https://target.com.evil-phishing-site.com
```

The validation would pass because `target.com` appears as a substring in the redirect URI, even though the actual destination is `evil-phishing-site.com`.

## Steps to Reproduce
1. Navigate to the OAuth logout endpoint
2. Test with a redirect_uri pointing to an external domain
3. Observe that the redirect_uri passes validation if it contains the target domain as a substring
4. Craft a phishing URL and send it to a victim

## Proof of Concept
```
https://target.com/oauth/logout?redirect_uri=https://target.com.attacker.com/login?next=attacker-controlled-page
```

## Impact
- Phishing attacks — victims see the legitimate domain in the URL before being redirected
- Bypass of URL reputation filters
- Credential theft if the landing page mimics the login form

## Remediation
The platform implemented a strict allowlist-based redirect URI validation, requiring exact matches against registered callback URLs.

## References
- https://bugcrowd.com/vulnerability/open-redirect-oauth-logout
