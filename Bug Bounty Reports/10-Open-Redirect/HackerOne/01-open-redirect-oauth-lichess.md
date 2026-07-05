# Title: Open Redirect Vulnerability in OAuth Flow Leading to Potential Phishing Attack

- **Platform**: HackerOne
- **Program**: Lichess
- **Severity**: Low (CVSS 3.6)
- **Date**: April 18, 2025
- **Researcher**: delsec_
- **Bounty**: N/A

## Summary
An open redirect vulnerability was discovered in the OAuth flow on lichess4545.com that allowed an attacker to redirect users to arbitrary external domains after authorization, enabling phishing attacks.

## Technical Details
The OAuth authorization flow on `lichess4545.com` accepted a `redirect_uri` parameter that was not properly validated. While the server checked that the redirect URI started with the expected domain `https://www.lichess4545.com/auth/lichess/`, it did not properly validate that the URI ended there. By injecting additional domain components, an attacker could redirect the user to any external website after completing the OAuth authorization.

## Steps to Reproduce
1. Start the OAuth login flow on lichess4545.com
2. Intercept the authorization request to Lichess
3. Notice the `redirect_uri` parameter
4. Change `redirect_uri=https://www.lichess4545.com/auth/lichess/` to `redirect_uri=https://example.com/auth/lichess/`
5. Complete the authorization by clicking "Authorize"
6. The browser redirects to `https://example.com/` instead of lichess4545.com
7. The authorization code is appended to the attacker's URL

## Proof of Concept
```
Request:
GET https://lichess.com/oauth/authorize?response_type=code&client_id=...&redirect_uri=https://example.com/auth/lichess/&scope=...

Response: 302 Redirect
Location: https://example.com/auth/lichess/?code=AUTH_CODE&state=...
```

## Impact
- Phishing attacks using the legitimate Lichess domain for trust
- Theft of OAuth authorization codes
- Potential account compromise through chained attacks
- Loss of user trust in the platform's security

## Remediation
Lichess fixed the issue by implementing proper validation of the `redirect_uri` parameter, ensuring it exactly matches the expected callback URL rather than just checking the prefix.

## References
- https://hackerone.com/reports/3099816
