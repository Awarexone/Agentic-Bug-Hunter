# Title: Open Redirect in Logout & Login

- **Platform**: HackerOne
- **Program**: Expedia Group Bug Bounty
- **Severity**: Medium
- **Date**: 2023
- **Researcher**: N/A
- **Bounty**: $1,000

## Summary
An open redirect vulnerability was discovered in Expedia Group's logout and login functionality, allowing attackers to redirect users to arbitrary external websites after authentication or session termination.

## Technical Details
Expedia's login and logout endpoints accepted a `redirect` or `returnUrl` parameter that determined where users were sent after completing the authentication action. The validation of these parameters was insufficient and could be bypassed, allowing an attacker to specify any external URL.

The vulnerability affected both the login redirect (where users are sent after signing in) and the logout redirect (where users are sent after signing out). This dual-vector attack surface made the vulnerability more dangerous as it could be exploited in different contexts.

## Steps to Reproduce
1. Visit the Expedia login page
2. Intercept the request or manipulate the `returnUrl` parameter in the URL
3. Change the URL to an external site (e.g., `https://evil.com`)
4. Complete the login process
5. The browser redirects to the attacker's website
6. Repeat the same for the logout endpoint

## Proof of Concept
```
Login redirect:
https://www.expedia.com/login?returnUrl=https://evil.com

Logout redirect:
https://www.expedia.com/logout?redirect=https://evil.com

Both redirect to https://evil.com after the respective action.
```

## Impact
- Phishing attacks using legitimate Expedia domains
- Credential theft through fake login pages displayed after redirect
- Bypass of URL reputation filters
- Potential session token leakage through the Referer header to the attacker's domain

## Remediation
Expedia Group fixed the issue by implementing strict validation of the redirect parameters, using a whitelist of allowed URLs. The login and logout redirect parameters now only accept relative paths or URLs that match Expedia's own domains.

## References
- https://hackerone.com/reports/1788006
