# Title: Intigriti Program - CSRF Allowing Unauthorized Actions

- **Platform**: Intigriti
- **Program**: E-commerce SaaS Platform
- **Severity**: Medium
- **Date**: 2024
- **Researcher**: N/A
- **Bounty**: N/A

## Summary
A cross-site request forgery (CSRF) vulnerability was discovered in an Intigriti bug bounty program's e-commerce platform, allowing unauthorized state-changing actions on behalf of authenticated users.

## Technical Details
The application used CSRF tokens for sensitive operations but improperly implemented the token validation. The CSRF token was stored in a cookie that was sent with all requests, and the server-side validation only checked if the token parameter matched the cookie value. Since the cookie was automatically sent by the browser for same-site requests, and an attacker could read the token via subdomain takeover or XSS, this created a bypass scenario.

Additionally, some endpoints lacked CSRF protection entirely, including:
- Profile email change
- Subscription cancellation
- API key regeneration

## Steps to Reproduce
1. Authenticate on the target platform
2. Navigate to the profile settings page
3. Intercept the email change request
4. Observe that the request contains a CSRF token from a cookie
5. Test if the endpoint works without the CSRF token
6. Find that the API key regeneration endpoint has no CSRF protection
7. Craft a CSRF PoC for the unprotected endpoint
8. Host on a malicious page and trick the victim into visiting

## Proof of Concept
```html
<html>
<body>
<form action="https://target.com/api/regenerate-key" method="POST">
<input type="hidden" name="confirm" value="true" />
<input type="submit" value="Submit" />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```

## Impact
An attacker could force victims to:
- Change their registered email address
- Cancel active subscriptions
- Regenerate API keys (breaking integrations)
- Modify account settings

## Remediation
The platform implemented proper CSRF protection across all state-changing endpoints using double-submit cookie pattern with proper validation on the server side.

## References
- https://app.intigriti.com/programs/torfs/torfs/detail (CSRF listed as in-scope low severity)
