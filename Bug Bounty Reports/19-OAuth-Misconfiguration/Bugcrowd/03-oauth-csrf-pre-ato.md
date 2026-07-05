# Title: OAuth Misconfiguration + Login CSRF Leads to Pre-ATO

- **Platform**: Bugcrowd
- **Program**: Private Program (redacted.com)
- **Severity**: High
- **Date**: August 7, 2025
- **Researcher**: YUZA
- **Bounty**: N/A (Duplicate)

## Summary
A vulnerability chain combining OAuth misconfiguration and missing CSRF protection on the login endpoint allowed pre-account takeover. An attacker could register with a victim's email, then when the victim signed up via OAuth, both parties silently shared access to the same account.

## Technical Details
The application supported both email/password and OAuth (Google) login. Two flaws existed:
1. OAuth misconfiguration: If email/password registration existed for an email, OAuth signup with the same email was allowed without ownership verification
2. No CSRF protection on the authenticate endpoint, allowing an attacker to force a victim to login as the attacker

## Steps to Reproduce
1. Attacker registers victim@gmail.com via email/password at dashboard.redacted.com
2. Attacker logs out during "Create Organization" step
3. Victim tries to register via Google OAuth with victim@gmail.com
4. Victim gets an error but also receives a verification email
5. Victim needs a valid session to use the verification link
6. Attacker sends a CSRF payload to the victim

## Proof of Concept
```
CSRF Payload sent to victim:
<html>
<body>
<form action="https://api.redacted.com/dashboard/auth/authenticate/" method="POST" enctype="application/json">
  <input type="hidden" name="email" value="attacker@gmail.com">
  <input type="hidden" name="password" value="Attackerpassword123#">
</form>
<script>document.forms[0].submit();</script>
</body>
</html>

Result: Victim logs in as attacker, clicks verification link
Both share access to the same account
```

## Impact
Pre-Account Takeover: attacker claims email before real user signs up. No ownership verification when signing up via OAuth. Victim and attacker silently share the same account, exposing billing info, API tokens, and PII.

## Remediation
Clear existing sessions when login method changes. Always verify ownership of email before activating accounts. If an account with that email already exists, prompt for confirmation. Add CSRF protection to login endpoints.

## References
- https://yuza7.wordpress.com/2025/08/07/oauth-misconfiguration-login-csrf-leads-to-pre-ato/
