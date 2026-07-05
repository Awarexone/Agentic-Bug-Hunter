# Title: OAuth Misconfiguration Leads to Full Account Takeover via CSRF

- **Platform**: Bugcrowd
- **Program**: Private Program (example.com)
- **Severity**: High (P2)
- **Date**: 2024
- **Researcher**: Yasser (Neroli)
- **Bounty**: N/A

## Summary
An OAuth misconfiguration combined with missing CSRF token in the OAuth callback allowed account takeover. An attacker could link a victim's account to their own social media profile via a CSRF attack, gaining permanent access to the victim's account.

## Technical Details
The application allowed users to login via email/password and link social media accounts via OAuth. The OAuth callback URL lacked a CSRF token (state parameter). Without this protection, an attacker could craft a malicious page that triggers the OAuth linking flow, binding the attacker's social media account to the victim's existing account. Once linked, the attacker could log in using their social media account and access the victim's account.

## Steps to Reproduce
1. Identify the OAuth callback URL without state/CSRF parameter
2. Intercept the OAuth callback request
3. Create an HTML page that auto-submits a form to this URL
4. Host the page and send it to the victim (social engineering)
5. When victim visits the page, their account is linked to attacker's social media
6. Attacker logs in via social media → full access to victim's account

## Proof of Concept
```
CSRF Payload to link attacker's social account to victim's account:
<html>
<body>
<form action="https://example.com/oauth/callback" method="GET">
  <input type="hidden" name="code" value="ATTACKER_AUTH_CODE">
  <input type="hidden" name="state" value="">
</form>
<script>document.forms[0].submit();</script>
</body>
</html>

// No state/CSRF token validation
// Victim's account is now linked to attacker's social profile
```

## Impact
Full account takeover. Once the OAuth account linking is complete, the attacker can login as the victim at any time using their own social media credentials. The victim may not notice until significant damage is done.

## Remediation
Implement CSRF protection using the `state` parameter in all OAuth flows. The state parameter should be a cryptographically random value bound to the user's session. Verify the state parameter on the callback endpoint before processing the OAuth response.

## References
- https://infosecwriteups.com/oauth-misconfiguration-leads-to-full-account-takeover-22b032cb6732
