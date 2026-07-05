# Title: Password Reset Token Leak Leading to Full Account Takeover

- **Platform**: Uber Bug Bounty
- **Program**: Uber
- **Severity**: Critical
- **Date**: 2016-10-02
- **Researcher**: procode701
- **Bounty**: $10,000

## Summary

A critical vulnerability in Uber's password reset flow allowed an attacker to completely take over any Uber account knowing only the victim's email address. The password reset token was exposed in the HTTP response of the password reset request, enabling an attacker to immediately reset the victim's password without any interaction from the victim.

## Technical Details

When a user initiates a password reset on Uber's platform, a reset token is typically sent via email to verify the user's identity. However, Uber's implementation had a critical flaw: the same password reset token that was sent via email was also returned in the HTTP response body of the password reset API request.

An attacker could:
1. Initiate a password reset for any known Uber account email
2. Intercept the HTTP response from the password reset endpoint
3. Extract the reset token directly from the response
4. Use the token to set a new password and take over the account

This completely bypassed the email-based verification step, as the attacker never needed access to the victim's email inbox.

## Steps to Reproduce

1. Attacker knows the victim's email address associated with their Uber account
2. Attacker sends a POST request to the password reset endpoint with the victim's email
3. The server processes the reset and sends a legitimate email to the victim
4. However, the HTTP response also contains the reset token in plaintext
5. Attacker extracts the token and uses it immediately to reset the password
6. Attacker logs in with the new password - complete account takeover

## Proof of Concept

```http
POST /password/reset HTTP/1.1
Host: auth.uber.com
Content-Type: application/json

{"email": "victim@example.com"}

HTTP/1.1 200 OK
Content-Type: application/json

{"token": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6", "status": "success"}
```

The attacker copies the `token` value and sends:
```http
POST /password/reset/confirm HTTP/1.1
Host: auth.uber.com
Content-Type: application/json

{"token": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6", "password": "newpassword123"}
```

## Impact

- Complete account takeover of any Uber account (rider or driver)
- Access to trip history, payment methods, and personal information
- Ability to request rides, change account settings, and view sensitive data
- Potential fraud by requesting rides on the victim's payment methods
- All Uber accounts were vulnerable regardless of security settings

## Remediation

Uber fixed this vulnerability immediately upon validation. The fix involved:
- Removing the reset token from API responses
- Implementing server-side session validation instead of token-based validation
- Adding additional verification steps in the password reset flow
- Ensuring tokens are only delivered via email and never exposed in API responses

## References
- https://hackerone.com/reports/173551
- https://www.uber.com/newsroom/bug-bounty-program/
