# Title: OAuth Misconfiguration Leads to Complete Account Takeover

- **Platform**: Medium
- **Program**: Various Programs
- **Severity**: Critical
- **Date**: January 20, 2019
- **Researcher**: Jacksonkv22
- **Bounty**: N/A

## Summary
An OAuth misconfiguration was found that allowed complete account takeover. The application allowed users to login with Google OAuth but failed to properly verify that the email returned by the OAuth provider matched an existing account, or allowed the OAuth flow to create new sessions for already-registered emails without proper authentication.

## Technical Details
The OAuth implementation had a fundamental flaw: when a user authenticated via the OAuth provider (Google), the application trusted the email returned in the OAuth response without verifying ownership. If an account with that email already existed, the application would log the user into that account rather than creating a new one. An attacker could register a Google account with a victim's email, then use that to access the victim's account on the target application.

## Steps to Reproduce
1. Identify target application with Google OAuth login
2. Register a Google account with victim@example.com (if possible)
3. Click "Login with Google" on the target application
4. The application returns the victim's account session
5. Full access to victim's data

## Proof of Concept
```
1. Attacker creates Google account with email "victim@gmail.com"
2. Attacker visits target.com and clicks "Login with Google"
3. Google OAuth returns: { email: "victim@gmail.com", sub: "google_uid" }
4. Target.com checks: "Does victim@gmail.com exist? Yes!"
5. Target.com logs attacker into victim's account
6. Attacker has full access to victim's data
```

## Impact
Complete account takeover. An attacker could access all victim data including personal information, payment methods, private messages, and connected services. No user interaction required.

## Remediation
Verify OAuth email ownership by requiring email confirmation before linking OAuth to existing accounts. Use the `sub` claim (unique OAuth provider ID) as the primary identifier rather than email. Implement account linking flows that require existing password confirmation.

## References
- https://medium.com/@Jacksonkv22/oauth-misconfiguration-lead-to-complete-account-takeover-c8e4e89a96a
