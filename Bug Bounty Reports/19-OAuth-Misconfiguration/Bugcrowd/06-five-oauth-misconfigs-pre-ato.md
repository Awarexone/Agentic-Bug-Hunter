# Title: 5 OAuth Misconfigurations Leading to Pre-Account Takeover in Bugcrowd Programs

- **Platform**: Bugcrowd
- **Program**: Multiple Public Programs (NASA, U.S. Dept of Veterans Affairs, etc.)
- **Severity**: High (P2)
- **Date**: August 24, 2025
- **Researcher**: Khaled Ahmed (KhaledAhmed107)
- **Bounty**: N/A (Duplicates)

## Summary
Five instances of OAuth misconfiguration were found across different Bugcrowd public programs, all leading to Pre-Account Takeover (Pre-ATO). The common pattern: when a user signed up via OAuth using the same email as an existing email/password account, the system didn't verify ownership.

## Technical Details
The vulnerable pattern was consistent across all five programs: the applications supported both email/password and OAuth login. If an email was already registered via email/password, signing up with the same email via OAuth would either overwrite the existing account or create a parallel account — effectively giving the OAuth user access to the email/password account's data.

## Steps to Reproduce
1. Register an account on target.com using email/password with victim@example.com
2. Log out
3. Visit target.com and click "Login with Google"
4. Use a Google account with email victim@example.com
5. If the application accepts this without verification → Pre-ATO exists

## Proof of Concept
```
// Across 5 different Bugcrowd programs:

Program 1: Accepts OAuth signup with existing email → account overwrite
Program 2: Links OAuth to existing account without verification → shared access
Program 3: Creates parallel account → confusion/mix-up
Program 4: OAuth flow doesn't check email ownership → Pre-ATO
Program 5: OAuth login with unverified email → account access

All follow the pattern:
1. victim@email.com exists via email/password
2. Attacker uses OAuth with victim@email.com
3. Application accepts without ownership verification
```

## Impact
Pre-Account Takeover across multiple programs. An attacker could claim accounts before real users complete registration, or take over existing accounts by linking their OAuth profile. Sensitive data exposure across government and private programs.

## Remediation
For all OAuth implementations: use the OAuth provider's unique user ID (`sub`) as primary identifier, not email. When linking accounts, require proof of ownership (existing password or email confirmation). Implement strict account linking flows.

## References
- https://medium.com/@KhaledAhmed107/how-i-found-5-oauth-misconfigurations-leading-to-pre-account-takeover-in-public-bug-bounty-programs-021d4c8c6954
