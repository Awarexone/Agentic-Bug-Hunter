# Title: OAuth Misconfiguration Found on WeMedia (Opera) - Account Squatting

- **Platform**: Bugcrowd
- **Program**: Opera Public Bug Bounty
- **Severity**: Medium (P4)
- **Date**: October 12, 2021
- **Researcher**: h__cker
- **Bounty**: $150

## Summary
An OAuth misconfiguration on Opera's WeMedia application allowed account squatting. When third-party authentication cookies were not properly invalidated after logout from both the app and authentication server, a local attacker could gain access to the victim's account on the same device.

## Technical Details
The vulnerability was in how OAuth session cookies were handled during logout. When a user logged out of the WeMedia application, the OAuth provider's session cookies were not properly invalidated. This meant that immediately after logout, a new user on the same device could re-authenticate using the cached OAuth session, gaining access to the previous user's account.

## Steps to Reproduce
1. User A logs into WeMedia via OAuth (e.g., Google/Facebook)
2. User A uses the application normally
3. User A logs out of WeMedia
4. User A does NOT log out of the OAuth provider (Google/Facebook)
5. User B (or attacker with device access) clicks "Login with Google"
6. The OAuth flow uses User A's still-valid OAuth session
7. User B is logged into User A's WeMedia account

## Proof of Concept
```
1. Victim logs into https://wemedia.opera.com with Google
2. Victim clicks "Logout" on WeMedia
3. Attacker opens same browser, clicks "Login with Google"
4. Google shows "Already logged in as victim@gmail.com"
5. Attacker clicks "Continue" and gains access to victim's WeMedia account
```

## Impact
Account takeover on the same device. An attacker with access to a victim's unlocked device could access their WeMedia account even after the victim logged out of the application.

## Remediation
Implement Single Sign-Out (SLO) — when a user logs out of the application, also revoke the OAuth provider session. Use the OAuth provider's logout endpoint to invalidate the federated session. Clear all locally stored session data.

## References
- https://bugcrowd.com/disclosures/6ff09a42-c27f-4d5d-9e7c-8eaafe8eee70/oauth-misconfiguration-found-on-https-wemedia-opera-com
