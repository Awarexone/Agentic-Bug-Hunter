# Title: 1 Program, 4 Business Logic Bugs and Cashing in $2,300

- **Platform**: Medium
- **Program**: Browser Service Platform (InfoSec Writeups)
- **Severity**: High
- **Date**: January 17, 2024
- **Researcher**: Manav Bankatwala
- **Bounty**: $2,300

## Summary
Four business logic vulnerabilities were found in a single browser service platform. The bugs included: bypassing member invitation limits, no-plan users inviting members, race condition in browser profile creation, and low-privilege users accessing workspace data via API.

## Technical Details

### Bug 1: Member invitation limit bypass
The platform only checked member count when users accepted invitations, not when they were sent. Sending invitations to unlimited users and having them all accept at once bypassed the limit.

### Bug 2: No-plan user can invite members
The invite API lacked proper server-side authorization checks. A no-plan user's session token could be used to invite team members.

### Bug 3: Race condition in profile creation
Using Turbo Intruder to send simultaneous requests allowed creation of more profiles than the plan allowed (300 → 306).

### Bug 4: Low-privilege data access
API endpoints returned workspace data without checking user role permissions.

## Steps to Reproduce
Bug 1:
1. Send invitation links to multiple users
2. Have all accept before member count updates
3. All added without additional charges

Bug 3:
1. Create 298 browser profiles
2. Capture create profile request
3. Send 10+ simultaneous requests via Turbo Intruder
4. Profile count exceeds 300

## Proof of Concept
```
Bug 4 - Low Privilege API access:
GET https://api.target.com/workspace/restrictions
GET https://api.target.com/workspace/users?limit=100&offset=0
GET https://api.target.com/workspace/invitations?limit=1000&offset=0
GET https://api.target.com/workspace/user_balance
```

## Impact
Financial loss to the company through bypassed pricing tiers. Unauthorized data access by low-privilege users. Potential for massive abuse of platform resources.

## Remediation
Count pending invitations against member limits. Implement server-side authorization for all API endpoints. Use database-level locking for resource creation limits.

## References
- https://infosecwriteups.com/1-program-4-business-logic-bugs-and-cashing-in-2300-299b42236993
