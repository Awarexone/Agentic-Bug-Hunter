# Title: Facebook Page Admin Privilege Escalation

- **Platform**: Facebook Bug Bounty
- **Program**: Facebook Pages
- **Severity**: High
- **Date**: 2022
- **Researcher**: N/A
- **Bounty**: $10,000

## Summary
A privilege escalation vulnerability was discovered in Facebook Pages where a page editor could escalate their role to admin by exploiting an API endpoint that improperly validated page roles.

## Technical Details
Facebook Pages have multiple roles: Editor, Moderator, Advertiser, and Admin. The API endpoint for updating page roles had a flaw where a user could include additional role changes in a batch request that the server would process without verifying the user's current role permissions.

By intercepting the Add Editor request and modifying it to include a role promotion for themselves to Admin, the server processed the entire batch without checking if the requester had sufficient permissions to grant admin roles.

## Steps to Reproduce
1. Gain editor access to a Facebook Page
2. Use the Graph API to inspect the page role management endpoint
3. Create a batch request that adds a new editor AND changes the requesting user's role to admin
4. Send the batch request
5. Observe that the user's role is upgraded to admin
6. Confirm admin access to the page

## Proof of Concept
```json
POST /GRAPHQL HTTP/1.1
Host: graph.facebook.com

batch=[{"method":"POST","relative_url":"v15.0/PAGE_ID/admins","body":"user_id=ATTACKER_ID&role=admin"}]
```

## Impact
- Unauthorized admin access to Facebook Pages
- Ability to delete the page, remove other admins, and access page insights
- Potential brand impersonation and content abuse

## Remediation
Facebook fixed the batch processing endpoint to validate permissions for each individual operation rather than just the first one.

## References
- https://www.facebook.com/whitehat/ (Facebook Bug Bounty - Privilege Escalation)
