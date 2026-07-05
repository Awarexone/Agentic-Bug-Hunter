# Title: IDOR in GraphQL — Delete Other Users' Certifications - $12,500

- **Platform**: HackerOne
- **Program**: HackerOne Bug Bounty Program
- **Severity**: High
- **Date**: 2023-08-15
- **Researcher**: Harshdranjan
- **Bounty**: $12,500

## Summary
An insecure direct object reference vulnerability was discovered in HackerOne's own GraphQL API. The `CreateOrUpdateHackerCertification` mutation allowed deleting or modifying any user's certifications by simply changing the certification ID, without any ownership verification.

## Technical Details
HackerOne allows users to add Licenses and Certifications to their profiles. These actions are handled through a GraphQL mutation called `CreateOrUpdateHackerCertification`. The mutation accepted a `certificationId` parameter to identify which certification to update or delete.

The critical flaw was that the server trusted the `certificationId` entirely — it never checked whether the logged-in user actually owned the specified certification. This allowed any authenticated user to modify or delete certifications belonging to any other user by simply iterating through certification IDs.

The vulnerability was straightforward: a user could intercept the GraphQL request in Burp Suite, change the `certificationId` parameter to another user's certification ID, and forward the request. The server would process it without any authorization check.

## Steps to Reproduce
1. Log into HackerOne with Account A
2. Add a certification and intercept the GraphQL request
3. Observe the request body contains `certificationId: 123`
4. Change the ID to `certificationId: 124` (belonging to Account B)
5. Forward the request
6. Account B's certification is deleted or modified without permission

## Proof of Concept
GraphQL mutation:
```graphql
mutation {
  CreateOrUpdateHackerCertification(input: {
    certificationId: 124,
    name: "Modified Certification",
    issuer: "Attacker"
  }) {
    ...
  }
}
```

The server returns a success response despite the certification belonging to another user.

## Impact
- Delete or modify any user's professional certifications
- Ability to iterate over ID ranges to mass-delete data
- Damage user trust and platform integrity
- Tampering with professional credentials displayed on profiles
- Demonstration of a critical authorization gap in HackerOne's own platform

## Remediation
HackerOne fixed the issue by implementing proper ownership validation on the certification endpoints. Before performing any create, update, or delete operation, the server now verifies that the authenticated user owns the specified certification. The fix was applied to all GraphQL mutations accepting object IDs.

## References
- https://medium.com/h7w/12-500-bounty-how-changing-one-graphql-id-let-me-delete-other-users-data-4a6e1c70ae12
- HackerOne Report ID: #2122671
