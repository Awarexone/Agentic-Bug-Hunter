# Title: Privilege Escalation via GraphQL Batching

- **Platform**: Intigriti
- **Program**: E-commerce Platform
- **Severity**: High
- **Date**: 2024
- **Researcher**: N/A
- **Bounty**: N/A

## Summary
A privilege escalation vulnerability was discovered in an e-commerce platform's GraphQL API where a standard user could escalate to admin by exploiting the batching functionality to mix mutations with different privilege levels.

## Technical Details
The platform used GraphQL with role-based permissions. Each mutation checked whether the authenticated user had the appropriate role. However, the GraphQL batching endpoint allowed multiple mutations to be sent in a single request, and the authorization check was only performed on the first mutation in the batch.

By crafting a batch with a low-privilege mutation first (that would pass authorization) followed by an admin-level mutation, the server would execute both without checking authorization for the second mutation.

## Steps to Reproduce
1. Log in as a standard user
2. Capture the GraphQL endpoint URL
3. Craft a batched GraphQL request:
   - First mutation: update profile (authorized as standard user)
   - Second mutation: admin add user (restricted to admin)
4. Send the batch request
5. Observe that the admin mutation executes successfully

## Proof of Concept
```graphql
[
  {
    "query": "mutation { updateProfile(name: \"test\") { id } }"
  },
  {
    "query": "mutation { addAdminRole(userId: 123) { id } }"
  }
]
```

## Impact
- Any authenticated user could perform admin-level actions
- Creation of admin accounts, modification of system settings
- Full system compromise

## Remediation
The platform fixed the authorization logic to validate each mutation individually within a batch, rather than relying on a single check for the entire request.

## References
- https://www.intigriti.com/blog/bug-bounty/graphql-batching-privilege-escalation
