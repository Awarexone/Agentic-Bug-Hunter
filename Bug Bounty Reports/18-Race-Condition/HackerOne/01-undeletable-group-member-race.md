# Title: Race Condition Leads to Undeletable Group Member

- **Platform**: HackerOne
- **Program**: HackerOne
- **Severity**: Low
- **Date**: June 9, 2019
- **Researcher**: yashrs
- **Bounty**: N/A

## Summary
A race condition vulnerability allowed a user to add themselves twice to a group, making them permanently unremovable. Neither the group admin nor the user themselves could remove the duplicate membership, resulting in permanent group access.

## Technical Details
The group join functionality lacked proper idempotency checks. When a user joins a group via an invitation link, the server checks if the user is already a member. However, by sending two join requests simultaneously, both requests could pass the membership check before either one completes, resulting in two membership records for the same user.

## Steps to Reproduce
1. Create a group with account A and generate an invitation link
2. With account B, intercept the POST request to join the group
3. Send two identical join requests simultaneously using a race condition tool
4. Both requests succeed, creating duplicate membership entries
5. Try to remove the user from the group — the action fails
6. The user cannot be removed by anyone, including the group admin

## Proof of Concept
```
POST /group/post_join HTTP/1.1
Host: ctf.hacker101.com
Content-Type: application/x-www-form-urlencoded
Cookie: <session>

csrf=391aecf0c3125e90c437d04c18204ab6&invite=bb5c42ab578b12c63e5d868b3e03816c8c45597262aaf095ca2be19116b8fd0a

// Send this request twice simultaneously
// Both return 200 OK
// User is now duplicated in group membership table
```

## Impact
Permanent group membership that cannot be revoked. This violates access control policies, allowing unauthorized users to maintain access to private groups and their contents indefinitely.

## Remediation
Use database-level unique constraints on group membership (user_id + group_id). Implement atomic database operations with proper locking to prevent race conditions. Check for existing membership within the same transactional context as the insert operation.

## References
- https://hackerone.com/reports/604534
