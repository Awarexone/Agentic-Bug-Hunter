# Title: Exceeding Workspace Limit via Race Condition in Workspace Creation

- **Platform**: HackerOne
- **Program**: SingleStore
- **Severity**: Low
- **Date**: July 2025
- **Researcher**: bl4ck-
- **Bounty**: N/A

## Summary
A race condition vulnerability in SingleStore's workspace creation process allowed users to exceed the maximum number of workspaces allowed per organization. By sending multiple parallel requests to create workspaces, the limit check was bypassed.

## Technical Details
SingleStore limits the number of workspaces per organization. The workspace creation process checked the current count before creating a new workspace. However, this check-and-insert operation was not performed atomically. Multiple simultaneous requests could all read the pre-insert count simultaneously and all proceed to create workspaces, exceeding the limit.

## Steps to Reproduce
1. Identify the workspace creation endpoint
2. Fill workspace details and intercept the creation request
3. Send 10+ parallel creation requests
4. Observe that more workspaces are created than the limit allows

## Proof of Concept
```
POST /api/v1/workspaces/create HTTP/1.1
Host: app.singlestore.com
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Extra Workspace",
  "region": "us-east-1",
  "size": "small"
}

// Send 10 parallel requests
// Server accepts 10, despite limit of 5 per org
```

## Impact
Bypass of business restrictions on resource usage. Users could create unlimited workspaces, potentially incurring unexpected costs for the organization and abusing free-tier limitations.

## Remediation
Use database-level locking mechanisms such as `SELECT FOR UPDATE` or optimistic locking when checking and incrementing workspace counts. Implement unique constraints on workspace creation per organization. Use idempotency keys.

## References
- https://hackerone.com/reports/3295500
