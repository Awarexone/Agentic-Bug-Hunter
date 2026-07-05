# Title: Privilege Escalation via HTTP Request Manipulation in ZenML

- **Platform**: Protect AI (huntr)
- **Program**: ZenML (Open Source Bug Bounty)
- **Severity**: High
- **Date**: 2024-07-15
- **Researcher**: huntr community member
- **Bounty**: Not disclosed

## Summary
A privilege escalation vulnerability was discovered in ZenML, an open-source MLOps framework. Authenticated users with normal privileges could escalate their privileges to the server account by modifying the `is_service_account` parameter in HTTP request payloads, potentially compromising the entire system.

## Technical Details
ZenML's API uses a parameter called `is_service_account` to distinguish between regular user accounts and service accounts with elevated privileges. The server relied on this client-supplied parameter without proper server-side validation or enforcement. By intercepting the HTTP request and changing this parameter from `false` to `true`, a regular user could gain the privileges of a service account. Service accounts had elevated permissions including access to pipeline runs, artifact stores, and administrative functions.

## Steps to Reproduce
1. Log in to the ZenML dashboard as a regular user
2. Intercept the HTTP request using a proxy like Burp Suite
3. Locate the `is_service_account` parameter in the request body
4. Modify its value from `false` to `true`
5. Forward the modified request
6. Observe that the server grants service account privileges

## Proof of Concept
```http
POST /api/v1/users/update HTTP/1.1
Host: zenml-instance.com
Authorization: Bearer [user_token]
Content-Type: application/json

{
  "username": "attacker",
  "is_service_account": true,
  "permissions": ["admin", "read_all", "write_all"]
}
```

## Impact
- Unauthorized access to all pipeline runs and their artifacts
- Ability to modify or delete ML models and training data
- Access to stored credentials and API keys in the artifact store
- Lateral movement to connected infrastructure (MLflow, S3, GCS)
- Complete compromise of the MLOps pipeline and data integrity

## Remediation
- Move privilege assignment to server-side logic only
- Never trust client-provided authorization parameters
- Implement role-based access control (RBAC) enforced server-side
- Use signed tokens (JWT) for session management that include privilege claims
- Apply least privilege principle by default
- Add audit logging for all privilege changes

## References
- https://huntr.com/bounties/94815e9f-df2c-4766-87f6-26353129732f
- https://protectai.com/threat-research/july-vulnerability-report
