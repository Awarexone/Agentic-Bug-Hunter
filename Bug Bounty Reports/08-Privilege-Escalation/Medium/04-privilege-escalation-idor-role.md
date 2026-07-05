# Title: Privilege Escalation via IDOR in User Role Assignment

- **Platform**: Medium
- **Program**: Enterprise SaaS Platform
- **Severity**: High
- **Date**: 2024
- **Researcher**: N/A
- **Bounty**: N/A

## Summary
A privilege escalation vulnerability was discovered in an enterprise SaaS platform where a low-privileged user could escalate their role to administrator by manipulating an IDOR in the user role assignment endpoint.

## Technical Details
The application used a role-based access control system with three tiers: User, Manager, and Admin. The user management endpoint `/api/admin/users/{id}/role` was intended for administrators to change user roles. However, the endpoint only checked if the authenticated user was an admin on the client side, and the API endpoint itself lacked proper server-side authorization checks.

A standard user could directly call the API endpoint with a PUT request to change their own role to admin. The API accepted any role value without verifying the requester's permissions.

## Steps to Reproduce
1. Log in as a standard user
2. Capture the authentication token from any API request
3. Send a PUT request to `/api/admin/users/{your_user_id}/role`
4. Set the body to `{"role": "admin"}`
5. Observe the response indicates success
6. Refresh the application to confirm admin access

## Proof of Concept
```
PUT /api/admin/users/123/role HTTP/1.1
Host: target.com
Authorization: Bearer user_token
Content-Type: application/json

{"role": "admin"}
```

## Impact
- Any user could escalate to administrator
- Full access to all administrative functions
- Data exfiltration, user management, and system configuration access

## Remediation
The platform implemented server-side authorization checks to verify that only users with the admin role could modify user roles.

## References
- https://medium.com/@privexploit/privilege-escalation-via-idor-in-user-role-assignment-7c4b2q2e1f2a
