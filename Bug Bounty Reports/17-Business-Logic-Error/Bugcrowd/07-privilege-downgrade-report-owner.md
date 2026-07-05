# Title: Business Logic Error Leads to Unauthorized Privilege Downgrade of Report Owner

- **Platform**: Bugcrowd
- **Program**: Private Program
- **Severity**: High
- **Date**: April 2025
- **Researcher**: som3a
- **Bounty**: N/A

## Summary
A business logic error in a bug bounty platform allowed an attacker to downgrade the privileges of a report owner. The vulnerability exploited missing authorization checks in the report management workflow, allowing unauthorized role changes.

## Technical Details
The report management system had a role-management feature where report owners could assign/change roles for participants. The vulnerability existed because the API endpoint that processed role changes did not properly verify that the requesting user was authorized to change the target user's role. Specifically, there was no check ensuring that a user could only be downgraded by someone with appropriate permissions.

## Steps to Reproduce
1. Identify the role management API endpoint
2. Capture the request for changing user roles on a report
3. Modify the request to target a report owner
4. Change the role parameter from "owner" to a lower privilege level
5. Submit the request — the server processes it without authorization verification

## Proof of Concept
```
POST /api/v1/reports/role/update HTTP/1.1
Host: platform.com
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "report_id": "12345",
  "target_user_id": "owner_user_id",
  "new_role": "viewer"
}

Response: 200 OK
{ "message": "Role updated successfully" }
```

## Impact
Unauthorized privilege downgrade of report owners could lead to:
- Loss of control over reports
- Unauthorized modifications to report status and visibility
- Potential for malicious actors to hide or alter vulnerability reports

## Remediation
Implement strict server-side authorization checks for all role management operations. Only users with equal or higher privileges should be able to modify roles. Add confirmation workflows for sensitive privilege changes.

## References
- https://som3a.medium.com/business-logic-error-leads-to-unauthorized-privilege-downgrade-of-report-owner-d34fcb43e0f3
