# Title: Privilege Escalation via Mass Assignment in User Profile

- **Platform**: YesWeHack
- **Program**: French SaaS Platform
- **Severity**: High
- **Date**: 2024
- **Researcher**: N/A
- **Bounty**: N/A

## Summary
A mass assignment vulnerability in the user profile update endpoint allowed a standard user to escalate privileges by including the `role` field in their profile update request, which the server blindly accepted.

## Technical Details
The platform used a Ruby on Rails backend with strong parameters, but the user profile update endpoint had been configured to accept all user attributes without filtering. When a user updated their profile via `PUT /api/users/profile`, the server used `User.update(params)` which accepted any attribute in the User model, including `role`.

By adding `role: "admin"` to the profile update payload, the server updated the user's role in the database without any additional authorization check.

## Steps to Reproduce
1. Register a standard user account on the platform
2. Intercept the profile update request in Burp Suite
3. Add the `role` parameter with value `admin` to the request body
4. Forward the request
5. Observe that the platform reflects the updated profile with admin role
6. Access admin-only features to confirm escalation

## Proof of Concept
```
PUT /api/users/profile HTTP/1.1
Host: app.target.com
Authorization: Bearer user_token
Content-Type: application/json

{
  "name": "Attacker Name",
  "email": "attacker@test.com",
  "role": "admin"
}
```

## Impact
- Any user could escalate to administrator
- Full administrative access to the platform
- Data exfiltration and system compromise

## Remediation
The platform:
- Implemented attribute whitelisting using strong parameters
- Added server-side authorization checks for role changes
- Conducted a code audit to identify similar mass assignment vulnerabilities

## References
- https://www.yeswehack.com/learn/bug-bounty/privilege-escalation-mass-assignment
