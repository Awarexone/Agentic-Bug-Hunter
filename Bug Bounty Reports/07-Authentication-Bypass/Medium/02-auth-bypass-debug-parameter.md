# Title: Authentication bypass via debug parameter left in production

- **Platform**: Medium
- **Program**: Fintech Application
- **Severity**: Critical (CVSS 9.8)
- **Date**: August 2025
- **Researcher**: Aj
- **Bounty**: N/A

## Summary
A critical authentication bypass vulnerability was discovered in a fintech application where a debug parameter (`auth=false`) was left in production, allowing anyone to access any user's data without authentication.

## Technical Details
The application used JSON-based API requests for authentication. While investigating API documentation in JavaScript files, a researcher discovered a hidden endpoint `/api/v2/auth/validate` that was used for session validation. By analyzing this endpoint, they found that the application accepted a query parameter `auth=false` that disabled authentication checks entirely.

When a request was sent to any user profile endpoint with `?id=USER_ID&auth=false`, the server returned full profile information without requiring any authentication token. The developers had left a debug flag enabled in production that bypassed all access controls.

## Steps to Reproduce
1. Identify the target application and its API endpoints
2. Discover the `/api/v2/auth/validate` endpoint in JavaScript files
3. Notice that some endpoints return partial data even without authentication tokens
4. Test sending requests with an `auth=false` parameter
5. Observe that the server returns full profile data without requiring authentication
6. Enumerate user IDs to access any user's data

## Proof of Concept
```
POST /api/login
Content-Type: application/json

{"username": "alice", "password": "SuperSecret123"}

Response: {"token": "valid_token"}

GET /api/user/profile?id=123
Authorization: Bearer <valid_token>

But with debug bypass:
GET /api/user/profile?id=123&auth=false
(No Authorization header needed)
Response: Full profile data including email, phone, address
```

## Impact
- Complete authentication bypass
- Access to any user's personal information
- Ability to perform actions on behalf of any user
- Full account takeover potential
- Data breach of all user records

## Remediation
The fintech company removed the debug parameter from the production environment and conducted a full code review to ensure no other debug functionality was exposed.

## References
- https://cybersecuritywriteups.com/bypassing-authentication-with-a-single-request-a-real-bug-bounty-story-9526dc2484d4
