# Title: Authentication Bypass via Response Manipulation

- **Platform**: Intigriti
- **Program**: European SaaS Platform
- **Severity**: High
- **Date**: 2024
- **Researcher**: N/A
- **Bounty**: N/A

## Summary
An authentication bypass vulnerability was discovered in a European SaaS platform where the login response could be manipulated to grant unauthorized access. The server returned a boolean `success` field in the login response, and modifying this response allowed bypassing authentication.

## Technical Details
The application used a REST API for authentication. The login endpoint `/api/login` accepted email and password and returned a JSON response. Instead of using standard HTTP status codes or secure session tokens, the application relied on a boolean `success` field in the JSON response to determine authentication state on the client side.

By intercepting the login response and changing `"success": false` to `"success": true`, the client-side application would treat the user as authenticated and grant access to protected functionality.

This occurred because the server did not set proper session cookies or tokens; all access control was implemented client-side based on the login response.

## Steps to Reproduce
1. Navigate to the application login page
2. Enter any email and password (even incorrect ones)
3. Intercept the login response using a proxy tool
4. Modify the JSON response from `{"success": false, "error": "Invalid credentials"}` to `{"success": true, "user": {"id": 1, "role": "admin"}}`
5. Forward the modified response
6. Observe that the application grants full access

## Proof of Concept
Original response:
```json
HTTP/1.1 200 OK
Content-Type: application/json

{"success": false, "error": "Invalid email or password"}
```

Modified response:
```json
HTTP/1.1 200 OK
Content-Type: application/json

{"success": true, "user": {"id": 1, "name": "Admin", "role": "admin"}}
```

## Impact
- Full authentication bypass — anyone could access the application without valid credentials
- Access to all features, including admin functionality
- Potential data breach of all users' information

## Remediation
The platform implemented proper server-side authentication using secure session tokens (JWT) and moved all access control checks to the server side.

## References
- https://www.intigriti.com/programs (Authentication Bypass category)
