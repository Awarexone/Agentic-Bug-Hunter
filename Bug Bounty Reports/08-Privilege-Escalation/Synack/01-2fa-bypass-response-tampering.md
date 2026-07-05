# Title: Two-Factor Authentication Bypass via Response Tampering

- **Platform**: Synack
- **Program**: Enterprise Application
- **Severity**: High
- **Date**: June 2024
- **Researcher**: Ozgur Alp (Synack Red Team)
- **Bounty**: $800

## Summary

Two enterprise applications were found to perform Two-Factor Authentication (2FA) verification on the client side rather than the server. Both applications trusted the HTTP response from the client to determine whether the OTP validation succeeded. By intercepting and modifying the server response, an attacker could bypass 2FA entirely and gain unauthorized access to authenticated sessions.

## Technical Details

The first application returned an HTTP error response when an invalid OTP code was submitted. The application's client-side code checked this response and displayed the 2FA challenge again if the response indicated failure. However, by intercepting the error response and changing its status or body to resemble a successful authentication response, the 2FA verification step was completely bypassed, and the user was logged into the authenticated session.

The second application exhibited an even simpler vulnerability. When a user submitted an OTP, the server returned a JSON response indicating success or failure. By intercepting the failed OTP response and replacing the entire JSON body with a success response structure, the application would advance the session past the 2FA gate without valid OTP verification.

## Steps to Reproduce

**Application 1:**
1. Authenticate with username and password (reaching the 2FA challenge page)
2. Submit an arbitrary/incorrect OTP code
3. Intercept the HTTP response using a proxy (e.g., Burp Suite)
4. Modify the response status code and body to reflect a successful authentication
5. Forward the tampered response to the browser
6. Observe that the application grants full access to the authenticated session

**Application 2:**
1. Authenticate with username and password
2. Submit any OTP code to the `/api/verify-otp` endpoint
3. Intercept the JSON response
4. Replace the response body with `{"success": true, "session": "valid_session_token"}`
5. Forward the response
6. The application accepts the modified response and logs the user in

## Proof of Concept

```http
# Original failed response (intercepted)
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{"success": false, "error": "Invalid OTP code", "remaining_attempts": 2}

# Modified successful response (forwarded)
HTTP/1.1 200 OK
Content-Type: application/json

{"success": true, "session": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", "user": {"id": 1234, "role": "admin"}}
```

## Impact

An attacker who has obtained a user's primary credentials (via phishing, credential stuffing, or data breach) could bypass the 2FA protection that would otherwise prevent account takeover. This effectively nullifies the security benefit of multi-factor authentication.

For applications with administrative panels, this could lead to:
- Full account takeover of privileged users
- Unauthorized access to sensitive customer data
- Ability to perform state-changing operations on behalf of the victim

## Remediation

- Move all OTP verification logic to the server side
- Never rely on client-side responses to determine authentication state
- Generate a secure, server-side session token only after successful OTP verification on the server
- Implement proper session management that ties the session to the completed authentication flow
- Conduct thorough testing of authentication bypass scenarios

## References
- https://www.linkedin.com/company/synack-red-team (Synack Red Team 2FA bypass post)
