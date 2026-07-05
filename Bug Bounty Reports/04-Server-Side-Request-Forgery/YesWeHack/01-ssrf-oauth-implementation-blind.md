# Title: Blind SSRF in OAuth Implementation of a Client Application

- **Platform**: YesWeHack
- **Program**: Private Bug Bounty Program
- **Severity**: Medium
- **Date**: 2024-03-20
- **Researcher**: Ahmed Fadel
- **Bounty**: Undisclosed ($$$)

## Summary
A blind server-side request forgery vulnerability was discovered in the OAuth implementation of a client application. By configuring a custom OAuth server and pointing the Token URL to internal addresses, the researcher confirmed that the application's backend made requests to arbitrary URLs.

## Technical Details
The target application `example.com` allowed users to add a custom OAuth server to access resources. The OAuth flow required the application to request an access token from the Token URL configured by the user. This request was made by the backend server, not the browser.

The researcher set up:
1. A custom OAuth server on Google Cloud Platform
2. Configured the application to use this custom OAuth server
3. Initially used a Burp Collaborator URL as the Token URL

When the authentication flow completed, the backend made a POST request to the Burp Collaborator URL. This confirmed the backend was making requests to user-supplied URLs.

The researcher then tried:
- `http://127.0.0.1` — received a stack trace "Content-Type is not JSON compatible"
- This confirmed the server made a request to localhost
- The SSRF was blind (no response body returned), but port scanning was possible via timing differences

## Steps to Reproduce
1. Set up a custom OAuth server (e.g., on GCP, or use any OAuth provider)
2. In the application, configure the OAuth settings with a custom Token URL
3. Initially set the Token URL to Burp Collaborator to confirm requests are sent
4. Change the Token URL to `http://127.0.0.1` and complete the OAuth flow
5. Observe the stack trace confirming localhost access
6. Use timing analysis for port scanning (ECONNREFUSED for closed ports)

## Proof of Concept
OAuth configuration:
```
Token URL: http://127.0.0.1/api/admin
```

The backend request resulted in a recognizable error, confirming SSRF. For port scanning:
```
Token URL: http://127.0.0.1:3306 -> Timeout (closed)
Token URL: http://127.0.0.1:80 -> Fast response (open - HTTP)
Token URL: http://127.0.0.1:443 -> Fast response (open - HTTPS)
```

## Impact
- Blind SSRF confirmed against internal resources
- Internal port scanning capability
- Potential interaction with internal services
- Information gathering about the internal network
- While full read access was not achieved, the blind SSRF could be used for internal reconnaissance

## Remediation
The program fixed the issue by:
1. Implementing URL validation/allowlisting for Token URLs
2. Blocking requests to private IP ranges
3. Validating that the OAuth server URL resolves to external IPs only
4. Implementing network-level restrictions on outbound requests

## References
- https://medium.com/@ahmedfadel6162/bug-bounty-write-up-ssrf-in-oauth-implementation-of-a-client-application-57ba02539e20
