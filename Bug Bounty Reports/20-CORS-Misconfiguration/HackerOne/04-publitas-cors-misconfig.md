# Title: CORS Misconfiguration on Publitas

- **Platform**: HackerOne
- **Program**: Publitas
- **Severity**: Medium
- **Date**: January 24, 2024
- **Researcher**: 2k_hacker
- **Bounty**: N/A

## Summary
A CORS misconfiguration was discovered on Publitas where the WordPress REST API endpoint reflected arbitrary origins with `Access-Control-Allow-Credentials: true`, allowing authenticated cross-origin data access.

## Technical Details
The Publitas website was running WordPress and its REST API endpoint returned permissive CORS headers. The `Access-Control-Allow-Origin` header dynamically reflected the request's `Origin` header, and `Access-Control-Allow-Credentials: true` was set. This allowed third-party websites to make authenticated cross-origin requests to the WordPress API.

## Steps to Reproduce
1. Visit the target Publitas URL and intercept the request
2. Add `Origin: https://attacker.com` header
3. Observe response includes `Access-Control-Allow-Origin: https://attacker.com`
4. Confirm credentials are enabled
5. Craft a CORS exploit page

## Proof of Concept
```
Request:
GET /wp-json/ HTTP/2
Host: ███████
Origin: https://evil.com
Cookie: ██████

Response:
HTTP/2 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
Access-Control-Allow-Methods: OPTIONS, GET, POST, PUT, PATCH, DELETE
```

## Impact
An attacker could steal sensitive information from the WordPress REST API, including posts, user data, and configuration details. With `Access-Control-Allow-Credentials: true`, authenticated data could be extracted from logged-in users.

## Remediation
Configure WordPress to only allow specific origins for CORS requests. This can be done via the `allowed_http_origins` filter in WordPress or via server-level configuration (Apache/Nginx). Never reflect arbitrary origins when credentials are enabled.

## References
- https://hackerone.com/reports/2332728
