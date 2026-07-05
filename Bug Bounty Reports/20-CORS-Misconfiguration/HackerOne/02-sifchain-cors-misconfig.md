# Title: CORS Misconfiguration on Sifchain Finance

- **Platform**: HackerOne
- **Program**: Sifchain
- **Severity**: Medium
- **Date**: May 12, 2021
- **Researcher**: itsme_ani
- **Bounty**: N/A

## Summary
A CORS misconfiguration was found on `sifchain.finance/wp-json` where `Access-Control-Allow-Origin` was dynamically fetched from the client's `Origin` header with `Credentials` set as true, allowing unauthorized cross-origin data access.

## Technical Details
The WordPress REST API endpoint at `/wp-json` was configured with a permissive CORS policy. The `Origin` header from the request was reflected back in the `Access-Control-Allow-Origin` response header, combined with `Access-Control-Allow-Credentials: true`. This allowed any external domain to make authenticated cross-origin requests to the WordPress API.

## Steps to Reproduce
1. Send a GET request to `https://sifchain.finance/wp-json` with `Origin: https://bing.com`
2. Observe the response includes `Access-Control-Allow-Origin: https://bing.com`
3. Confirms the CORS policy reflects arbitrary origins

## Proof of Concept
```
Request:
GET /wp-json HTTP/1.1
Host: sifchain.finance
Origin: https://bing.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0

Response:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://bing.com
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: X-WP-Total, X-WP-TotalPages, Link
Access-Control-Allow-Headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
Access-Control-Allow-Methods: OPTIONS, GET, POST, PUT, PATCH, DELETE
```

## Impact
Sensitive information exposure via the WordPress REST API. An attacker could access posts, pages, user data, and other WordPress resources. If cookies or authorization headers are sent, the attacker could access authenticated resources.

## Remediation
Implement a whitelist of allowed origins for the WordPress REST API. Remove the dynamic origin reflection. Restrict credentialed CORS to specific, trusted domains only.

## References
- https://hackerone.com/reports/1194280
