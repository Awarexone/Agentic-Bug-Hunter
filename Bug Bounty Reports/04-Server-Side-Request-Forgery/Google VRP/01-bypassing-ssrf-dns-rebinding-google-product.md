# Title: Bypassing SSRF Restrictions on a Google Product via DNS Rebinding

- **Platform**: Google VRP
- **Program**: Google Vulnerability Reward Program
- **Severity**: High
- **Date**: 2024-07-20
- **Researcher**: Muthu D (anonysm)
- **Bounty**: $5,000+

## Summary
A blind SSRF vulnerability was discovered in a Google product that initially only allowed arbitrary HTTP requests without significant impact. By leveraging DNS rebinding, the researcher bypassed SSRF restrictions to perform internal network port scanning, revealing open internal services.

## Technical Details
The researcher found a blind SSRF vulnerability where a Google product would make HTTP requests to URLs supplied by the user. Initially, the SSRF was "blind" — the response content was not returned to the attacker. Direct attempts to access internal IP ranges (10.x.x.x, 172.x.x.x, 192.168.x.x) were blocked.

The researcher used DNS rebinding to bypass these restrictions. DNS rebinding tricks the server into thinking it's connecting to a legitimate external domain, but the DNS resolution changes between queries to point to an internal IP address.

Using a DNS rebinding service (rbndr.us), the researcher set up a domain that initially resolved to an external IP (passing validation) but later resolved to internal IPs.

## Steps to Reproduce
1. Identify the blind SSRF endpoint in the Google product
2. Set up a DNS rebinding domain that resolves to both external and internal IPs
3. Configure the TTL to be very short
4. Submit the DNS rebinding URL to the SSRF endpoint
5. When the server follows the redirect, it connects to internal IPs
6. Analyze response timing to identify open ports

## Proof of Concept
DNS rebinding configuration:
```
Domain: 7f000001.0ef11380.rbndr.us
Initial resolve: 203.0.113.128 (external)
After rebind: 127.0.0.1 (internal)
```

SSRF endpoint with rebinding URL:
```
POST /vulnerable-endpoint HTTP/1.1
Host: google-product.com
Content-Type: application/json

{"url": "http://7f000001.0ef11380.rbndr.us:8080/admin"}
```

Timing analysis revealed open ports (fast response = open, slow = closed/timeout).

## Impact
- Internal network port scanning
- Discovery of internal services (admin panels, databases, etc.)
- Potential access to internal-only endpoints
- Bypass of SSRF protection mechanisms
- Chaining with other vulnerabilities for deeper access

## Remediation
Google fixed the vulnerability by:
1. Implementing proper DNS rebinding protection
2. Validating the final resolved IP address, not just the initial hostname
3. Adding a DNS pinning mechanism to prevent IP changes between queries
4. Blocking private IP ranges even after DNS resolution

## References
- https://anonysm.medium.com/bypassing-ssrf-restrictions-on-a-google-product-a-journey-through-dns-rebinding-a4e9d18213af
