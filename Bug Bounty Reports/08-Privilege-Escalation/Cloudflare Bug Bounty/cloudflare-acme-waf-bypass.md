# Title: ACL Bypass via ACME Challenge Path - WAF Rules Disabled for Sensitive Endpoints

- **Platform**: Cloudflare Bug Bounty
- **Program**: Cloudflare
- **Severity**: High
- **Date**: 2025-10-09
- **Researcher**: FearsOff
- **Bounty**: N/A

## Summary

A high-severity vulnerability in Cloudflare's handling of ACME HTTP-01 challenge paths allowed attackers to bypass all WAF rules, access controls, and security features for any hostname. The ACME challenge endpoint (`.well-known/acme-challenge/`) had security features disabled to allow Let's Encrypt certificate validation, but the implementation failed to properly validate that requests were legitimate ACME challenges.

## Technical Details

Cloudflare's infrastructure includes special handling for the ACME HTTP-01 challenge path (`/.well-known/acme-challenge/`) to allow Let's Encrypt to validate domain ownership. This path needs to bypass certain security features so that challenge responses are served correctly. However, the implementation was too permissive - ANY request to this path had security features disabled, not just legitimate ACME validation requests.

An attacker could prepend `/.well-known/acme-challenge/` to any URL path and bypass all Cloudflare security controls, including WAF rules, IP access restrictions, and authentication checks. This effectively nullified Cloudflare's security for any request using this path.

The vulnerability particularly affected:
- Spring/Tomcat applications using servlet path traversal (`..;/`)
- Next.js server-side rendering applications leaking operational data
- PHP applications with local file inclusion vulnerabilities
- Account-level WAF rules configured with custom header conditions

## Steps to Reproduce

1. Identify a Cloudflare-protected website
2. Craft a request targeting a sensitive endpoint using the ACME path:
   ```
   GET /.well-known/acme-challenge/../admin HTTP/1.1
   Host: target.com
   ```
3. Observe that WAF rules and access controls are bypassed
4. Access endpoints that should be protected by Cloudflare security features

## Proof of Concept

```http
GET /.well-known/acme-challenge/../../../admin/panel HTTP/1.1
Host: vulnerable-target.com
```

This request would bypass WAF rules and reach the origin server's admin panel, even if Cloudflare WAF rules were configured to block such paths.

For Spring Boot applications:
```http
GET /.well-known/acme-challenge/..;/actuator/env HTTP/1.1
Host: vulnerable-target.com
```

This would expose environment variables including database credentials and API tokens.

## Impact

- Complete bypass of WAF rules for any hostname
- Access to sensitive actuator endpoints on Java/Spring applications
- Exposure of environment variables, credentials, and API tokens
- Server-Side Request Forgery via exposed debug endpoints
- Local File Inclusion exploitation on vulnerable PHP applications
- Arbitrary file read on vulnerable applications

## Remediation

Cloudflare deployed a permanent fix on October 27, 2025, modifying the code to disable security features only when requests match valid ACME HTTP-01 challenge tokens for the specific hostname. Post-fix testing confirmed WAF rules now apply uniformly across all paths.

## References
- https://blog.cloudflare.com/acme-path-vulnerability/
- https://cybersecuritynews.com/cloudflare-zero-day-vulnerability/
