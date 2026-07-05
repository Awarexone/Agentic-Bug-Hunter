# Title: HTTP Request Smuggling in Transform Rules Using Hexadecimal Escape Sequences

- **Platform**: Cloudflare Bug Bounty
- **Program**: Cloudflare
- **Severity**: Critical (CVSS 10.0)
- **Date**: 2022-02-11
- **Researcher**: albertspedersen
- **Bounty**: $6,000

## Summary

A critical HTTP Request Smuggling vulnerability was discovered in Cloudflare's Transform Rules engine. The `concat()` and `lower()` string functions accepted hexadecimal escape sequences (e.g., `\x0a\x0d`) that could be used to inject CRLF sequences into HTTP headers, enabling HTTP request smuggling attacks against origin servers.

## Technical Details

Cloudflare's Edge Rules engine includes Transform Rules that allow customers to modify HTTP request and response headers using string functions. The `lower()` and `concat()` functions accepted hexadecimal escape sequences like `\x0a` (newline) and `\x0d` (carriage return). When these were used to inject newlines into header values, Cloudflare would forward the malicious request to the origin server with the injected headers, potentially causing the origin to interpret a single request as two separate requests.

This created a classic request smuggling scenario where Cloudflare (the front-end) and the origin server (the back-end) could disagree on request boundaries.

## Steps to Reproduce

1. Create a Cloudflare Transform Rule that modifies a request header using the `concat()` function
2. Include hexadecimal escape sequences `\x0d\x0a` in the header value to inject CRLF
3. Send a request through Cloudflare to a target origin
4. The injected CRLF causes the origin to interpret the remainder of the original request as a new, smuggled request

## Proof of Concept

```javascript
// Transform Rule expression using concat() with hex escapes
concat($request.headers["x-forwarded-host"], "\\x0d\\x0aTransfer-Encoding: chunked\\x0d\\x0a\\x0d\\x0a")
```

When applied as a header modification, this injected `Transfer-Encoding: chunked` into the request, allowing request smuggling against origins that interpreted the injected headers.

## Impact

- HTTP request smuggling allowing an attacker to:
  - Bypass Cloudflare security controls (WAF, rate limiting)
  - Poison web caches with malicious content
  - Hijack user requests and steal sensitive data
  - Perform actions on behalf of other users
- Affected all Cloudflare customers using Transform Rules with string manipulation functions

## Remediation

Cloudflare deployed a fix that sanitized hexadecimal escape sequences in Transform Rule string functions, preventing CRLF injection. The fix ensured that special characters like `\x0a` and `\x0d` were properly escaped or rejected before being used in header values.

## References
- https://hackerone.com/reports/1478633
- https://vulners.com/hackerone/H1:1478633
- https://blog.cloudflare.com/tag/bug-bounty/
