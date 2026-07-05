# Title: Open Redirect via Host Header Injection

- **Platform**: YesWeHack
- **Program**: European Banking Portal
- **Severity**: Medium
- **Date**: 2024
- **Researcher**: N/A
- **Bounty**: N/A

## Summary
An open redirect vulnerability was discovered in a European banking portal where the application used the `Host` header to construct redirect URLs without validation, allowing attackers to redirect users to arbitrary domains.

## Technical Details
The banking portal had a "language switcher" feature that redirected users to language-specific subdomains. The application constructed the redirect URL using the `Host` header from the incoming request:
```python
redirect_url = f"https://{request.host}/{language_prefix}/"
```

By sending a request with a modified `Host` header, the application would construct a redirect URL pointing to the attacker's domain:

```
GET /switch-language/en HTTP/1.1
Host: banking-portal.com@evil.com
```

The response would contain:
```
Location: https://banking-portal.com@evil.com/en/
```

In some URL parsers, everything after `@` is treated as the actual host, making the redirect go to `evil.com`.

## Steps to Reproduce
1. Navigate to the banking portal's language switcher endpoint
2. Intercept the request with a proxy
3. Modify the `Host` header to an attacker-controlled domain
4. Forward the request
5. Observe that the Location header in the response points to the attacker's domain

## Proof of Concept
```
GET /switch-language/de HTTP/1.1
Host: target.com@evil.com
User-Agent: Mozilla/5.0

HTTP/1.1 302 Found
Location: https://target.com@evil.com/de/
```

## Impact
- Phishing attacks targeting banking customers
- Credential theft via fake banking login pages
- Financial fraud and account compromise

## Remediation
The banking portal:
- Stopped using the `Host` header to construct redirect URLs
- Used a whitelist of allowed subdomains for language switching
- Implemented proper URL validation and canonicalization

## References
- https://www.yeswehack.com/learn/bug-bounty/open-redirect-host-header
