# Title: Open Redirect via Path Traversal in Redirect Endpoint

- **Platform**: Intigriti
- **Program**: European News Portal
- **Severity**: Medium
- **Date**: 2024
- **Researcher**: N/A
- **Bounty**: N/A

## Summary
An open redirect vulnerability was discovered in a European news portal's redirect endpoint where path traversal could be used to bypass domain validation and redirect users to arbitrary external sites.

## Technical Details
The news portal used a redirect tracking endpoint at `/redirect?url=/articles/123` that would validate the URL parameter. The validation checked if the URL started with `/` (indicating a relative path) and would prepend the domain. However, the endpoint did not canonicalize the path before prepending.

By using path traversal sequences, an attacker could craft:
```
/redirect?url=/articles/../../https://evil.com
```

The path traversal would resolve to `https://evil.com` when the browser processed the redirect, because `/articles/../../` navigates up to the root, and then `https://evil.com` is interpreted as a protocol-relative URL or as a path component depending on browser behavior.

## Steps to Reproduce
1. Find the redirect endpoint on the news portal
2. Test with a path traversal payload in the URL parameter
3. Observe the redirect behavior
4. Craft a payload that redirects to an external domain

## Proof of Concept
```
GET /redirect?url=/articles/../../https://evil.com HTTP/1.1
Host: news-portal.com

Response: 302 Found
Location: https://news-portal.com/https:/evil.com
```

Some browsers normalize double slashes, treating `https:/evil.com` (single slash) as `https://evil.com`.

## Impact
- Phishing attacks using the news portal's domain
- Bypassing domain reputation filters
- Credential theft

## Remediation
The news portal:
- Added URL canonicalization before validation
- Blocked path traversal sequences in the redirect parameter
- Implemented a strict allowlist of allowed redirect paths

## References
- https://www.intigriti.com/programs (Open Redirect category)
