# Title: Bypass of Open Redirect Fix via Path Traversal on lovable.dev

- **Platform**: YesWeHack
- **Program**: lovable.dev
- **Severity**: Medium
- **Date**: 2026-03-12
- **Researcher**: marioniangi
- **Bounty**: N/A

## Summary
A bypass of a previously patched open redirect vulnerability on lovable.dev was discovered. The original fix blocked backslash-based payloads but failed to account for path traversal sequences combined with double slashes. By supplying `/..//google.com` as the redirect value, an attacker could still redirect authenticated users to arbitrary external domains.

## Technical Details
The application processes a `redirect` parameter during the post-login flow: `https://lovable.dev/auth/post-login?redirect=/..//google.com`. The original fix blocked `/\` and `/%5C` patterns, but did not handle the path traversal sequence `/..//`. When the browser resolves this path, it interprets the `..` as navigating up one directory level, and the double slash allows escaping to an external domain.

## Steps to Reproduce
1. Identify an open redirect endpoint in the application
2. Test the original redirect parameter with valid internal URLs
3. Attempt to bypass the fix using `/..//` followed by an external domain
4. If successful, the victim logs in and is redirected to the attacker's site

## Proof of Concept
```
# The post-login redirect endpoint
GET /auth/post-login?redirect=/..//google.com HTTP/1.1
Host: lovable.dev

# The server processes the path and redirects to https://google.com
# HTTP/1.1 302 Found
# Location: https://google.com
```

## Impact
- Phishing attacks by redirecting users after login
- Credential theft through convincing lookalike pages
- Bypass of security controls intended to prevent open redirects

## Remediation
The application implemented proper URL validation, ensuring only whitelisted internal paths are accepted as redirect targets, and rejecting any input containing traversal sequences or external domains.

## References
- https://academy.logicalbreach.com/writeups/bypass-of-open-redirect-fix-on-lovable-dev-via-path-traversal-in-redirect-parameter-9bc11b88
- https://hackerone.com/reports/3599248
