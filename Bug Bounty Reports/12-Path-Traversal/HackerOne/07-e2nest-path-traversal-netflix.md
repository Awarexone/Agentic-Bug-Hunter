# Title: Path Traversal in Netflix E2Nest

- **Platform**: HackerOne
- **Program**: Netflix Bug Bounty
- **Severity**: High
- **Date**: 2024-09-27
- **Researcher**: nathan31337 (ZeroPath)
- **Bounty**: N/A

## Summary
A path traversal vulnerability was discovered in Netflix's open-source project E2Nest (CVE-2024-9301). The URL parser relied on `os.path.commonprefix` for path validation, which could be bypassed with crafted inputs, allowing unauthenticated users to read arbitrary files from the server's filesystem.

## Technical Details
E2Nest parses the URL path to open video content within the `mp4_root` path. The application used `os.path.commonprefix` to verify the constructed path was within the intended directory. However, this string-based comparison could be bypassed with specific inputs containing relative path components. An attacker could supply malicious payloads in the URL path to perform path traversal and retrieve files outside `mp4_root`.

## Steps to Reproduce
1. Identify an E2Nest instance (versions before pull #16)
2. Examine the `mp4_byterange_view` function in `urls.py`
3. Craft a URL with path traversal sequences that bypass `os.path.commonprefix`
4. Access sensitive files from outside the intended directory

## Proof of Concept
```
# The vulnerable code in urls.py
# full_path = os.path.normpath(os.path.join(mp4_root, path))
# if os.path.commonprefix([full_path, mp4_root]) != mp4_root:
#     return HttpResponseForbidden()

# Bypass payload
GET /..%2f..%2f..%2fetc%2fpasswd HTTP/1.1
Host: e2nest.example.com

# Or using a path that passes commonprefix but traverses out
GET /allowed_dir/../../etc/passwd HTTP/1.1
Host: e2nest.example.com
```

## Impact
- Read arbitrary files from the server filesystem
- Access to sensitive configuration files like `settings.py`
- Exposure of server secrets, API keys, and internal data
- Potential pivot to more severe attacks

## Remediation
Netflix fixed the issue in E2Nest pull request #16 by using `os.path.realpath` instead of `os.path.normpath` and improving the path validation logic to prevent traversal bypasses.

## References
- https://github.com/Netflix/security-bulletins/blob/master/advisories/nflx-2024-004.md
- https://github.com/Netflix/e2nest/security/advisories/GHSA-p7rm-pq2x-crg9
