# Title: Path Traversal Vulnerability via File Uploads in Netflix Genie

- **Platform**: HackerOne
- **Program**: Netflix Bug Bounty
- **Severity**: Critical (CVSS 9.9)
- **Date**: 2024-05-09
- **Researcher**: Joseph Beeton / jmoritzc53
- **Bounty**: $250 (duplicate of earlier finding)

## Summary
A path traversal vulnerability was discovered in Netflix's open-source Genie application (CVE-2024-4701). The file upload functionality accepted user-supplied filenames without proper sanitization, allowing attackers to write files to arbitrary locations on the filesystem.

## Technical Details
Genie's API accepts multipart/form-data file uploads. The application used the user-supplied filename directly when writing the file to disk without validating or sanitizing it. By manipulating the filename to contain path traversal sequences (`../`), an attacker could break out of the intended attachment storage directory and write files to any location the Java process had write access to.

## Steps to Reproduce
1. Identify a file upload endpoint in a Genie instance (versions < 4.3.18)
2. Intercept the upload request in a proxy
3. Modify the filename parameter to include path traversal sequences
4. Upload the file and verify it was written to the target location

## Proof of Concept
```
POST /api/v1/jobs/123/attachments HTTP/1.1
Host: genie-instance.example.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="../../../../tmp/evil.txt"
Content-Type: text/plain

malicious content
------WebKitFormBoundary--

# The file was written to /tmp/evil.txt
# This could be escalated to RCE by overwriting cron jobs, SSH keys, etc.
```

## Impact
- Arbitrary file write to any location the Java process can access
- Potential remote code execution by overwriting application files, cron jobs, or SSH keys
- Data corruption and system compromise

## Remediation
Netflix fixed the issue in Genie OSS v4.3.18 by sanitizing user-supplied filenames and preventing path traversal sequences. They also recommended using S3 storage instead of local filesystem for file attachments.

## References
- https://github.com/Netflix/genie/security/advisories/GHSA-wpcv-5jgp-69f3
- https://www.contrastsecurity.com/security-influencers/contrast-security-discovers-netflix-oss-genie-application-path-traversal-vulnerability-that-can-lead-to-rce-during-file-upload
