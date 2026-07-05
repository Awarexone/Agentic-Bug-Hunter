# Title: Authenticated RCE in binance-trading-bot via Command Injection

- **Platform**: GitHub Bug Bounty
- **Program**: GitHub Security Lab (PVR)
- **Severity**: High (CVSS 7.2)
- **Date**: 2025-02-14
- **Researcher**: Kwstubbs (Kevin Stubbings)
- **Bounty**: N/A

## Summary
A command injection vulnerability was discovered in the binance-trading-bot open source project (CVE-2025-27106). The `/restore` endpoint passed the name of an uploaded file to `shell.exec()` without sanitization other than path normalization, allowing authenticated users to achieve remote code execution.

## Technical Details
The `/restore` endpoint accepts a file upload for restoring backups. The filename of the uploaded archive is passed directly to `shell.exec()` via string concatenation. While basic path normalization was applied, shell metacharacters in the filename were not filtered. By crafting a filename containing command injection payloads (e.g., `; touch /tmp/test`), an attacker can execute arbitrary commands on the server.

## Steps to Reproduce
1. Authenticate to the binance-trading-bot instance
2. Send a POST request to the `/restore` endpoint
3. Include a filename with command injection payload
4. Observe command execution on the server

## Proof of Concept
```
POST /restore HTTP/1.1
Host: trading-bot.example.com
Authorization: Bearer <valid-token>
Content-Type: multipart/form-data

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="; touch /tmp/pwned;"
Content-Type: application/octet-stream

[archive content]

------WebKitFormBoundary--
```

The command `touch /tmp/pwned` executes on the server within the application's user context.

## Impact
- Remote code execution as the application user
- Access to trading bot credentials and API keys
- Potential cryptocurrency theft
- Server compromise and lateral movement

## Remediation
The fix replaced `shell.exec()` with `execFile()` which treats arguments as literal strings rather than shell commands, preventing command injection.

## References
- https://securitylab.github.com/advisories/GHSL-2025-023_binance-trading-bot/
- CVE-2025-27106
