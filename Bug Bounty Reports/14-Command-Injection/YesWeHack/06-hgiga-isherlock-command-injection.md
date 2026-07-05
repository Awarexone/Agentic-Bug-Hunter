# Title: OS Command Injection in HGiga iSherlock (CVE-2025-3361)

- **Platform**: YesWeHack
- **Program**: HGiga
- **Severity**: Critical (CVSS 9.8)
- **Date**: 2025-04-08
- **Researcher**: Security Researcher
- **Bounty**: N/A

## Summary
An OS command injection vulnerability was discovered in HGiga iSherlock (including MailSherlock, SpamSherlock, and AuditSherlock). The web service failed to filter special characters in certain function parameters, allowing unauthenticated remote attackers to inject and execute arbitrary OS commands.

## Technical Details
The system configuration interface of HGiga iSherlock processes user-supplied input in function parameters without proper sanitization. The vulnerable parameters are passed directly to OS command execution functions. An unauthenticated attacker can send crafted requests to execute arbitrary commands on the server.

Both iSherlock 4.5 and 5.5 versions were affected. The vulnerability was particularly critical because no authentication was required to exploit it.

## Steps to Reproduce
1. Identify an HGiga iSherlock instance with the web service exposed
2. Locate vulnerable parameters in the system configuration interface
3. Inject shell metacharacters (;, |, `, $()) followed by commands
4. Observe command execution on the server

## Proof of Concept
```
POST /vulnerable-endpoint HTTP/1.1
Host: isherlock.example.com
Content-Type: application/x-www-form-urlencoded

parameter=value;whoami
```

The `whoami` command executes on the server, revealing the application user context.

## Impact
- Unauthenticated remote code execution
- Full server compromise
- Access to email and audit data stored by iSherlock
- Potential lateral movement within the network

## Remediation
HGiga released patched versions (iSherlock-user-4.5 to version 236 and iSherlock-user-5.5 to version 236) with proper input validation and sanitization of special characters.

## References
- https://nvd.nist.gov/vuln/detail/CVE-2025-3361
- https://www.twcert.org.tw/tw/cp-132-7771-36c50-1.html
