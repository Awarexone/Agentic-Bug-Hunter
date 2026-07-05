# Title: OS Command Injection in Palo Alto Networks Expedition (CVE-2024-9463)

- **Platform**: HackerOne
- **Program**: Palo Alto Networks Bug Bounty
- **Severity**: Critical (CVSS 9.8)
- **Date**: 2024-10-09
- **Researcher**: Security Researcher
- **Bounty**: N/A

## Summary
An OS command injection vulnerability in Palo Alto Networks Expedition allowed an unauthenticated attacker to run arbitrary OS commands as root. The vulnerability resulted in the disclosure of usernames, cleartext passwords, device configurations, and device API keys for PAN-OS firewalls.

## Technical Details
The Expedition migration tool processes user-supplied input without proper sanitization before passing it to OS commands. Multiple parameters across various endpoints were found to be vulnerable to command injection. Since Expedition runs as root, injected commands execute with full system privileges.

Expedition versions 1.2.0 through 1.2.96 were affected. The tool is used to migrate firewall configurations, making it a high-value target containing credentials for PAN-OS firewalls.

## Steps to Reproduce
1. Identify a Palo Alto Networks Expedition instance
2. Find an endpoint that passes user input to system commands
3. Craft a request with command injection payloads
4. Execute arbitrary commands as root on the server

## Proof of Concept
```
POST /vulnerable-endpoint HTTP/1.1
Host: expedition.example.com
Content-Type: application/x-www-form-urlencoded

param=value;id
```

The `id` command executes as root, demonstrating full system compromise.

## Impact
- Disclosure of firewall usernames and cleartext passwords
- Extraction of device configurations and API keys
- Full root-level compromise of the Expedition server
- Access to all managed PAN-OS firewalls

## Remediation
Palo Alto Networks released Expedition 1.2.100 with proper input validation and sanitization. The fix ensures user-supplied input cannot be interpreted as system commands.

## References
- https://nvd.nist.gov/vuln/detail/CVE-2024-9463
- https://security.paloaltonetworks.com/PAN-SA-2024-0010
