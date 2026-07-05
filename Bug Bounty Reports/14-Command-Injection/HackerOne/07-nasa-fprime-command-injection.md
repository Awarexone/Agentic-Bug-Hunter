# Title: Command Injection in NASA Fprime Command Dispatcher Service

- **Platform**: HackerOne
- **Program**: NASA - Vulnerability Disclosure Program
- **Severity**: High
- **Date**: 2024-11-04
- **Researcher**: Security Researcher
- **Bounty**: N/A

## Summary
A command injection vulnerability was discovered in NASA Fprime v3.4.3 (CVE-2024-55030). The Command Dispatcher Service failed to properly neutralize special elements used in commands, allowing attackers to execute arbitrary commands.

## Technical Details
Fprime is NASA's open-source flight software framework used in space missions. The Command Dispatcher Service processes commands destined for flight hardware. Due to improper input validation, an attacker could inject additional commands by including shell metacharacters in command parameters. Since the service runs with elevated privileges for hardware access, exploitation could lead to mission-critical impacts.

The vulnerability was classified under CWE-77 (Improper Neutralization of Special Elements used in a Command).

## Steps to Reproduce
1. Gain access to the Fprime command interface
2. Send a crafted command with injected shell metacharacters
3. Observe arbitrary command execution on the flight software system
4. Confirm impact by executing benign test commands

## Proof of Concept
```
# Send a crafted command sequence to the Command Dispatcher Service
cmd_name=thruster_enable;cmd_arg=1;$(cat /etc/passwd > /tmp/leak)
```

## Impact
- Arbitrary command execution on flight software systems
- Potential compromise of spacecraft/satellite control systems
- Data exfiltration from mission-critical systems
- Denial of service or physical damage to hardware

## Remediation
NASA Fprime team implemented proper input validation and command sanitization. The fix ensures command parameters are treated as data, not executable code, by escaping shell metacharacters and using safe execution methods.

## References
- https://nvd.nist.gov/vuln/detail/CVE-2024-55030
- https://visionspace.com/remote-code-execution-and-critical-vulnerabilities-in-nasa-fprime-v3-4-3/
