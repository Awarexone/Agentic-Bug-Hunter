# Title: Vulnerabilities chain leading to privilege escalation

- **Platform**: HackerOne
- **Program**: Nord Security
- **Severity**: Medium
- **Date**: January 3, 2020
- **Researcher**: r3ggi-on-h1
- **Bounty**: Hidden

## Summary
A chain of 5 vulnerabilities in NordVPN's macOS application allowed an attacker to escalate privileges to root by exploiting XPC connection issues, TOCTOU race conditions, and symlink attacks.

## Technical Details
The researcher discovered a chain of vulnerabilities in NordVPN's macOS privileged helper tool:
1. The XPC service connection could be established without proper validation
2. The privileged helper accepted messages to open binaries from user-controlled locations
3. A symlink was used by the helper to resolve file paths
4. A TOCTOU (Time-of-Check-Time-of-Use) race condition existed in the file resolution
5. By constantly swapping between a legitimate NordVPN binary and a malicious file via symlink, the attacker could win the race condition

When successfully exploited, the malicious file would execute with root permissions.

## Steps to Reproduce
1. Establish a valid XPC connection with the NordVPN privileged helper
2. Send a message to open a binary located in a controlled location
3. Create a symlink that alternates between the legitimate NordVPN binary and a malicious payload
4. Exploit the TOCTOU race condition by rapidly swapping the symlink target
5. The privileged helper resolves the symlink to the malicious payload at the wrong moment
6. The malicious file executes with root privileges

## Proof of Concept
```bash
# Set up the race condition
while true; do
    ln -sf /Applications/NordVPN.app/Contents/MacOS/NordVPN /tmp/target
    ln -sf /tmp/malicious.sh /tmp/target
done &

# Trigger the vulnerable code path
# (XPC message to open binary at /tmp/target)
```

## Impact
Local privilege escalation from a standard user account to root on macOS systems running NordVPN. This could allow an attacker to install malware, access all system files, and completely compromise the system.

## Remediation
Nord Security fixed the issue by:
1. Properly validating XPC connections
2. Removing the vulnerable symlink resolution logic
3. Implementing proper file ownership checks before execution
4. Fixing the race condition with atomic file operations

## References
- https://hackerone.com/reports/767647
