# Title: Unauthenticated Command Injection in Kemp LoadMaster (CVE-2024-7591)

- **Platform**: HackerOne
- **Program**: Progress Kemp
- **Severity**: Critical (CVSS 9.8)
- **Date**: 2024-07-29
- **Researcher**: Marius Walter (Insinuator)
- **Bounty**: N/A

## Summary
A critical unauthenticated command injection vulnerability was discovered in Kemp LoadMaster load balancer. The vulnerability existed in the login functionality where user-supplied input was passed to an `eval` statement without sanitization, allowing remote code execution as the `bal` user.

## Technical Details
The login endpoint at `/progs/status/login` accepts POST parameters `token`, `token2`, `user`, and `pass`. These values are passed to a function called `pass_read` and then used inside an `eval` statement without any sanitization. By escaping the context of the eval, an attacker can execute arbitrary shell commands.

All LoadMaster versions up to 7.2.60.0 and multi-tenant hypervisors up to 7.1.35.11 were affected. No authentication was required - the vulnerability was exploitable by anyone with network access to the Web User Interface.

## Steps to Reproduce
1. Identify a Kemp LoadMaster device with the WUI exposed
2. Send a crafted POST request to `/progs/status/login`
3. Inject command payload in one of the vulnerable parameters
4. Commands execute as the `bal` user

## Proof of Concept
```
POST /progs/status/login HTTP/1.1
Host: loadmaster.example.com
Content-Type: application/x-www-form-urlencoded

token=;id&user=admin&pass=admin
```

The `id` command executes on the server as the `bal` user, demonstrating unauthenticated remote code execution.

## Impact
- Unauthenticated remote code execution
- Full compromise of the load balancer device
- Potential lateral movement within the network
- Traffic interception and manipulation

## Remediation
Kemp released patched versions that replaced the `eval` statement with a `read` command, which does not execute supplied input. All users were advised to update to the latest version immediately.

## References
- https://insinuator.net/2024/11/vulnerability-disclosure-command-injection-in-kemp-loadmaster-load-balancer-cve-2024-7591/
