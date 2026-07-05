# Title: Server Side Template Injection on Name Parameter during Sign Up Process

- **Platform**: HackerOne
- **Program**: Glovo
- **Severity**: High
- **Date**: February 16, 2021
- **Researcher**: battle_angel
- **Bounty**: N/A

## Summary
Server-side template injection was found on the Name parameter during the sign-up process on Glovo. When an attacker signs up and uses a payload in the First Name field, the payload is rendered server-side and executed in promotional/welcome emails sent to the user.

## Technical Details
The application uses a template engine to render user-provided data in email templates. The First Name field during registration is directly concatenated into the email template without proper sanitization, allowing SSTI payloads to be evaluated server-side. The payload `{{7*7}}` was rendered as `49` in the welcome email, confirming the vulnerability.

## Steps to Reproduce
1. Navigate to Glovoapp and click on Register
2. In the First Name field, enter the value `{{7*7}}`
3. Complete the registration process
4. Check the welcome/promotional email received
5. Observe that `{{7*7}}` was evaluated to `49`

## Proof of Concept
```
Registration Form:
First Name: {{7*7}}
Last Name: Test
Email: attacker@example.com

Email Received:
"Welcome {{7*7}} to Glovo!" rendered as "Welcome 49 to Glovo!"
```

## Impact
Server-side template injection can be escalated to Remote Code Execution (RCE) depending on the template engine used. This could lead to full server compromise, data exfiltration, and pivot attacks against internal infrastructure.

## Remediation
User input should be passed to templates as data, not concatenated into template strings. Use proper escaping and sandboxed template environments.

## References
- https://hackerone.com/reports/1104349
