# Title: H1514 Server Side Template Injection in Return Magic Email Templates

- **Platform**: HackerOne
- **Program**: Shopify
- **Severity**: Critical
- **Date**: October 13, 2018
- **Researcher**: zombiehelp54
- **Bounty**: Hidden

## Summary
A server-side template injection vulnerability was discovered in Shopify's Return Magic app email templates. The application uses Handlebars (Node.js) for email template rendering, and user-supplied template content is evaluated server-side, potentially allowing RCE.

## Technical Details
The Return Magic app allows merchants to customize email workflow templates. When editing email templates in the code editor, Handlebars expressions like `{{this}}` are evaluated server-side when test emails are sent. The researcher confirmed that the backend is Node.js by accessing the prototype chain via `{{this.__proto__}}`.

## Steps to Reproduce
1. Install Return Magic app on a Shopify store
2. Navigate to Settings > Emails > Workflow
3. Edit any email template and click the code icon
4. Enter `{{this}}` in the template editor
5. Click "Send me a test email"
6. Check your inbox - the email shows `[Object Object]`
7. Further probing with `{{this.__proto__.constructor.name}}` returns `Object`

## Proof of Concept
```
Template input: {{this}}
Rendered output: [Object Object]

Template input: {{this.__proto__}}
Rendered output: [Object Object]

Template input: {{this.__proto__.constructor.name}}
Rendered output: Object
```

## Impact
Node.js Handlebars template injection can lead to Remote Code Execution via access to the `process` object and `require` function, allowing full server compromise and access to Shopify's internal infrastructure.

## Remediation
Restrict template syntax and use sandboxed rendering environments. Disable dangerous Handlebars features and implement a strict allowlist of template helpers.

## References
- https://hackerone.com/reports/423541
- https://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html
