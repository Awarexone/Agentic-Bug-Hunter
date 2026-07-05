# Title: SSTI in Bug Bounty Program: Playing with Handlebars

- **Platform**: Intigriti
- **Program**: Private Program
- **Severity**: High
- **Date**: September 5, 2024
- **Researcher**: Ali Zamini
- **Bounty**: N/A

## Summary
A Handlebars Server-Side Template Injection vulnerability was discovered in a bug bounty program. The application uses Handlebars as its Node.js template engine, and user-controlled input was directly concatenated into templates, allowing for template injection and potential RCE.

## Technical Details
Handlebars is a logic-less templating engine for Node.js. When user input is embedded directly into a template string rather than passed as data, an attacker can inject Handlebars expressions. The vulnerability was identified by sending `{{7*7}}` in a parameter and receiving `49` in the response. Further exploration revealed access to the JavaScript runtime environment.

## Steps to Reproduce
1. Identify input fields that are reflected in server-rendered templates (e.g., name, email, search queries)
2. Inject `{{7*7}}` and observe if it renders as `49` in the response
3. Progress to accessing the environment: `{{this}}` returns `[object Object]`
4. Chain to prototype: `{{this.__proto__}}`
5. Access `require`: `{{this.constructor.constructor('return process')().mainModule.require}}`

## Proof of Concept
```
Test injection: {{7*7}} → 49
Object leak: {{this}} → [object Object]
Constructor access: {{this.constructor.constructor('return this.process.env')()}}
```

## Impact
Remote Code Execution via Node.js. An attacker could execute arbitrary JavaScript on the server, access environment variables, read/write files, and compromise the entire application infrastructure.

## Remediation
Use Handlebars' built-in expression handling: pass user data as context variables (`{ name: userInput }`) instead of concatenating into template strings. Use strict template compilation and consider using Handlebars' partial blocking features.

## References
- https://medium.com/@ali.zamini/ssti-in-bug-bounty-program-the-time-i-played-with-handlebars-and-broke-stuff-7dc1f9834a3d
- https://handlebarsjs.com/guide/expressions.html
