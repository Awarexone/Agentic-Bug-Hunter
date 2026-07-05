# Title: Server-Side Template Injection (SSTI) via Flask Jinja2 Leading to RCE on uber.com

- **Platform**: Uber Bug Bounty
- **Program**: Uber
- **Severity**: Critical
- **Date**: 2016-03-25
- **Researcher**: Orange Tsai (orange)
- **Bounty**: $10,000

## Summary

One of the earliest and most impactful Uber bug bounty reports: a Server-Side Template Injection (SSTI) vulnerability in the Flask/Jinja2 templating engine on uber.com allowed full Remote Code Execution. Orange Tsai discovered that user-supplied input was rendered unsafely by Jinja2 templates, enabling Python code injection on the server.

## Technical Details

The vulnerability was found on `uber.com` which used the Flask web framework with Jinja2 templating. A particular endpoint reflected user input directly into a Jinja2 template without proper sanitization. Jinja2, by default, allows execution of arbitrary Python code when user input is rendered with `render_template_string()` instead of `render_template()` using untrusted data.

The vulnerable endpoint passed user-controlled input to a template rendering function that used `render_template_string()`, which evaluates Jinja2 expressions in the input. An attacker could inject Jinja2 syntax like `{{ config }}` or `{{ ''.__class__.__mro__[2].__subclasses__() }}` to execute arbitrary Python code on the server.

## Steps to Reproduce

1. Identify the vulnerable endpoint on uber.com that reflects user input
2. Inject a Jinja2 test payload to confirm SSTI:
   ```
   {{ 7*7 }}
   ```
3. If the response contains "49", SSTI is confirmed
4. Escalate to RCE using Python's built-in classes:
   ```
   {{ ''.__class__.__mro__[1].__subclasses__() }}
   ```
5. Execute system commands via subprocess module

## Proof of Concept

Simple detection payload:
```
{{ config.__class__.__init__.__globals__["os"].popen("id").read() }}
```

This would execute the `id` command on the server and return the output in the HTTP response.

## Impact

- Full Remote Code Execution on uber.com servers
- Access to internal Uber infrastructure and databases
- Ability to read, modify, or delete any data accessible to the web server
- Potential lateral movement within Uber's internal network
- Exposure of source code, API keys, and database credentials

## Remediation

Uber fixed the issue within 2 days of the report. The fix involved:
- Switching from `render_template_string()` to `render_template()` for user-controlled input
- Proper input sanitization and output encoding
- Removing the vulnerable endpoint pattern

Orange Tsai also published a detailed blog post about the finding, which was one of the first public SSTI-to-RCE writeups.

## References
- https://hackerone.com/reports/125980
- http://blog.orange.tw/2016/03/bug-bounty-ubercom-ubercom-remote-code.html
