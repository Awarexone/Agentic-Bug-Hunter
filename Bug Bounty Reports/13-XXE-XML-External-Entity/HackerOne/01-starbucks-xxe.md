# Title: XXE at ecjobs.starbucks.com.cn

- **Platform**: HackerOne
- **Program**: Starbucks
- **Severity**: High
- **Date**: 2019-01-15
- **Researcher**: Security Researcher
- **Bounty**: N/A

## Summary
An XML External Entity (XXE) injection vulnerability was discovered on a Starbucks subdomain in China (ecjobs.starbucks.com.cn). The application processed XML input without disabling external entity resolution, allowing file disclosure and SSRF.

## Technical Details
The vulnerable endpoint at `/retail/hxpublic_v6/hxdynamicpage6.aspx` accepted XML input that was processed by an ASP.NET XML parser with DTD processing enabled. By injecting an external entity definition, an attacker could read local files from the server or perform server-side request forgery.

## Steps to Reproduce
1. Identify an endpoint that accepts XML input
2. Test with a basic XXE payload referencing a local file
3. If the file content is returned in the response, XXE is confirmed
4. Escalate by reading sensitive files or performing SSRF

## Proof of Concept
```
POST /retail/hxpublic_v6/hxdynamicpage6.aspx HTTP/1.1
Host: ecjobs.starbucks.com.cn
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

## Impact
- Read sensitive files from the server including configuration files
- Server-Side Request Forgery (SSRF) to internal networks
- Potential denial of service via entity expansion
- Information disclosure leading to further compromise

## Remediation
Starbucks fixed the XXE by disabling DTD processing and external entity resolution in the XML parser configuration. They also implemented input validation for XML content.

## References
- https://hackerone.com/reports/500515
- https://github.com/codebygk/hackerone-bug-bounty-reports
