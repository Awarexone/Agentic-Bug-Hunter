# Title: XXE on DuckDuckGo

- **Platform**: HackerOne
- **Program**: DuckDuckGo
- **Severity**: High
- **Date**: 2019-01-15
- **Researcher**: Security Researcher
- **Bounty**: N/A

## Summary
An XML External Entity (XXE) injection vulnerability was discovered on DuckDuckGo's infrastructure. The vulnerability allowed an attacker to read local files and perform server-side request forgery through XML processing.

## Technical Details
A DuckDuckGo endpoint processed XML input without properly disabling external entity resolution. By injecting a DTD with external entity references, an attacker could exfiltrate file contents or probe internal network resources. The parser was configured with default settings that allowed DTD processing.

## Steps to Reproduce
1. Locate an endpoint that accepts XML input
2. Craft an XXE payload with a local file reference
3. Send the payload and observe the response for file contents
4. If blind XXE, use out-of-band techniques to exfiltrate data

## Proof of Concept
```
POST /xml-endpoint HTTP/1.1
Host: duckduckgo.com
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<search>
  <query>&xxe;</query>
</search>
```

## Impact
- Read sensitive files from DuckDuckGo's servers
- Server-Side Request Forgery (SSRF) to internal services
- Potential data exfiltration and further compromise

## Remediation
DuckDuckGo disabled DTD processing and external entity resolution in their XML parser configuration.

## References
- https://hackerone.com/reports/483774
- https://github.com/1kouki/hackerone-reports
