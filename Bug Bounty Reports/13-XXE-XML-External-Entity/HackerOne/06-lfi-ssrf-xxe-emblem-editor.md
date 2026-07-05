# Title: LFI and SSRF via XXE in Emblem Editor

- **Platform**: HackerOne
- **Program**: HackerOne
- **Severity**: High
- **Date**: 2018-01-15
- **Researcher**: Security Researcher
- **Bounty**: $1,500

## Summary
An XXE vulnerability in HackerOne's emblem editor functionality allowed Local File Inclusion (LFI) and Server-Side Request Forgery (SSRF). The application processed XML-based SVG files without disabling external entity resolution.

## Technical Details
HackerOne's emblem editor allowed users to upload SVG images. SVG is an XML-based format, and the application parsed uploaded SVG files without disabling DTD processing or external entity resolution. By crafting a malicious SVG with XXE payloads, an attacker could read local files or make requests to internal services.

## Steps to Reproduce
1. Create an SVG file with an embedded XXE payload
2. Upload the SVG through the emblem editor
3. When the server processes the SVG, the external entity is resolved
4. File contents are displayed in the error message or rendered output

## Proof of Concept
```svg
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
  <text x="10" y="50" font-size="16">&xxe;</text>
</svg>
```

## Impact
- Local File Inclusion - reading server files
- Server-Side Request Forgery - probing internal services
- Potential exfiltration of sensitive data
- Chaining to more severe attacks

## Remediation
HackerOne disabled DTD processing and external entity resolution in their SVG parser. They also implemented content security checks on uploaded files.

## References
- https://hackerone.com/reports/347139
- https://github.com/codebygk/hackerone-bug-bounty-reports
