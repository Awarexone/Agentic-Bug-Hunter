# Title: XXE Injection in YesWeHack Dojo AI Image Generator

- **Platform**: YesWeHack
- **Program**: YesWeHack Dojo CTF Challenge #34
- **Severity**: High
- **Date**: 2024-08-05
- **Researcher**: Multiple Winners
- **Bounty**: CTF Challenge

## Summary
An XXE injection vulnerability was discovered in an AI Image Generator application. The application accepted user-supplied XML data and processed it with an insecure XML parser configuration, allowing attackers to read local files from the server.

## Technical Details
The web application rendered user-supplied XML data through a templated HTML interface. It used Python's `lxml` library to parse XML files, with DTD loading and entity resolution enabled. An attacker could submit a base64-encoded XML payload containing external entity declarations to read files on the server.

## Steps to Reproduce
1. Identify the XML input functionality in the application
2. Submit a classic XXE payload as base64-encoded XML
3. Observe file contents reflected in the application response
4. Escalate to read sensitive files like the flag

## Proof of Concept
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

The payload was base64 encoded and submitted to the AI image generator prompt. The server returned the file contents as part of the generated output.

## Impact
- Arbitrary file read from the server filesystem
- Access to application source code, configuration, and secrets
- Potential Server-Side Request Forgery (SSRF)

## Remediation
The remediation involves setting `load_dtd=False` and `resolve_entities=False` in the `lxml.etree.XMLParser` configuration to prevent DTD loading and entity expansion.

## References
- https://www.yeswehack.com/dojo/dojo-ctf-challenge-winners-34
