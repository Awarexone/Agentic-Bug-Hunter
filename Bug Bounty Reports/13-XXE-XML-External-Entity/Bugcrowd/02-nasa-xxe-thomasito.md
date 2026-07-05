# Title: Unauthenticated XXE Allowing Arbitrary File Read in NASA

- **Platform**: Bugcrowd
- **Program**: NASA - Vulnerability Disclosure Program
- **Severity**: Critical (P1)
- **Date**: 2024-10-26
- **Researcher**: thomasito (thomscoder)
- **Bounty**: N/A

## Summary
A critical unauthenticated XXE vulnerability was discovered on a NASA application. The endpoint accepted XML processing before validating authentication tokens, and returned parsing errors that leaked file contents via error-based XXE.

## Technical Details
The vulnerable endpoint required an authentication token normally, but would process XML input before validating the token. The XML parser had external entities enabled. By injecting a specially crafted DTD that triggered a parsing error containing the target file's content, the researcher achieved error-based XXE exfiltration without needing out-of-band channels.

## Steps to Reproduce
1. Identify an XML processing endpoint
2. Send a request without authentication - observe if XML is processed before auth check
3. Craft a malicious DTD that references a local file
4. Trigger a parsing error that includes the file contents in the error message
5. Read the error response to retrieve sensitive file contents

## Proof of Concept
```
POST /xml-endpoint HTTP/1.1
Host: nasa.gov
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % error "<!ENTITY &#x25; file SYSTEM 'file:///nonexistent/&xxe;'>">
  %error;
]>
<root>&file;</root>
```

## Impact
- Arbitrary file read from the server without authentication
- Access to sensitive NASA systems data and configurations
- Potential pivot to internal network scanning via SSRF

## Remediation
NASA disabled external entity processing in the XML parser and moved the authentication check before any XML processing occurs.

## References
- https://medium.com/@thomscoder/how-i-found-an-unauthenticated-xxe-that-allowed-arbitrary-file-read-in-nasa-bfffe24dc24e
