# Title: XML External Entity (XXE) Injection in HackDonalds Application

- **Platform**: Intigriti
- **Program**: Intigriti CTF Challenge (HackDonalds)
- **Severity**: High
- **Date**: 2025-04-13
- **Researcher**: Gurudatt Choudhary / Multiple Researchers
- **Bounty**: CTF Challenge

## Summary
An XXE vulnerability was found in a Next.js application's XML processing endpoint. Chained with a Next.js middleware authentication bypass (CVE-2025-29927), an attacker could read arbitrary files from the server without authentication.

## Technical Details
The application used Next.js 13.2 and had a middleware authentication bypass via the `X-Middleware-Subrequest: middleware` header. After bypassing authentication, the admin panel revealed an ice cream machine management feature that accepted XML input. The XML parser had DTD processing enabled, allowing XXE injection.

The endpoint `/api/parse-xml.json` accepted XML wrapped in JSON and processed it with an insecure parser configuration, allowing external entity resolution and file disclosure.

## Steps to Reproduce
1. Bypass middleware authentication using the `X-Middleware-Subrequest: middleware` header
2. Navigate to the admin panel and find the XML processing feature
3. Craft an XXE payload to read local files
4. Submit the payload and observe file contents in the response

## Proof of Concept
```
POST /api/parse-xml.json HTTP/1.1
Host: hackdonalds.intigriti.io
X-Middleware-Subrequest: middleware
Content-Type: application/json

{
  "xml": "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE machine [  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><machine><id>1</id><name>&xxe;</name></machine>"
}
```

## Impact
- Arbitrary file read from the server
- Access to application source code and configuration
- Potential exposure of secrets and API keys
- Chaining with other vulnerabilities for RCE

## Remediation
The CTF challenge was fixed by disabling DTD processing and external entity resolution in the XML parser. The middleware authentication bypass was addressed in later Next.js versions.

## References
- https://gurudattchoudhary.medium.com/intigriti-hackdonalds-ctf-writeup-chaining-next-js-fa0d8f6acbef
- https://github.com/MaMi364/Hackdonalds-Intigriti
