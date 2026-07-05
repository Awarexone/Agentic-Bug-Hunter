# Title: $25,000 SSRF in HackerOne's Analytics Reports — AWS Metadata Exposure

- **Platform**: HackerOne
- **Program**: HackerOne Bug Bounty Program
- **Severity**: Critical (CVSS 10.0)
- **Date**: 2023-11-23
- **Researcher**: @mega7
- **Bounty**: $25,000

## Summary
A critical server-side request forgery vulnerability was discovered in HackerOne's PDF generation feature for analytics reports. By injecting an `<iframe>` tag with a URL to the AWS metadata endpoint, the researcher triggered an SSRF that exposed temporary AWS credentials, leading to potential full infrastructure compromise.

## Technical Details
HackerOne's analytics reports feature generated PDFs server-side by rendering HTML templates. The backend Ruby code looped through report elements and rendered them into a PDF. One code path reflected an error message containing the template name, which could be user-controlled.

The vulnerable code:
```ruby
"Missing template for element: #{element[:template]}"
```

This error message was passed to the PDF rendering engine without sanitization. If the `template` key contained HTML, it would be rendered in the PDF. The PDF renderer then made requests for resources referenced in the HTML.

The researcher injected:
```html
<iframe src="http://169.254.169.254/latest/meta-data/"></iframe>
```

When the PDF renderer processed this HTML, it made a server-side request to the AWS metadata service, returning instance metadata including IAM role credentials.

## Steps to Reproduce
1. Navigate to HackerOne's analytics reports
2. Create a report with a malicious element template name
3. The template name should contain: `<iframe src="http://169.254.169.254/latest/meta-data/">`
4. Trigger PDF generation
5. The response contains AWS metadata, including temporary credentials
6. Extract credentials from the PDF output

## Proof of Concept
The injected HTML template element:
```json
{
  "template": "<iframe src='http://169.254.169.254/latest/meta-data/iam/security-credentials/hackerone-role'></iframe>"
}
```

The PDF would render with the content of the AWS metadata response visible, including:
```json
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "..."
}
```

## Impact
- Exposure of AWS temporary credentials (AccessKeyId, SecretAccessKey, Token)
- Full AWS resource manipulation
- Access to S3 buckets, EC2 instances, RDS databases
- Potential remote code execution via AWS SSM
- User and admin account takeover via chained attacks
- Complete pivot into HackerOne's infrastructure

## Remediation
HackerOne fixed the issue in under 24 hours:
1. Removed reflection of the template value in error messages
2. Changed from:
   ```ruby
   "Missing template for element: #{element[:template]}"
   ```
   To:
   ```ruby
   "Missing template for element"
   ```
3. Added regression tests to prevent reoccurrence
4. Implemented additional input sanitization for the PDF generation flow

## References
- https://osintteam.blog/25-000-ssrf-in-hackerones-analytics-reports-b9a5b3aa3d6e
