# Title: SSRF in Webhooks Leading to AWS Private Keys Exposure

- **Platform**: HackerOne
- **Program**: Omise
- **Severity**: Critical
- **Date**: 2019-05-22
- **Researcher**: Redacted
- **Bounty**: Undisclosed

## Summary
A server-side request forgery vulnerability was discovered in Omise's webhook implementation. The webhook functionality allowed attackers to make requests to internal AWS services, including the EC2 metadata service, potentially exposing AWS private keys and other sensitive infrastructure information.

## Technical Details
Omise, a payment processing company, used Amazon Web Services (AWS) as their cloud provider. The webhook feature allowed users to configure URLs that would receive event notifications. However, the application did not properly validate or restrict the URLs that could be used for webhooks.

The webhook endpoint would fetch the configured URL on the server side, making it possible to request internal AWS metadata endpoints. The critical endpoint `http://169.254.169.254/latest/meta-data/` exposes instance metadata including IAM role credentials.

By configuring a webhook to point to the AWS metadata service, an attacker could:
1. Request the IAM role name
2. Request the temporary security credentials (AccessKeyId, SecretAccessKey, Token)
3. Use these credentials to access AWS resources

## Steps to Reproduce
1. Log into the Omise dashboard
2. Navigate to webhook settings
3. Create a new webhook with the URL: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
4. Trigger the webhook
5. Inspect the webhook delivery logs for the metadata response
6. Extract IAM role credentials

## Proof of Concept
Webhook configuration:
```
URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

The response would include AWS temporary credentials:
```json
{
  "Code": "Success",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "..."
}
```

## Impact
- Exposure of AWS IAM credentials
- Unauthorized access to AWS resources (S3, EC2, RDS, etc.)
- Access to payment processing infrastructure
- Customer data exposure
- Full cloud account compromise
- Potential for further lateral movement

## Remediation
Omise fixed the vulnerability by:
1. Implementing URL validation/restriction for webhooks
2. Blocking access to private IP ranges (169.254.0.0/16, 10.0.0.0/8, etc.)
3. Adding IP address filtering on the webhook processing layer
4. Implementing IMDSv2 (Instance Metadata Service v2) with session tokens

## References
- https://hackerone.com/reports/508459
