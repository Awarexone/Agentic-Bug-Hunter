# Title: SSRF in Shopify Exchange to RCE via Kubernetes Service Account Token

- **Platform**: HackerOne
- **Program**: Shopify Bug Bounty Program
- **Severity**: Critical (10.0 CVSS)
- **Date**: 2018-04-23
- **Researcher**: André Baptista (0xacb)
- **Bounty**: $25,000

## Summary
A server-side request forgery (SSRF) vulnerability in Shopify's Exchange application was exploited to retrieve a Google Kubernetes Engine (GKE) service account token from the instance metadata service. This could have led to full cluster compromise. Shopify's infrastructure isolation and least-privilege configurations prevented complete takeover.

## Technical Details
The Exchange application had a screenshot/rendering service that followed user-supplied URLs. The researcher discovered that this service could be used to make requests to internal resources, including the GKE metadata endpoint at `http://169.254.169.254/`.

By requesting the metadata service, the researcher successfully retrieved the GKE service account token for the node. This token could have been used to interact with the Kubernetes API server. However, due to Shopify's security controls (including RBAC and minimal service account privileges), the token's usefulness was limited.

The attack chain was:
1. Identify the screenshot service that accepts URLs
2. Exploit SSRF to access GKE metadata: `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token`
3. Extract the OAuth2 access token
4. Use the token to authenticate to GKE API

## Steps to Reproduce
1. Identify the Exchange screenshot functionality
2. Submit a URL pointing to GKE metadata endpoint
3. Capture the OAuth2 token from the response
4. Authenticate to the Kubernetes API with the token
5. Attempt to enumerate cluster resources

## Proof of Concept
The researcher submitted:
```
POST /exchange/screenshot HTTP/1.1
Host: exchange.shopify.com
url=http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
Header: Metadata-Flavor: Google
```

The response contained the GKE service account access token.

## Impact
- Retrieval of GKE service account credentials
- Potential Kubernetes API access
- Cluster-wide compromise if privileges were sufficient
- Access to other nodes and containers in the cluster
- Shopify declared an incident and rotated credentials within hours

## Remediation
Shopify took multiple actions:
1. Disabled the vulnerable screenshot service
2. Rotated all credentials
3. Implemented metadata proxy to prevent SSRF to cloud metadata
4. Enabled `disable-legacy-endpoints` on GKE clusters
5. Reviewed and minimized RBAC permissions
6. Implemented least-privilege service accounts

## References
- https://hackerone.com/reports/341876
- https://0xacb.com/2018/05/23/shopify-ssrf-to-rce/
