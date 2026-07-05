# Title: Hijack All Emails Sent to Any Domain That Uses Cloudflare Email Routing

- **Platform**: Cloudflare Bug Bounty
- **Program**: Cloudflare
- **Severity**: Critical (CVSS 9.8)
- **Date**: 2022-07-28
- **Researcher**: albertspedersen
- **Bounty**: $6,000

## Summary

A critical vulnerability in Cloudflare's Email Routing service allowed an attacker to hijack all emails sent to any domain using Cloudflare Email Routing. By exploiting the domain verification and routing configuration process, an attacker could redirect email destined for any Cloudflare Email customer to their own mail server.

## Technical Details

Cloudflare Email Routing allows customers to configure email forwarding for their domains. The service uses domain verification to ensure only domain owners can configure email routing rules. However, the researcher discovered a flaw in the verification and configuration process that allowed an attacker to claim email routing for a domain they did not own.

The vulnerability involved manipulation of the DNS-based domain verification flow. When a domain was added to Cloudflare Email Routing, the verification process had a race condition or improper state validation that could be exploited to bypass ownership verification. Once verified, the attacker could configure catch-all email forwarding rules to receive all emails sent to any address on the target domain.

## Steps to Reproduce

1. Identify a domain using Cloudflare Email Routing
2. Initiate the email routing setup process for the target domain
3. Manipulate the DNS verification step to bypass ownership checks
4. Once access is gained, configure a catch-all email forwarding rule
5. Set the forwarding destination to an attacker-controlled email server
6. All emails sent to any address on the target domain are now forwarded to the attacker

## Proof of Concept

The researcher demonstrated that by exploiting the gap between:
- DNS verification of domain ownership
- The actual configuration of email routing rules

An attacker could insert themselves as the routing authority for the domain and configure email forwarding without legitimate domain ownership.

## Impact

- Complete interception of all email for any Cloudflare Email Routing customer
- Access to password reset emails, account verification links, and sensitive communications
- Account takeovers across all services using the compromised email domain
- Business email compromise attacks
- Total loss of email privacy and integrity

## Remediation

Cloudflare fixed the vulnerability by strengthening the domain verification process for Email Routing, ensuring that only verified domain owners could configure email forwarding rules. The fix included additional validation checks and closing the race condition that allowed the bypass.

## References
- https://hackerone.com/reports/1419341
- https://github.com/ajaysenr/HackerOne-Disclosed-Reports/blob/main/by-program/cloudflare.md
