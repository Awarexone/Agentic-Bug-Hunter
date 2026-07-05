# Title: Takeover of hackerone.engineering via Medium

- **Platform**: Medium
- **Program**: HackerOne
- **Severity**: High
- **Date**: 2024-11-14
- **Researcher**: raditz
- **Bounty**: N/A

## Summary
The subdomain hackerone.engineering was configured to point to a Medium publication that had been deleted or was no longer managed by HackerOne. This allowed an attacker to claim the Medium publication and take over the subdomain.

## Technical Details
HackerOne's engineering blog was hosted on Medium via a custom domain configuration. When the Medium publication was removed or the custom domain was disassociated, the DNS CNAME record remained pointing to Medium's servers. An attacker could create a new Medium publication and configure it to use the custom domain, effectively taking over the subdomain.

## Steps to Reproduce
1. Identify custom domains pointing to third-party blogging platforms
2. Check if the third-party account still exists and is configured for the custom domain
3. If the account is deleted or the domain is unlinked, register a new account
4. Configure the custom domain in the new account
5. Verify control by publishing content on the claimed subdomain

## Proof of Concept
```
$ dig hackerone.engineering
hackerone.engineering. 3600 IN CNAME medium.com

# Medium publication was deleted/unlinked
# Created a new Medium publication and added hackerone.engineering as custom domain
# DNS propagated and the subdomain served attacker-controlled content
```

## Impact
- Publishing malicious content under a HackerOne subdomain
- Phishing attacks targeting security researchers
- Brand impersonation and reputational damage
- Potential cookie theft from visitors

## Remediation
HackerOne removed the dangling DNS record and updated their processes to ensure custom domains are properly cleaned up when decommissioning third-party services.

## References
- https://hackerone.com/reports/2709660
- https://www.redpacketsecurity.com/hackerone-bugbounty-disclosure-takeover-of-hackerone-engineering-via-medium-raditz/
