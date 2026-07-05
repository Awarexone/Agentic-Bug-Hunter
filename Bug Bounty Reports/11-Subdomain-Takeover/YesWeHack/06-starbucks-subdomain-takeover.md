# Title: Subdomain takeover of mydailydev.starbucks.com

- **Platform**: YesWeHack
- **Program**: Starbucks
- **Severity**: High
- **Date**: 2024-01-15
- **Researcher**: Security Researcher
- **Bounty**: N/A

## Summary
The subdomain mydailydev.starbucks.com was discovered to be vulnerable to takeover. The subdomain's DNS record pointed to an unclaimed resource on a cloud platform, allowing an attacker to gain control of the subdomain.

## Technical Details
During subdomain enumeration, mydailydev.starbucks.com was found with a CNAME record pointing to a third-party service. The target resource had been deleted or expired, making it available for registration. By registering the resource on the same platform, an attacker could claim the subdomain and host arbitrary content under starbucks.com.

## Steps to Reproduce
1. Enumerate subdomains using tools like Sublist3r, Amass, or DNS brute-forcing
2. Filter results for CNAME records pointing to external services
3. Check each target for availability (e.g., NXDOMAIN, 404, or unclaimed resource)
4. Register the available resource
5. Deploy a proof-of-concept page demonstrating control

## Proof of Concept
```
$ dig mydailydev.starbucks.com
mydailydev.starbucks.com. 3600 IN CNAME mydailydev.netlify.app

# The Netlify site was deleted
# Created a new Netlify site with the same name
# Configured the custom domain in Netlify
# DNS propagated and the subdomain served attacker-controlled content
```

## Impact
- Phishing campaigns targeting Starbucks customers
- Brand impersonation and reputational damage
- Malware distribution via a trusted domain
- Credential theft through convincing login pages

## Remediation
Starbucks removed the dangling DNS record and implemented automated scanning for orphaned DNS records across their infrastructure.

## References
- https://hackerone.com/reports/570651
- https://github.com/codebygk/hackerone-bug-bounty-reports
