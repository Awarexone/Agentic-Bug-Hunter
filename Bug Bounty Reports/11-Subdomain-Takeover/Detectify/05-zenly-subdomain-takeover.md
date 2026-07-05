# Title: Subdomain Takeover of brand.zen.ly

- **Platform**: Detectify
- **Program**: Zenly (Snapchat)
- **Severity**: High
- **Date**: 2022-03-15
- **Researcher**: Detectify Crowdsource
- **Bounty**: N/A

## Summary
The subdomain brand.zen.ly was discovered to be vulnerable to subdomain takeover. It was configured with a DNS record pointing to a third-party service (likely GitHub Pages or similar) that was no longer in use by Zenly.

## Technical Details
Subdomain takeover occurs when a DNS entry (CNAME or A record) points to an external service that has been decommissioned. The brand.zen.ly subdomain had a CNAME pointing to a hosting platform where the associated account had been deleted. This allowed an attacker to create an account on the same platform, claim the resource name, and serve content under brand.zen.ly.

## Steps to Reproduce
1. Identify the target subdomain through DNS enumeration
2. Determine the external service being pointed to via CNAME lookup
3. Verify the external resource is unclaimed or available for registration
4. Register the resource and configure it to respond to the subdomain
5. Confirm the takeover by accessing the subdomain

## Proof of Concept
```
$ dig brand.zen.ly
brand.zen.ly. 3600 IN CNAME zenly-brand.github.io

# The GitHub Pages repository was deleted
# Created a new GitHub Pages repository named zenly-brand
# Added a CNAME file with brand.zen.ly
# The subdomain started serving the attacker's GitHub Pages content
```

## Impact
- Ability to host phishing pages mimicking Zenly/Snapchat branding
- Distribution of malware through a trusted subdomain
- Session hijacking if cookies are set with broad domain scope
- SEO poisoning and traffic interception

## Remediation
Zenly removed the dangling DNS record and implemented monitoring for orphaned DNS entries. They also established a process to audit external service integrations when they are decommissioned.

## References
- https://hackerone.com/reports/1474784
