# Title: Dangling DNS Record Leading to Subdomain Takeover

- **Platform**: Bugcrowd
- **Program**: 4data.ch (Private Program)
- **Severity**: High
- **Date**: 2024-09-20
- **Researcher**: Lucien Stuker
- **Bounty**: N/A (bounty paid)

## Summary
A dangling DNS record was discovered pointing to a decommissioned cloud IP address. The researcher identified that the previously assigned IP address had been released and was now assigned to a new customer, enabling potential subdomain takeover.

## Technical Details
After decommissioning a development instance on a public cloud provider, the DNS record pointing to the old IP was not removed. Public cloud IPs are immediately released and reassigned to new customers upon deallocation. The researcher obtained the previously used IP address and could have set up a service claiming the subdomain.

## Steps to Reproduce
1. Identify orphaned A/AAAA records pointing to decommissioned cloud infrastructure
2. Verify the IP is no longer owned by the target organization
3. Acquire the same IP address (if still available) or claim the cloud resource
4. Set up a server on the claimed resource
5. Demonstrate control over the subdomain

## Proof of Concept
```
$ dig A dev-instance.4data.ch
dev-instance.4data.ch. 3600 IN A 203.0.113.42

# Check the IP does not belong to 4data anymore
$ whois 203.0.113.42
# IP was allocated to a different cloud customer

# The researcher could provision the same IP on the cloud provider
# and serve arbitrary content on the subdomain
```

## Impact
- Loss of subdomain control leading to brand damage
- Cookie harvesting from users visiting the subdomain
- Phishing campaigns using a trusted domain
- Theft of SSL/TLS certificates via Let's Encrypt
- Malware distribution from a legitimate domain

## Remediation
4data.ch deleted all dangling DNS records immediately after notification. They implemented a formal process to audit and remove DNS entries when decommissioning infrastructure.

## References
- https://4data.ch/en/blog/why_we_paid_a_bug_bounty_hunter/
