# Title: Mailgun subdomain takeover

- **Platform**: Intigriti
- **Program**: Deriv.com
- **Severity**: High
- **Date**: 2024-05-02
- **Researcher**: zacian
- **Bounty**: N/A

## Summary
A subdomain takeover vulnerability was identified where a subdomain of Deriv.com was configured with a CNAME record pointing to a Mailgun service that was no longer active. This allowed an attacker to claim the Mailgun domain and gain control over email communications from that subdomain.

## Technical Details
The subdomain's CNAME record pointed to `mailgun.org`, which is used for email processing. When the Mailgun domain configuration was removed or expired, the DNS entry remained. An attacker could add the domain to their own Mailgun account and take control of email flow, including sending and receiving emails from that domain.

## Steps to Reproduce
1. Enumerate subdomains of the target domain
2. Identify CNAME records pointing to known third-party services (Mailgun, SendGrid, etc.)
3. Verify the third-party service account has been deleted or the domain has been removed
4. Register the domain in an attacker-controlled account on the same service
5. Verify control by sending/receiving email or accessing the subdomain

## Proof of Concept
```
$ dig mail.deriv.com
mail.deriv.com. 3600 IN CNAME mailgun.org

# The Mailgun domain was not claimed by any account
# Adding deriv.com to a new Mailgun account verified the takeover
# Email sent to test@mail.deriv.com was received by the attacker's Mailgun inbox
```

## Impact
- Full control over email communications from the subdomain
- Ability to send phishing emails from a trusted domain
- Interception of password reset emails and account verification links
- Reputational damage and loss of customer trust

## Remediation
Deriv.com removed the dangling CNAME record and conducted a full audit of their DNS configuration. They implemented controls to ensure decommissioned services have their DNS records cleaned up.

## References
- https://hackerone.com/reports/2270082
- https://www.redpacketsecurity.com/hackerone-bugbounty-disclosure-mailgun-subdomain-takeover-zacian/
