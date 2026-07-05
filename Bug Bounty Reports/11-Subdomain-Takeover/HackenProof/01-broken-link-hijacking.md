# Title: Impersonation via Broken Link Hijacking on Twitter/Telegram

- **Platform**: HackenProof
- **Program**: HackenProof (self-hosted)
- **Severity**: Medium
- **Date**: 2023-05-20
- **Researcher**: bughuntar
- **Bounty**: $250 (estimated)

## Summary
A broken link hijacking vulnerability was discovered on the HackenProof platform's official social media accounts. The official Telegram account link in HackenProof's Twitter bio was pointing to a non-existent or expired Telegram handle, which an attacker could register and use to impersonate HackenProof's official support channel.

## Technical Details
The vulnerability falls under the category of "Resource Injection" or "Broken Link Hijacking" (similar to subdomain takeover but for social media handles). The official HackenProof website and email signatures contained a link to their Telegram account (`@hackenproof_ch`). The researcher discovered that this Telegram handle was no longer actively controlled by HackenProof and could potentially be claimed by an attacker. Once claimed, the attacker could impersonate official HackenProof support staff and interact with users seeking help.

## Steps to Reproduce
1. Visit the official HackenProof website (https://hackenproof.com)
2. Scroll to the bottom of the page and click on the official Twitter icon
3. On the Twitter profile, click on the linked Telegram account
4. The researcher discovered the Telegram handle was already hijacked/available for registration

## Proof of Concept
The researcher demonstrated that:
- The Telegram handle `@hackenproof_ch` was not properly secured
- An attacker could register this handle and pose as official HackenProof support
- Users clicking the link from HackenProof's official Twitter/X bio would be directed to the attacker-controlled Telegram account
- A video PoC (poc.mp4) was provided showing the hijacked account

## Impact
- Social engineering attacks against HackenProof users seeking support
- Theft of cryptocurrency or personal information from users who believe they are talking to official support
- Brand reputation damage
- Users could share private keys, passwords, or other sensitive information with attackers
- Chained attacks targeting high-value users of the platform

## Remediation
- Regularly audit all external links and social media handles for validity
- Implement a social media monitoring process to detect unauthorized changes
- Claim and verify official handles on all platforms
- Remove links to unmanaged or expired accounts
- Use URL shorteners with the ability to update destination URLs
- Implement brand verification badges where available

## References
- https://hackenproof.com/reports/HAC-858
- https://hackerone.com/reports/1117079 (similar finding)
