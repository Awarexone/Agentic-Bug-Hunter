# Title: Information Disclosure of Team Members via Mention Feature and Unicode URL Redirect Bypass in Zerocopter

- **Platform**: Zerocopter
- **Program**: Zerocopter Bug Bounty Platform
- **Severity**: High
- **Date**: 2022
- **Researcher**: Md Rashedul Hasan
- **Bounty**: €€€ (monetary reward)

## Summary

Two related vulnerabilities were discovered in the Zerocopter platform itself:

**Bug 1 - Information Disclosure**: A broken access control in the report management feature allowed any researcher to discover and enumerate platform team members and other researchers by username, even when those users had no relation to the researcher's report. This enabled OSINT reconnaissance against Zerocopter personnel.

**Bug 2 - Unicode URL Spoofing**: A special character validation bypass in a report editing endpoint allowed attackers to create homograph attack URLs using Unicode characters that visually resembled legitimate domains but redirected to attacker-controlled websites.

## Technical Details

### Bug 1: Team Member Information Disclosure

When managing a report on Zerocopter, the platform had an autocomplete/@mention feature for referencing team members or other researchers. Due to improper access controls, this feature did not restrict which users could be mentioned. By entering partial usernames or specific characters, an attacker could enumerate:

- Which researchers were registered on the platform
- Their exact usernames
- Whether they were associated with specific programs

This information could be gathered even when the mentioned user had no access to the attacker's report, violating the principle of least privilege.

### Bug 2: Unicode URL Homograph Bypass

Zerocopter had input validation that blocked special characters and non-ASCII Unicode characters in URL fields to prevent homograph attacks. However, a specific editing endpoint failed to apply the same validation. This allowed researchers to craft URLs using visually similar Unicode characters that bypassed the filter.

For example, the Cyrillic characters `ѡ` (U+0461) and `і` (U+0456) in `tѡіtter.com` visually resemble Latin `o` and `i` but resolve to a completely different domain (`xn--ttter-n2e0f.com`).

## Steps to Reproduce

### Bug 1:
1. Open any report where you are a participant
2. Use the @mention feature in the comment/reply section
3. Try various character combinations to enumerate usernames
4. Observe that the system reveals usernames of researchers not associated with the report

### Bug 2:
1. Access the report editing endpoint on Zerocopter
2. Craft a URL using homograph-capable Unicode characters (e.g., `https://www.tѡіtter.com`)
3. Submit the URL through the editing endpoint
4. Observe that the special character protection is bypassed
5. The rendered link visually appears as twitter.com but redirects to a different domain

## Proof of Concept

**Bug 1**: Searching for `@` followed by common letter combinations would return usernames of platform researchers who had no access to the current report. This could be scripted to build a complete directory of platform users.

**Bug 2**: A URL like `https://www.tѡіtter.com` would:
- Visually display as `https://www.twitter.com` to users (due to Unicode homoglyphs)
- Actually resolve to `https://xn--ttter-n2e0f.com` (an attacker-controlled domain)
- Appear in the researcher's dashboard without triggering the validation warning

## Impact

- **Bug 1**: Privacy violation for platform researchers; ability to map team structures and identify security personnel for targeted attacks
- **Bug 2**: Phishing attacks against Zerocopter users; credential theft via homograph domains; reduced trust in platform communication
- Combined: An attacker could identify targets via Bug 1 and then craft convincing phishing links via Bug 2

## Remediation

- Restrict the @mention feature to only show users who are explicitly participants in the current report
- Apply consistent Unicode/special character validation across all endpoints
- Implement internationalized domain name (IDN) detection and display punycode versions
- Show security warnings for links containing mixed-script Unicode characters
- Use a URL allowlist or blocklist for external links in reports

## References

- https://www.mdrashedulhasan.me/blogs-and-articles/hacking-the-hackers-zerocopter-bugs-that-allowed-me-external-privilages
