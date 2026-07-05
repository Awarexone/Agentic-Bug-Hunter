# Title: Open Redirect Vulnerability on phorest.com

- **Platform**: OpenBugBounty
- **Program**: phorest.com
- **Severity**: Low
- **Date**: 2024-06-12
- **Researcher**: SYPltd
- **Bounty**: N/A (Coordinated Disclosure)

## Summary
An open redirect vulnerability was discovered on phorest.com, a salon management software platform. The application allowed unvalidated redirects via the `redirect` parameter, enabling attackers to redirect users to arbitrary external domains.

## Technical Details
The application used a URL parameter to redirect users after certain actions (such as login or logout). The parameter value was not validated against an allowlist of permitted domains, allowing arbitrary external URLs to be specified.

## Steps to Reproduce
1. Craft a URL with a malicious external domain in the redirect parameter
2. Send the link to a victim (e.g., via phishing email)
3. When the victim clicks the link and completes the action, they are redirected to the attacker-controlled site

## Proof of Concept
```
https://www.phorest.com/login?redirect=https://evil.com/phishing-page
```

## Impact
- Phishing attacks: Users could be redirected to attacker-controlled pages that mimic the legitimate site
- Credential theft: Combined with a convincing phishing page, users could be tricked into entering credentials
- Brand reputation damage: The legitimate domain being used for redirects erodes user trust
- Bypassing URL validation filters in security products

## Remediation
- Implement an allowlist of permitted redirect destinations
- Use relative paths instead of full URLs for redirects
- Validate that redirect URLs match the application's own domain
- Display a warning to users when redirecting to external domains

## References
- https://www.openbugbounty.org/reports/2815551/
