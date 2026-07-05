# Title: CSRF Bypass Using Domain Confusion Leads to Account Takeover

- **Platform**: Medium (InfoSec Write-ups)
- **Program**: Confidential E-commerce Platform
- **Severity**: High
- **Date**: August 2024
- **Researcher**: Osama Aly
- **Bounty**: $4,000

## Summary
A CSRF bypass using domain confusion was discovered on an e-commerce platform, allowing an attacker to perform state-changing actions on behalf of a victim by crafting requests that bypassed the CSRF token validation through domain manipulation.

## Technical Details
The application used CSRF tokens tied to the domain in the HTTP Referer header. However, the validation logic only checked if the Referer contained the base domain name, rather than performing an exact match. By registering a domain like `target.com.attacker.com` and crafting a CSRF form hosted there, the domain confusion bypass allowed the CSRF token validation to pass because `target.com` was found as a substring in the Referer header.

This bypass enabled the attacker to change the victim's email address and initiate a password reset, leading to full account takeover.

## Steps to Reproduce
1. Identify the CSRF protection mechanism on the target application
2. Notice that CSRF validation checks if the Referer header contains the domain name
3. Register a subdomain like `target.com.evil.com` 
4. Craft a CSRF exploitation page on this domain
5. The form targets the sensitive email change endpoint
6. Send the malicious link to the victim
7. When the victim visits, the Referer header contains `target.com` as a substring
8. The CSRF token validation passes and the email is changed
9. Initiate password reset to complete account takeover

## Proof of Concept
```html
<!-- Hosted on target.com.attacker.com -->
<html>
<body>
<form action="https://target.com/api/user/email" method="POST">
<input type="hidden" name="email" value="attacker@evil.com" />
<input type="hidden" name="csrf_token" value="KNOWN_VALID_TOKEN" />
<input type="submit" value="Click here for free prize!" />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```

## Impact
Full account takeover of victim accounts on the e-commerce platform, including access to personal information, order history, payment methods, and the ability to make purchases.

## Remediation
The platform fixed the CSRF validation to perform an exact domain match rather than substring matching, preventing domain confusion bypasses.

## References
- https://infosecwriteups.com/csrf-bypass-using-domain-confusion-leads-to-ato-ac682dd17722
