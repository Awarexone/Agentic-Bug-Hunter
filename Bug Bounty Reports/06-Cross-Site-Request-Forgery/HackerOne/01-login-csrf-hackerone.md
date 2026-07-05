# Title: Login CSRF vulnerability on hackerone.com

- **Platform**: HackerOne
- **Program**: HackerOne
- **Severity**: Medium
- **Date**: March 30, 2020
- **Researcher**: what_web
- **Bounty**: $500

## Summary
A Login Cross-Site Request Forgery (CSRF) vulnerability was discovered on hackerone.com that allowed an attacker to force a victim user to log in to an attacker-controlled account without their knowledge or consent.

## Technical Details
The login endpoint on hackerone.com did not properly validate CSRF tokens. By crafting a malicious HTML form that submits credentials to the HackerOne login endpoint, an attacker could trick a victim into unknowingly authenticating as the attacker's account. This type of CSRF is known as Login CSRF.

The vulnerability existed because the login form submission lacked CSRF protection mechanisms such as anti-CSRF tokens or SameSite cookie attributes. When a user submitted login credentials, the server accepted the request without verifying that the request originated from the legitimate login page.

## Steps to Reproduce
1. Create an attacker account on HackerOne
2. Craft an HTML page with an auto-submitting form pointing to `https://hackerone.com/users/sign_in`
3. Set the form fields to the attacker's username and password
4. Host the HTML page on an attacker-controlled domain
5. Send the victim the link to the crafted page
6. When the victim visits the page, the form auto-submits
7. The victim's browser is now authenticated as the attacker's account without their knowledge

## Proof of Concept
```html
<html>
<body>
<form action="https://hackerone.com/users/sign_in" method="POST">
<input type="hidden" name="user[email]" value="attacker@example.com" />
<input type="hidden" name="user[password]" value="attackerpassword123" />
<input type="submit" value="Submit" />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```

## Impact
Login CSRF can be leveraged in various ways:
- The attacker can trick victims into saving bookmarks or authorizing OAuth applications under the attacker's account
- Sensitive information the victim submits while logged into the attacker's account becomes accessible to the attacker
- This can be chained with other vulnerabilities for account takeovers

## Remediation
The fix involved implementing proper CSRF protection on the login endpoint by validating anti-CSRF tokens for login form submissions and applying appropriate SameSite cookie attributes.

## References
- https://hackerone.com/reports/834366
