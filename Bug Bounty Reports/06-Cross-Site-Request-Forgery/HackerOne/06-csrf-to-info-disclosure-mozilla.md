# Title: CSRF to Information disclosure on password reset

- **Platform**: HackerOne
- **Program**: Mozilla
- **Severity**: Low
- **Date**: August 11, 2023
- **Researcher**: hackeriron1
- **Bounty**: N/A

## Summary
A CSRF vulnerability in Mozilla's Firefox Accounts password reset flow allowed an attacker to trigger a password reset email that would leak the victim's IP address, location, and browser details to the attacker.

## Technical Details
The password reset endpoint on `accounts.firefox.com` did not require CSRF tokens or proper origin validation. An attacker could craft a request that initiates a password reset to an attacker-controlled email address. When the victim visits a malicious page, the CSRF triggers the password reset request. The server processes the request and sends a password reset email containing the victim's IP address and browser details to the attacker's email.

The vulnerability existed because the password reset initiation endpoint lacked CSRF protection, and the application disclosed sensitive metadata in the password reset workflow.

## Steps to Reproduce
1. Create a CSRF PoC for the password reset endpoint on Firefox Accounts
2. The attacker changes the email field to their own email address
3. Host the malicious HTML page on attacker.com
4. Send the victim to attacker.com
5. The CSRF automatically submits the password reset request
6. The server sends a password reset link to the attacker's email
7. The attacker receives the victim's IP address and browser details from the request metadata

## Proof of Concept
```html
<html>
<body>
<script>history.pushState('','','/')</script>
<form action="https://accounts.firefox.com/reset_password" method="POST">
<input type="hidden" name="email" value="attacker@evil.com" />
<input type="submit" value="Submit" />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```

## Impact
The attacker can obtain the victim's IP address, approximate geographic location, operating system, and browser information. This information disclosure could be used for targeted attacks, social engineering, or profiling the victim.

## Remediation
Mozilla implemented CSRF protection on the password reset endpoint, including proper origin validation and anti-CSRF tokens.

## References
- https://hackerone.com/reports/2106662
