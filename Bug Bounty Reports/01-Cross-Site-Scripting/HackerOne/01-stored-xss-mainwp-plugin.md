# Title: Stored Cross-Site Scripting (XSS) in "Add Contact" Name Field – MainWP Plugin

- **Platform**: HackerOne
- **Program**: MainWP WordPress Plugin
- **Severity**: High
- **Date**: 2025-01-14
- **Researcher**: Redacted
- **Bounty**: N/A

## Summary
A stored XSS vulnerability was discovered in the MainWP WordPress plugin's Client Management feature. The "Add Contact" name field failed to sanitize user input, allowing an attacker to inject malicious JavaScript that executed whenever a user viewed the compromised contact.

## Technical Details
The MainWP plugin allows site administrators to manage multiple WordPress sites from a single dashboard. Within the Client Management section, users can add contacts with name, email, phone, and other details. The `name` parameter in the contact creation form was not properly sanitized before being stored in the database and rendered in the admin interface.

The vulnerable code path involved the contact name field being stored directly and later rendered without output encoding in the WordPress admin panel. When an administrator navigated to the Clients page and viewed the contact list, the injected script executed in the context of their WordPress admin session.

## Steps to Reproduce
1. Log in as a WordPress administrator with MainWP installed
2. Navigate to Clients > Add Contact
3. Enter a malicious payload in the Name field: `<img src=x onerror=alert(document.domain)>`
4. Save the contact
5. Navigate to the Clients page to view the contact list
6. Observe the JavaScript alert box executing

## Proof of Concept
The following payload was used in the Name field:
```
<img src=x onerror=alert(document.domain)>
```

The payload was stored in the database without sanitization and rendered as HTML in the admin dashboard. When the page loaded, the broken image tag triggered the `onerror` event, executing the JavaScript.

## Impact
An attacker with the ability to create or edit contacts could execute arbitrary JavaScript in the context of other administrators' browsers. This could lead to:
- Session cookie theft
- CSRF token theft
- Privilege escalation within the WordPress admin panel
- Defacement or data theft
- Complete compromise of the WordPress site

## Remediation
The MainWP team implemented proper sanitization and output encoding for the contact name field. Input validation was added on the server side, and the output was encoded using WordPress's built-in escaping functions like `esc_html()` to prevent HTML injection.

## References
- https://hackerone.com/reports/3176981
