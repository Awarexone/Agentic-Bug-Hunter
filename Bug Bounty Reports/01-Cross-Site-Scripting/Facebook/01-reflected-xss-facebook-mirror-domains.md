# Title: Reflected XSS in Facebook's Mirror Websites

- **Platform**: Facebook Bug Bounty
- **Program**: Facebook (Meta) Bug Bounty
- **Severity**: Medium
- **Date**: 2020-06-20
- **Researcher**: Bipin Jitiya (sudi)
- **Bounty**: $500

## Summary
A reflected cross-site scripting vulnerability was discovered in Facebook's mirror domains. The `href` attribute in an anchor tag on the error page reflected user input without proper encoding, allowing JavaScript execution via the `javascript:` URI scheme.

## Technical Details
The researcher was collecting subdomains of `thefacebook.com` and discovered a mirror domain with an interesting behavior. When accessing a non-existent path, the error page displayed a link containing the original URL path in the `href` attribute of an anchor tag.

The reflection was inside single quotes within the `href` value:
```html
<a href='/non-existent-path'>Go back</a>
```

By breaking out of the single quotes and using the multiple-href technique, the researcher could inject a `javascript:` URI. The final payload used a space character and two `href` attributes — the browser would use the second one, which contained the JavaScript code.

The vulnerable endpoints included:
- `mirror.facebook.net`
- `mirror.t.tfbnw.net`
- Various `thefacebook.com` subdomains

## Steps to Reproduce
1. Visit a Facebook mirror domain with a malicious path:
   `http://mirror.facebook.net/'>
2. Observe that the path is reflected in the HTML
3. Craft a payload using the double-href technique:
   `http://mirror.facebook.net/' href='javascript:alert(document.domain)'`
4. Click the injected link on the page
5. JavaScript executes in the Facebook domain context

## Proof of Concept
```
http://mirror.facebook.net/' href='javascript:alert(document.domain)'
```

The injected HTML becomes:
```html
<a href='/mirror.facebook.net/' href='javascript:alert(document.domain)'>Go back</a>
```

The browser uses the second `href` attribute, executing the JavaScript.

## Impact
- JavaScript execution on Facebook mirror domains
- Session cookie theft in the Facebook context
- Phishing attacks against users visiting mirror domains
- Ability to perform actions on behalf of the victim
- Three Facebook mirror domains were found vulnerable

## Remediation
Facebook fixed the issue by encoding the single quote character (`'`) to its HTML entity (`&#39;`), preventing attackers from breaking out of the `href` attribute context. Input sanitization was applied across all mirror domain endpoints.

## References
- https://sudistark.github.io/2020/08/08/reflected-xss-in-facebook-s-mirror-websites.html
- https://cuberk.com/blog/Simple-story-of-some-complicated-XSS-on-Facebook/
