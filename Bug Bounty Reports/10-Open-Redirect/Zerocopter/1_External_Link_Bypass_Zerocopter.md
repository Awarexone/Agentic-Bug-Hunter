# Title: External Link Warning Page Bypass in Zerocopter via Markdown

- **Platform**: Zerocopter
- **Program**: Zerocopter Responsible Disclosure
- **Severity**: Medium
- **Date**: April 2018
- **Researcher**: 0xPrial
- **Bounty**: T-shirt and stickers

## Summary

A security bypass was discovered in Zerocopter's external link warning mechanism. When users include external links in bug bounty reports using Markdown, Zerocopter normally wraps them in an intermediate warning page to prevent phishing. The researcher found that by converting IP addresses to their decimal representation and using a malformed protocol prefix, the external warning page could be completely bypassed, allowing direct redirection to external websites.

## Technical Details

Zerocopter's report system supports Markdown for formatting. When a user includes an external link in a report, the platform wraps it in a safety warning page:

```html
<a href="/external_redirect?href=http%3A%2F%2Fgoogle.com" rel="noreferrer" target="_blank">Click Me</a>
```

The researcher discovered two bypass techniques:

**Technique 1 - Missing TLD**: Using `http:google` (without `//`) produced:

```html
<a href="http%3Agoogle" rel="noreferrer" target="_blank">Click Me</a>
```

Note the missing `/external_redirect?href=` prefix — the link bypassed the warning entirely.

**Technique 2 - IP Long/Decimal Encoding**: By converting the IP address to its decimal representation, the link was rendered without going through the warning page:

```
http:1249723505  (where 1249723505 = 74.125.68.113 = google.com)
```

This produced:

```html
<a href="http%3A1249723505" rel="noreferrer" target="_blank">Click Me</a>
```

## Steps to Reproduce

1. Create a report on Zerocopter
2. Use the Markdown link syntax with a decimal-encoded IP: `[Click Me](http:1249723505)`
3. Save the report
4. Click the link — it redirects directly to google.com without the external warning page

## Proof of Concept

**Original behavior (with warning page)** — using `[Click Me](http://google.com)`:

```html
<a href="/external_redirect?href=http%3A%2F%2Fgoogle.com" rel="noreferrer" target="_blank" title="">Click Me</a>
```

**Bypass** — using `[Click Me](http:1249723505)`:

```html
<a href="http%3A1249723505" rel="noreferrer" target="_blank" title="">Click Me</a>
```

The second link directs the user to `http://74.125.68.113` (google.com) without any security warning.

## Impact

- An attacker could craft report links that bypass Zerocopter's external link warning
- Malicious links could point to phishing sites impersonating known services
- Other security researchers or team members clicking the link would not be warned
- Reduced effectiveness of the platform's anti-phishing protection

## Remediation

- Extend URL validation to cover edge cases in Markdown parsing (missing `//`, decimal IPs)
- Normalize URL schemes before applying external redirect checks
- Treat all non-relative URLs as requiring the warning page
- Add additional regex patterns to catch malformed but functional URLs
- Implement server-side URL normalization before rendering links

## References

- https://0xprial.com/external-link-warning-page-bypass-in-zerocopter/
