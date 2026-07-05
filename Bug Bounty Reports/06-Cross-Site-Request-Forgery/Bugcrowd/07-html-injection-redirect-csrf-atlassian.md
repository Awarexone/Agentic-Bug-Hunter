# Title: CRITICAL: HTML injection - redirect - CSRF

- **Platform**: Bugcrowd
- **Program**: Atlassian (Confluence/CrowdStream)
- **Severity**: High (P3)
- **Date**: July 21, 2023
- **Researcher**: beerbrain
- **Bounty**: N/A (Points: 2)

## Summary
An HTML injection vulnerability in Atlassian Confluence allowed an attacker to create search results that redirect users to arbitrary external websites, enabling phishing attacks and CSRF exploitation.

## Technical Details
The vulnerability existed in Confluence's code block macro functionality. An attacker could create a code block macro with HTML meta refresh content. When other users searched for keywords present in the document, the search results would trigger the meta refresh redirect, sending users to an attacker-controlled website.

```html
<meta http-equiv="refresh" content="2; url=https://attacker.com">
```

The injected HTML was not sanitized, and the search result preview rendered the meta tag, causing the browser to redirect after 2 seconds.

## Steps to Reproduce
1. Create a page in Confluence with a code block macro
2. Insert the following content inside the code block: `<meta http-equiv="refresh" content="2; url=https://attacker.com">`
3. Add relevant keywords in the body text of the document (e.g., "project plans")
4. When a victim searches for those keywords
5. The search result preview renders the meta refresh tag
6. After 2 seconds, the victim's browser redirects to the attacker's website
7. The attacker's page can host a phishing clone or perform CSRF attacks on internal networks

## Proof of Concept
```
Code Block Macro Contents:
<meta http-equiv="refresh" content="2; url=https://attacker.com" />

Page Body:
"Quarterly project plans review meeting notes Q3"
```

## Impact
- Phishing attacks via trusted Confluence domains
- CSRF attacks against internal corporate services
- Credential harvesting through cloned login pages
- Malware distribution through trusted redirect chains

## Remediation
Atlassian patched Confluence to properly sanitize HTML in code block macros and prevented meta refresh tags from being rendered in search result previews.

## References
- https://bugcrowd.com/disclosures/f91f6ee5-9400-468d-a75a-509c9eec67ba/critical-html-injection-redirect-csrf
