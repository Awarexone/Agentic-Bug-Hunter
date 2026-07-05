# Title: CRLF to XSS via Microsoft Firewall Bypass

- **Platform**: Microsoft Bounty
- **Program**: Microsoft Bug Bounty Program (M365)
- **Severity**: Important (P2)
- **Date**: 2024-07-31
- **Researcher**: Neh Patel (THECYBERNEH)
- **Bounty**: $6,000

## Summary
A CRLF injection vulnerability was discovered in a Microsoft subdomain that allowed an attacker to bypass the firewall and achieve reflected cross-site scripting (XSS). The vulnerability was present due to improper sanitization of user input in the URL path.

## Technical Details
The Microsoft subdomain was vulnerable to CRLF (Carriage Return Line Feed) injection. The application failed to sanitize newline characters in the URL, allowing the injection of arbitrary HTTP headers and response body content. By carefully crafting a payload with multiple CRLF sequences, the researcher was able to force the server to send a blank line after the injected content, effectively splitting the HTTP response.

The researcher used a Unicode variant of CRLF characters to bypass the firewall. The payload `嘍嘊` (URL encoded as `%E5%98%8D%E5%98%8A`) represented a CRLF sequence that the firewall didn't block but the backend server interpreted as line breaks.

Once response splitting was achieved, the researcher injected a `<script>` tag in the response body to achieve XSS.

## Steps to Reproduce
1. Craft the malicious URL with CRLF payload:
   `https://subdomain.microsoft.com/%E5%98%8D%E5%98%8ASet-Cookie:whoami=attacker%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%BCscript%E5%98%BEalert(1)%E5%98%BC/script%E5%98%BE`
2. The CRLF sequences inject headers and a script tag
3. The browser processes the injected script
4. JavaScript executes in the context of the Microsoft subdomain

## Proof of Concept
The key payload components:
- `%E5%98%8D%E5%98%8A` = CRLF sequence (firewall bypass)
- `Set-Cookie: whoami=attacker` = Injected header
- `%E5%98%BCscript%E5%98%BEalert(1)%E5%98%BC/script%E5%98%BE` = Injected script tag

The double CRLF sequence after the Set-Cookie header caused the server to treat the remaining content as the response body, where the script tag was rendered.

## Impact
- Arbitrary header injection (Set-Cookie, etc.)
- Cross-site scripting (XSS)
- HTML injection
- HTTP response splitting
- Bypassing cookie-based CSRF protections
- Potential session fixation attacks

## Remediation
Microsoft fixed the vulnerability by properly sanitizing CRLF sequences in URL paths. Input validation was enhanced to strip or reject malicious newline characters. The fix was deployed across the affected infrastructure.

## References
- https://thecyberneh.github.io/posts/MicrosoftBugbounty/
