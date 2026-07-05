# Title: RCE via PHP Serialized Cookies on WordPress Website

- **Platform**: HackerOne
- **Program**: HackerOne Blog/Case Study
- **Severity**: Critical
- **Date**: 2024-03-15
- **Researcher**: HackerOne Community Researcher
- **Bounty**: Undisclosed

## Summary
A remote code execution vulnerability was discovered on a WordPress website through insecure handling of PHP serialized cookies. By manipulating serialized PHP session data, the researcher achieved arbitrary code execution on the server.

## Technical Details
WordPress uses PHP sessions to maintain user state. The session data is serialized and stored, often in cookies or server-side storage. The vulnerability arose when the application unserialized user-controlled data from cookies without proper validation.

PHP serialization is a known attack vector when user input can influence serialized data. The researcher found that the WordPress site stored session data in cookies using PHP serialization format. By crafting a malicious serialized object containing PHP code, the researcher could trigger code execution during unserialization.

The specific vulnerability was in a custom plugin that stored serialized user preferences in cookies. When the server read these cookies, it called `unserialize()` on the attacker-controlled value without any integrity checks.

## Steps to Reproduce
1. Identify a WordPress endpoint that stores serialized data in cookies
2. Decode the serialized cookie format
3. Create a malicious serialized payload using PHP gadget chains
4. Inject the crafted cookie
5. Trigger the unserialize call
6. Observe code execution

## Proof of Concept
The researcher used known PHP gadget chains to execute arbitrary code via the unserialize call:
```
Cookie: session_data=a:2:{s:4:"user";s:5:"admin";s:8:"preferences";O:14:"MaliciousClass":0:{}}
```

This exploited PHP's Object Injection pattern where magic methods like `__destruct()`, `__wakeup()`, or `__toString()` triggered code execution.

## Impact
- Arbitrary PHP code execution on the server
- Full WordPress site compromise
- Database access (user credentials, posts, options)
- File system access
- Potential to pivot to other servers
- Malware deployment

## Remediation
- Never use `unserialize()` on user-supplied input
- Replace with JSON serialization (json_encode/json_decode)
- Implement HMAC signing for cookie data if serialization is required
- Use `session_set_save_handler()` with secure session storage
- Apply the principle of not trusting client-side session data

## References
- https://www.hackerone.com/blog/how-serialized-cookies-led-rce-wordpress-website
