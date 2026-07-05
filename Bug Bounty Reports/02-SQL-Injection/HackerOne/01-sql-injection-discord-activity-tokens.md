# Title: SQL Injection in Discord Activities Leading to First-Party Bot Token Theft

- **Platform**: HackerOne
- **Program**: Discord Bug Bounty Program
- **Severity**: Critical
- **Date**: 2024-04-08
- **Researcher**: real2two
- **Bounty**: N/A (Golden Bug Hunter Badge awarded)

## Summary
A SQL injection vulnerability was discovered in Discord's first-party activity platform (Putt Party and others). The vulnerability allowed an attacker to extract Discord bot tokens by exploiting the OAuth callback endpoint, leading to unauthorized access to private bot resources.

## Technical Details
The vulnerability was found in the endpoint `GET /papi/api/oauth-callback/:activityId`. The endpoint accepted three query parameters that fed into SQL queries without proper sanitization. By manipulating the `applicationId` parameter, the researcher could inject SQL conditions that revealed whether a bot token started with a specific character.

The key insight was setting `applicationId` to:
```
false OR app_id=' ' and bot_token LIKE 'a%' ORDER BY "discord_applications"."app_id" LIMIT 1; --
```

If the token started with 'a', the endpoint returned "Invalid code" (because no valid code was supplied). If it didn't start with 'a', a different error was returned. This binary oracle allowed character-by-character brute-forcing of bot tokens.

## Steps to Reproduce
1. Set up a Discord activity (e.g., Putt Party)
2. Intercept the OAuth callback request to `/papi/api/oauth-callback/:activityId`
3. Manipulate the `channel_id` parameter to bypass validation
4. Use SQL injection in the `applicationId` parameter to create a boolean oracle
5. Brute-force the bot token character by character
6. Use the extracted token to authenticate as the bot and send messages in private channels

## Proof of Concept
The SQL injection payload used a boolean-based blind approach:
```
false OR app_id=' ' and bot_token LIKE 'a%' ORDER BY "discord_applications"."app_id" LIMIT 1; --
```

The researcher created a script that iterated through characters, checking the response for "Invalid code" (true) vs other responses (false) to determine each character of the token.

Once the full token was extracted, it was used to authenticate to the Discord API and access private channels.

## Impact
- Extraction of Discord first-party bot tokens
- Unauthorized access to private bot resources
- Ability to send messages in private channels
- Potential for privilege escalation within Discord's infrastructure
- The vulnerability affected multiple first-party Discord activities

## Remediation
Discord fixed the SQL injection by implementing proper parameterized queries and input validation. The affected activity applications were made private. The endpoint was also made "stable" with additional validation.

## References
- https://gist.github.com/real2two/b321e43268162ae4ef62f78f1be70d89
