# Title: IDOR in TikTok Family Pairing Allows Unauthorized Control of Any User's Account Settings

- **Platform**: TikTok Bug Bounty
- **Program**: TikTok (HackerOne)
- **Severity**: High
- **Date**: 14 September 2021
- **Researcher**: s3c
- **Bounty**: N/A (paid bounty, amount undisclosed)

## Summary

An Insecure Direct Object Reference (IDOR) vulnerability was discovered in TikTok's Family Pairing feature. The `child_user_id` parameter in API requests was not properly validated to ensure the requesting parent account was authorized to modify the target child account's settings. This allowed an attacker to change sensitive privacy and safety settings for any TikTok user by simply knowing or enumerating their user ID.

## Technical Details

TikTok's Family Pairing feature allows parents to link their accounts to their children's accounts to enforce privacy and safety controls. The feature exposes an API endpoint that accepts parameters including `child_user_id`, `restriction_type`, and `restriction_value`.

The vulnerability existed because the server only verified that:
- The requesting user was authenticated
- The requesting user had a Family Pairing relationship with *some* account

It failed to verify that the `child_user_id` in the request actually belonged to the paired child. By modifying the `child_user_id` parameter to any arbitrary user ID, an attacker could change settings for any TikTok account.

The `restriction_type` parameter controlled which setting was modified:
- 1: Direct Messages
- 2: Liked Videos
- 3: Comments
- 4: Public/Private Account

The `restriction_value` determined the state:
- 1: ON / Allowed
- 2: OFF / Disallowed
- 3: No One

## Steps to Reproduce

1. Create two TikTok accounts — one "parent" and one "child"
2. Link the accounts via Family Pairing
3. Using Burp Suite, intercept the request when changing a child account setting (e.g., switching from public to private)
4. Observe the `child_user_id`, `restriction_type`, and `restriction_value` parameters
5. Modify `child_user_id` to a different user's ID
6. Forward the modified request
7. Observe that the target user's settings are changed without authorization

## Proof of Concept

The original intercepted request:

```
POST /api/family_pairing/update_settings HTTP/1.1
Host: www.tiktok.com
...

child_user_id=12345&restriction_type=4&restriction_value=1
```

Modified request targeting another user:

```
POST /api/family_pairing/update_settings HTTP/1.1
Host: www.tiktok.com
...

child_user_id=67890&restriction_type=4&restriction_value=1
```

The server returned a 200 OK response, and the target user's account was changed from public to private without their consent.

## Impact

An attacker could:
- Change any TikTok user's account from public to private (or vice versa)
- Disable or enable direct messages for any user
- Disable or enable comments on any user's videos
- Disable or enable liked videos visibility for any user
- Potentially enumerate user IDs and perform bulk modifications
- Disrupt content creators, influencers, and verified accounts

## Remediation

- Implement proper authorization checks to verify the requesting user is the legitimate parent of the specified child account
- Use session-based or token-based association instead of user-supplied IDs
- Implement rate limiting on sensitive settings endpoints
- Add re-authentication or multi-factor confirmation for critical setting changes
- Log and monitor anomalous cross-account modification attempts

## References

- https://s3c.medium.com/how-i-hacked-world-wide-tiktok-users-24e794d310d2
- https://hackerone.com/tiktok
