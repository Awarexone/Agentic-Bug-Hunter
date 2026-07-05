# Title: OAuth: A Backdoor in Disguise — $7,500 Bug Bounty Study Case

- **Platform**: Medium
- **Program**: Private Social Media Management Application
- **Severity**: Critical
- **Date**: October 14, 2024
- **Researcher**: 0xdead4f
- **Bounty**: $7,500

## Summary
Two critical OAuth implementation flaws were discovered: (1) Broken authentication via reusable JWT tokens where the `sub` claim could be manipulated, and (2) User enumeration via `/api/v4/users` endpoint that leaked OAuth IDs, IP addresses, and AI platform tokens. Chained together, these allowed full account takeover of any user who logged in via OAuth.

## Technical Details
The OAuth implementation failed to validate JWT token signatures properly. The `id_token` JWT contained a `sub` claim used as the user identifier. Since the server didn't verify the JWT signature, an attacker could modify the `sub` value to any user's OAuth ID and re-encode the token. The second vulnerability allowed retrieving target users' OAuth IDs through a user enumeration endpoint that exposed IDs, IPs, device info, and AI platform tokens.

## Steps to Reproduce
1. Login via OAuth and capture the POST to `/api/v4/authorize`
2. Observe the `code`, `password`, and `id_token` parameters are reusable
3. Decode the JWT `id_token` and change the `sub` value
4. Re-encode without signature verification
5. Use modified token to login as any user
6. For user enumeration: POST to `/api/v4/users` with target email
7. Response contains the user's OAuth ID (for use in step 3-5)

## Proof of Concept
```
Step 1 - Capture login request:
POST /api/v4/authorize HTTP/2
Host: vuln.com
{"password": "...", "is_nude": "...", "code": "...", "id_token": "eyJ..."}

Step 2 - Decode id_token:
{"sub": "victim_oauth_id", "email": "victim@example.com"}

Step 3 - Modify sub to different user ID:
{"sub": "another_user_id", "email": "victim@example.com"}

Step 4 - Token enumeration:
POST /api/v4/users
{"email": "victim@example.com"}
Response includes OAuth ID, IP, device info, AI token
```

## Impact
Complete account takeover of any user who logged in using OAuth. Chained with user enumeration, an attacker could target specific users, learn their IP and device details, and access their accounts including AI platform integrations.

## Remediation
Validate JWT signatures on every request. Ensure authentication codes are one-time use only. Restrict sensitive information exposed through API endpoints. Implement proper claim validation.

## References
- https://xdead4f.medium.com/oauth-a-backdoor-in-disguise-a-7500-study-case-3383a4012295
