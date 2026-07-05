# Title: Facebook User Email Disclosure via Graph API

- **Platform**: Facebook Bug Bounty
- **Program**: Facebook Graph API
- **Severity**: Medium
- **Date**: 2021
- **Researcher**: N/A
- **Bounty**: $5,000

## Summary
A vulnerability in the Facebook Graph API allowed an attacker to disclose the email addresses of Facebook users by exploiting a misconfiguration in the OAuth permission scope validation.

## Technical Details
Facebook's Login API allows applications to request specific permissions from users. The `email` permission is a special permission that should only return the user's primary email after explicit user consent. However, a vulnerability existed where an application could request the `email` permission for a user who had already granted other permissions, and the API would return the email without showing a consent dialog.

The vulnerability was in the token exchange flow: when an app exchanged a short-lived token for a long-lived token, the permission validation was not properly checked. If the app had previously obtained any valid token for the user, it could silently add the `email` permission without the user's knowledge.

## Steps to Reproduce
1. Create a Facebook App
2. Implement Facebook Login and request the `public_profile` permission
3. Have a user log in and grant `public_profile`
4. Exchange the short-lived token for a long-lived token
5. Add `email` to the requested permissions in a subsequent API call
6. The API returns the user's email without showing a new consent dialog

## Proof of Concept
```
GET /v12.0/oauth/access_token?grant_type=fb_exchange_token
  &client_id=APP_ID&client_secret=APP_SECRET
  &fb_exchange_token=SHORT_LIVED_TOKEN
  &scope=email,public_profile

Response includes email address without re-consent
```

## Impact
- Silent disclosure of user email addresses
- Privacy violation — users may not want to share their email
- Potential for spam and phishing attacks

## Remediation
Facebook fixed the permission validation to always show a consent dialog when requesting new permissions, even during token exchange.

## References
- https://www.facebook.com/whitehat/ (Facebook Bug Bounty)
