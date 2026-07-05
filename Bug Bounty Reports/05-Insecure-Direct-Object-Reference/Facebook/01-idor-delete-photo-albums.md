# Title: IDOR in Facebook Graph API — Delete Any User's Photo Albums - $12,500

- **Platform**: Facebook Bug Bounty
- **Program**: Facebook Bug Bounty Program
- **Severity**: Critical
- **Date**: 2015-02-10
- **Researcher**: Laxman Muthiyah
- **Bounty**: $12,500

## Summary
An insecure direct object reference vulnerability was discovered in Facebook's Graph API that allowed any authenticated attacker to delete any photo album belonging to any user, page, or group. The vulnerability was fixed within 2 hours of confirmation.

## Technical Details
Facebook's Graph API allows developers to interact with Facebook data. According to documentation, photo albums cannot be deleted using the Graph API album node. However, the researcher discovered that Facebook's own mobile applications use "top-level" access tokens with additional permissions not available to third-party apps.

The researcher captured an access token from the Facebook for Android application using Charles Proxy. With this token, sending a DELETE request to `graph.facebook.com/<album_id>` successfully deleted the target album.

The vulnerability was confirmed by taking another user's album ID and sending the DELETE request with the attacker's access token. The request succeeded, proving there was no ownership validation.

## Steps to Reproduce
1. Capture Facebook for Android's access token using a MITM proxy
2. Obtain any user's photo album ID (can be found through Graph API or public pages)
3. Send a DELETE request with the album ID and captured access token
4. The album is deleted regardless of ownership

## Proof of Concept
```
DELETE /<victim_album_id> HTTP/1.1
Host: graph.facebook.com
Content-Length: 245

access_token=<attacker_facebook_android_access_token>
```

Response: `true`

This confirmed the album deletion. By iterating through album IDs, an attacker could mass-delete any public or accessible photo albums.

## Impact
- Delete any Facebook photo album — user albums, page albums, group albums
- Mass deletion without any authorization checks
- Irreversible data loss for victims
- Affected all Facebook users with photo albums
- Reputational damage to Facebook

## Remediation
Facebook mitigated the issue within 2 hours by:
1. Validating that the access token belongs to the owner of the photo album
2. If a user sends someone else's album ID with their own token, the request is dropped
3. The Graph API endpoint now checks ownership before processing deletions

## References
- https://thezerohack.com/how-i-hacked-your-facebook-photos
- https://thezerohack.com/publications/deleting-any-facebook-photo-album.pdf
