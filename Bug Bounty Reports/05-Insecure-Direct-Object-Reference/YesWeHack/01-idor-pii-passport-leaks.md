# Title: Simple IDOR Led to PII & Passport Leaks — $1,000 Bounty

- **Platform**: YesWeHack
- **Program**: Private Bug Bounty Program
- **Severity**: High (CVSS 8.8)
- **Date**: 2025-06-15
- **Researcher**: toast
- **Bounty**: $1,000

## Summary
An insecure direct object reference vulnerability was discovered in a private program's subscription endpoint. By manipulating an ID in the URL path, an authenticated attacker could access any other user's personal information, including passports and bank documents. Approximately 900 users had their data exposed.

## Technical Details
The target application had a subscription feature where users could manage their plans. The researcher logged in, navigated to the subscription endpoint, and captured the GET request in Burp Suite. The URL contained a numeric user ID in the path: `/blah_blah/[ID]`.

By changing the ID parameter to other users' IDs, the researcher discovered that:
- The endpoint returned full PII including names, emails, phone numbers, and addresses
- Bank account numbers and financial details were accessible
- Uploaded documents like passports and bank statements could be viewed and downloaded
- No authorization check was performed to verify the requester owned the resource

The vulnerability required the attacker to be authenticated (have a valid session), but any authenticated user could access any other user's data.

## Steps to Reproduce
1. Log in to the application
2. Navigate to the subscription management page
3. Intercept the GET request to the subscription endpoint
4. Note the user ID in the URL path: `/subscription/12345`
5. Change the ID to another value: `/subscription/12346`
6. Observe that the response contains the other user's full PII
7. Continue iterating through IDs to access all exposed accounts

## Proof of Concept
```
GET /subscription/12346 HTTP/1.1
Host: target.com
Cookie: session=valid_attacker_session

Response:
{
  "name": "Victim Name",
  "email": "victim@email.com",
  "phone": "+1-555-0123",
  "address": "123 Victim Street",
  "bank_account": "XXXX-XXXX-XXXX-1234",
  "documents": {
    "passport": "/documents/passport_victim.pdf",
    "bank_statement": "/documents/bank_victim.pdf"
  }
}
```

## Impact
- Exposure of PII for approximately 900 users
- Identity theft potential via passport and bank document access
- Financial fraud via exposed bank account details
- Privacy violation and regulatory non-compliance (GDPR, etc.)
- High severity (CVSS 8.8) due to data sensitivity

## Remediation
YesWeHack coordinated with the program to implement:
1. Server-side ownership validation on the subscription endpoint
2. The authenticated user's ID is now compared with the requested resource's owner
3. Access denied if the IDs don't match
4. Audit logging for suspicious ID enumeration attempts

## References
- https://medium.com/@theteatoast/simple-idor-led-to-pii-passport-leaks-and-a-1-000-bounty-e3e453a519ec
