# Title: USPS API Business Logic Flaw Exposed 60 Million Users' Data

- **Platform**: Intigriti
- **Program**: USPS (Public Discovery)
- **Severity**: Critical
- **Date**: November 2018
- **Researcher**: Cox Media Group Security Team
- **Bounty**: N/A

## Summary
A critical business logic flaw in the USPS API exposed personal information of approximately 60 million users. The API, designed for businesses to track package data in near real-time, allowed any authenticated user to access other users' personal data including email addresses, street addresses, and phone numbers without sophisticated techniques.

## Technical Details
The USPS API had a broken authorization model. The business logic flaw was that the API authenticated the requesting application but did not properly authorize access to individual user records. Once authenticated, any user's data could be queried by manipulating a user identifier parameter. The API assumed that if a request was authenticated, it was authorized to access any resource.

## Steps to Reproduce
1. Register for a USPS API account (free)
2. Obtain API credentials
3. Query the tracking API with different user identifiers
4. Observe that any user's PII is returned without additional authorization checks
5. Brute-force or enumerate user IDs to collect mass amounts of data

## Proof of Concept
```
GET /usps/api/v1/tracking?userId=1000001
Response: { "name": "John Doe", "email": "john@example.com", "address": "123 Main St", "phone": "555-0100" }

GET /usps/api/v1/tracking?userId=1000002
Response: { "name": "Jane Smith", "email": "jane@example.com", "address": "456 Oak Ave", "phone": "555-0101" }
```

## Impact
Exposure of PII (names, emails, addresses, phone numbers) for ~60 million USPS customers. Could lead to identity theft, phishing attacks, physical threats, and regulatory non-compliance (privacy violations).

## Remediation
Implement proper access control: users should only be able to access data they own or are explicitly authorized to view. Add authentication that verifies the relationship between the requester and the requested resource. Rate limit API calls to prevent mass enumeration.

## References
- https://www.wired.com/story/usps-api-exposed-data-60-million-users/
- https://krebsonsecurity.com/2018/11/usps-site-exposed-data-on-60-million-users/
