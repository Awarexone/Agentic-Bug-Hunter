# Title: Information Disclosure via Debug Endpoint Exposed

- **Platform**: Medium
- **Program**: Ride-sharing Mobile App
- **Severity**: Medium
- **Date**: 2024
- **Researcher**: N/A
- **Bounty**: N/A

## Summary
An information disclosure vulnerability was discovered in a ride-sharing mobile application where a debug endpoint was inadvertently exposed in the production build, leaking internal API credentials, database connection strings, and user personally identifiable information (PII).

## Technical Details
The mobile application contained a hidden debug activity that could be triggered by dialing a specific USSD code on the device. This debug activity exposed a `DEBUG` screen that displayed:
- Internal API endpoint URLs
- Database connection strings with credentials
- AWS S3 access keys and secret keys
- Firebase Cloud Messaging server keys
- Recent API request/response logs containing user PII
- User authentication tokens

The debug activity was meant to be compiled only in debug builds, but a build configuration error caused it to be included in the production APK.

## Steps to Reproduce
1. Install the ride-sharing mobile app on an Android device
2. Open the phone dialer and enter `*#*#2846579#*#*` (project menu code)
3. Select "Background Settings" from the debug menu
4. Navigate to "API Debug Logs"
5. View sensitive information including AWS keys and database credentials
6. Review user API logs containing PII

## Proof of Concept
The debug menu displayed:
```
=== API Configuration ===
API URL: https://internal-api.target.com/v2
DB_HOST: db.target.com
DB_USER: prod_user
DB_PASS: S3cr3tP@ss!
AWS_KEY: AKIAIOSFODNN7EXAMPLE
AWS_SECRET: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

## Impact
- Exposure of cloud infrastructure credentials
- Potential data breach of all user records
- Unauthorized access to internal systems
- Compliance violations (GDPR, CCPA)

## Remediation
The company:
- Removed the debug activity from the production build
- Rotated all exposed credentials and API keys
- Implemented build pipeline checks to prevent inclusion of debug components in release builds

## References
- https://infosecwriteups.com/information-disclosure-via-debug-endpoint-7c4b2q2e1f2a
