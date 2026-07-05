# Title: Admins can change authentication details of user configured external storage

- **Platform**: HackerOne
- **Program**: Nextcloud
- **Severity**: Medium
- **Date**: 2023
- **Researcher**: N/A
- **Bounty**: $100

## Summary
An information disclosure and privilege escalation vulnerability in Nextcloud allowed administrators to view and modify authentication details of external storage configurations set up by users, exposing credentials and access tokens.

## Technical Details
Nextcloud allows users to configure external storage backends (like S3, FTP, WebDAV, etc.) for their personal use. The administrator panel provided functionality to view and manage all external storage configurations on the server. However, the admin interface did not properly restrict access to the authentication details (passwords, keys, tokens) of storage backends configured by individual users.

While administrators by definition have elevated privileges, this vulnerability specifically exposed user-specific credentials that should have been encrypted or masked from administrators. The authentication details were stored in the database and the admin interface would display them in plaintext.

## Steps to Reproduce
1. A regular user configures an external storage backend with authentication credentials
2. An administrator navigates to the external storage management page
3. The admin interface lists all external storage configurations
4. The authentication details (password, access key, secret) are visible in plaintext
5. The admin can also modify these credentials without the user's knowledge

## Proof of Concept
```
Admin URL: /settings/admin/externalstorages

Displayed information:
User: victim@example.com
Storage type: Amazon S3
Bucket: my-private-bucket
Access Key: AKIAIOSFODNN7EXAMPLE
Secret Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

## Impact
- Exposure of user-specific cloud storage credentials to administrators
- Unauthorized access to user-controlled external storage systems
- Potential data breach if storage credentials are used for other services
- Violation of data isolation and privacy expectations

## Remediation
Nextcloud fixed the issue by properly encrypting or masking authentication details in the admin interface. User-configured storage credentials are now stored with proper encryption and are not displayed in plaintext to administrators.

## References
- https://hackerone.com/reports/2107934
