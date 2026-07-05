# Title: Privilege escalation

- **Platform**: HackerOne
- **Program**: Automattic (Cloudup)
- **Severity**: High
- **Date**: May 29, 2014
- **Researcher**: niks
- **Bounty**: Hidden

## Summary
A privilege escalation vulnerability in Cloudup (Automattic's file sharing service) allowed an attacker to access password-protected files belonging to other users by manipulating the URL structure.

## Technical Details
Cloudup file URLs followed the pattern `https://cloudup.com/files/XXXXXXX/download`. When a file was password-protected and a non-owner tried to access the download URL, the server returned a "Forbidden" error. However, by removing the `/download` suffix from the URL (`https://cloudup.com/files/XXXXXXX/`), the server would return the file metadata and contents without checking ownership or the password requirement.

This affected all file types including images, text files, and any other uploaded content that had password protection enabled.

## Steps to Reproduce
1. Create two Cloudup accounts (Account X and Account Y)
2. From Account X, upload a file and set a password for it
3. Copy the download link: `https://cloudup.com/files/XXXXXXX/download`
4. Log out of Account X and log into Account Y
5. Attempt to access the download URL - returns "Forbidden"
6. Remove `/download` from the URL: `https://cloudup.com/files/XXXXXXX/`
7. The file contents and metadata are now accessible

## Proof of Concept
```
Direct download (protected):
GET /files/iDQ23wk5p1O/download HTTP/1.1
→ 403 Forbidden

Metadata endpoint (unprotected):
GET /files/iDQ23wk5p1O/ HTTP/1.1
→ 200 OK
Response includes:
{
  "exif": {
    "file name": "document.pdf",
    "file size": "46 kB",
    ...
  },
  "contents": "..."
}
```

## Impact
- Authentication bypass for password-protected files
- Privilege escalation allowing unauthorized users to access restricted content
- Information disclosure of file metadata and contents
- Any file with password protection was accessible to any registered user

## Remediation
Automattic/Cloudup fixed the issue by enforcing proper authorization checks on the metadata endpoint, ensuring that password-protected files required authentication regardless of the URL format.

## References
- https://hackerone.com/reports/13959
