# Title: Information Disclosure via Git Repository Exposure

- **Platform**: YesWeHack
- **Program**: European Government E-Health Portal
- **Severity**: Critical
- **Date**: 2024
- **Researcher**: N/A
- **Bounty**: N/A

## Summary
A critical information disclosure vulnerability was discovered in a European government e-health portal where the `.git` directory was exposed on the production server, leaking the entire source code repository including database credentials, API keys, and encryption keys.

## Technical Details
The e-health portal had directory listing enabled and the `.git` directory was accessible at `https://portal.e-health.gov/.git/`. Using tools like `git-dumper` or `dvcs-ripper`, an attacker could download the entire Git repository history, which contained:

- Database connection strings with plaintext passwords
- Encryption keys for patient data
- API keys for third-party health services
- JWT signing secrets
- SMTP server credentials
- Infrastructure configuration files
- Commit history revealing developer credentials

## Steps to Reproduce
1. Navigate to `https://portal.e-health.gov/.git/HEAD`
2. If accessible, confirm the `.git` directory is exposed
3. Use `git-dumper` to download the entire repository
4. Check the Git log for sensitive commits
5. Search for credentials in configuration files

## Proof of Concept
```bash
# Download the exposed Git repository
git clone https://portal.e-health.gov/.git/

# Or use git-dumper
git-dumper https://portal.e-health.gov/.git/ ./extracted-repo/

# Search for credentials
cd extracted-repo
git log --all -p | grep -i "password\|secret\|key\|token"
```

## Impact
- Exposure of complete source code
- Access to database credentials — could lead to data breach of all patient medical records
- Encryption key compromise — potential decryption of stored patient data
- JWT secret compromise — ability to forge authentication tokens
- Full infrastructure compromise

## Remediation
The government agency:
- Removed the `.git` directory from the production server
- Disabled directory listing
- Rotated all credentials and keys
- Implemented CI/CD pipeline checks to prevent source code exposure

## References
- https://www.yeswehack.com/learn/bug-bounty/git-repository-exposure
