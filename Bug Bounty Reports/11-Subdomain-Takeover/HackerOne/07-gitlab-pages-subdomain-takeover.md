# Title: Subdomain takeover in GitLab Pages

- **Platform**: HackerOne
- **Program**: GitLab
- **Severity**: High
- **Date**: 2024-05-30
- **Researcher**: fdeleite
- **Bounty**: N/A

## Summary
A subdomain takeover was possible through GitLab Pages by exploiting dangling custom domains. When a user configured a custom domain for their GitLab Pages site and then deleted the project or group, the DNS CNAME record pointing to GitLab Pages remained active, allowing another user to claim the domain.

## Technical Details
GitLab Pages allows users to configure custom domains (e.g., `blog.example.com`) pointing to `instanceX.gitlab.io`. When a user deletes their GitLab Pages project or the entire group, the DNS record pointing to GitLab Pages is not automatically cleaned up. If an attacker creates a new GitLab Pages project and configures the same custom domain, GitLab's virtual hosting will serve the attacker's content under the victim's domain.

## Steps to Reproduce
1. Identify custom domains pointing to GitLab Pages via CNAME lookup
2. Check if the GitLab Pages project still exists by visiting the Pages URL
3. If the site returns 404, the Pages project may have been deleted
4. Create a new GitLab Pages project and configure the custom domain
5. Verify the takeover by accessing the custom domain

## Proof of Concept
```
$ dig blog.example.com
blog.example.com. 3600 IN CNAME instanceX.gitlab.io

# The original GitLab Pages project was deleted
# Created a new GitLab Pages project with a simple HTML page
# Added blog.example.com as a custom domain in GitLab Pages settings
# GitLab verified the domain via the CNAME record
# The domain started serving the attacker's GitLab Pages content
```

## Impact
- Hosting malicious content under a trusted organization's domain
- Phishing and social engineering attacks
- Credential theft and malware distribution
- Undermining trust in the organization's digital presence

## Remediation
GitLab implemented additional checks to prevent claiming custom domains that belong to deleted projects without proper verification. Users were advised to remove DNS records before deleting GitLab Pages projects.

## References
- https://hackerone.com/reports/2523654
- https://gitlab.com/gitlab-org/gitlab/-/issues/464558
