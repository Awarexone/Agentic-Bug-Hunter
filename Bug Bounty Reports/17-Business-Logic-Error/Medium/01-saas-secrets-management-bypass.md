# Title: $1,500 Bounty: Business Logic Flaw in Project Secrets Management

- **Platform**: Medium
- **Program**: Private SaaS Platform (Infosec Writeups)
- **Severity**: High (CVSS 8.3)
- **Date**: July 5, 2025
- **Researcher**: Abhi Sharma
- **Bounty**: $1,500

## Summary
A business logic vulnerability allowed Editor-level users to bypass UI restrictions and directly add secrets to projects via API — something only Owners were supposed to do. The UI correctly prevented Editors from accessing the Manage section, but the backend API lacked the same restriction.

## Technical Details
The platform had three roles: Owners (full permissions), Editors (edit code/resources), and Viewers (read-only). Free-tier projects didn't have the Manage section available. Despite UI restrictions hiding the Manage section for Editors on free-tier projects, the backend API allowed Editor users to directly add secrets via crafted API requests.

## Steps to Reproduce
1. Create or access a free-tier project as an Editor
2. Observe that the Manage section is hidden in the UI
3. Intercept traffic with Burp Suite
4. Send crafted API request to add a secret

## Proof of Concept
```
POST /api/v1/secrets/namespace/project:<project_id>/name/<secret_name> HTTP/2
Host: target.com
Content-Type: application/json

{"value":"csdc"}

Response:
HTTP/2 200 OK
{
  "message": "Secret created successfully",
  "name": "<secret_name>",
  "value": "csdc"
}
```

## Impact
Privilege escalation — Editors could perform Owner-only actions. Free-tier limitations bypassed. Malicious editors could inject secrets affecting deployments, pipelines, or configurations.

## Remediation
Implement server-side authorization checks that mirror UI restrictions. The API endpoint should verify the user's role and project tier before allowing secret creation.

## References
- https://infosecwriteups.com/1-500-bounty-business-logic-flaw-in-project-secrets-management-4b985175071e
