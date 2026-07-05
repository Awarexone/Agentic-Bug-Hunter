# Title: IDOR — Delete Any Folder for Any User via folder_id Manipulation

- **Platform**: HackerOne
- **Program**: SingleStore Bug Bounty Program
- **Severity**: Low (CVSS 3.8)
- **Date**: 2025-05-20
- **Researcher**: Redacted
- **Bounty**: Undisclosed

## Summary
An insecure direct object reference vulnerability was discovered in SingleStore's backend API. Low-privilege users within the same organization could delete folders owned by other users by manipulating the `folder_id` parameter in DELETE requests. The authorization check was missing or insufficient.

## Technical Details
The vulnerability resided in the endpoint pattern:
```
/public/notebooks/api/contents/<org_id>/_internal-s2-stage/<folder_id>/<folder_name>/
```

The DELETE operation to this endpoint accepted a `folder_id` parameter that directly referenced a database object. The server failed to verify that the authenticated user owned the specified folder. A low-privilege user could craft a DELETE request targeting another user's folder ID and successfully delete it.

The attack required:
1. Knowledge of the target user's folder ID (a UUID)
2. Knowledge of the target user's organization UUID
3. A valid session on the platform

While the CVSS score was low due to these requirements, the vulnerability demonstrated a real authorization gap.

## Steps to Reproduce
1. Log in with a low-privilege user account
2. Identify the folder ID of another user's folder (e.g., shared organization, or through information disclosure)
3. Send a DELETE request to the vulnerable endpoint with the target's folder_id
4. The folder is deleted despite not belonging to the requester

## Proof of Concept
```
DELETE /public/notebooks/api/contents/<org_uuid>/_internal-s2-stage/<victim_folder_uuid>/folder_name/
Host: backend.singlestore.com
Cookie: session=attacker_session
```

Response: `200 OK` — the victim's folder is deleted.

## Impact
- Low-privilege users can delete other users' folders
- Potential data loss and disruption for affected users
- CWE-639 (Authorization Bypass Through User-Controlled Key)
- The vulnerability operated within the same organization tenant

## Remediation
SingleStore fixed the vulnerability by adding proper ownership validation to the folder deletion endpoint. Before processing any DELETE request, the server now verifies that the authenticated user is the owner of the specified folder. Organization-level access controls were also reviewed.

## References
- https://www.redpacketsecurity.com/hackerone-bugbounty-disclosure-delete-any-folder-for-any-user-within-the-organization-bl-ck/
