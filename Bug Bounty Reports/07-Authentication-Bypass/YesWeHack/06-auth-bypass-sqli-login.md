# Title: Authentication Bypass via SQL Injection in Login

- **Platform**: YesWeHack
- **Program**: European Telecom Provider
- **Severity**: Critical
- **Date**: 2024
- **Researcher**: N/A
- **Bounty**: N/A

## Summary
A critical SQL injection vulnerability was discovered in the login endpoint of a European telecom provider's customer portal. The vulnerability allowed complete authentication bypass, enabling access to any customer account without valid credentials.

## Technical Details
The login endpoint `/login` accepted a username and password via POST parameters. The username field was directly concatenated into a SQL query without proper sanitization or parameterized queries. By injecting SQL into the username field, an attacker could manipulate the authentication query to always return a valid user record.

The vulnerable query was:
```sql
SELECT * FROM users WHERE username = '$username' AND password = '$password'
```

By injecting `' OR '1'='1' -- ` as the username, the query became:
```sql
SELECT * FROM users WHERE username = '' OR '1'='1' -- ' AND password = 'anything'
```

This returned the first user in the database, and the application treated this as a successful login.

## Steps to Reproduce
1. Navigate to the telecom provider's customer portal login page
2. Enter the following in the username field: `' OR '1'='1' -- `
3. Enter any value in the password field
4. Submit the login form
5. Observe that the application authenticates as the first user in the database
6. The account typically belongs to an administrator or a test account

## Proof of Concept
```
POST /login HTTP/1.1
Host: portal.telecom.com
Content-Type: application/x-www-form-urlencoded

username='+OR+'1'%3d'1'++--+&password=anything
```

## Impact
- Complete authentication bypass
- Access to any customer account (by adjusting the injection)
- Access to billing information, call logs, personal data
- Ability to perform account actions on behalf of customers

## Remediation
The telecom provider:
- Implemented parameterized queries for all database interactions
- Conducted a full security audit of all login and database query endpoints
- Deployed a WAF with SQL injection detection rules

## References
- https://www.yeswehack.com/programs (SQL Injection / Authentication Bypass)
