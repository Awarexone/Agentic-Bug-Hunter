# Title: Four SQL Injection Vulnerabilities in a CRM Platform - $2,000 Bounty

- **Platform**: HackerOne
- **Program**: Private CRM Program
- **Severity**: High
- **Date**: 2024-09-10
- **Researcher**: JAI NIRESH J
- **Bounty**: $2,000 ($500 each)

## Summary
A time-based SQL injection vulnerability was discovered in a CRM platform through analysis of JavaScript files. The `executedSql` parameter in the request body was reflecting SQL queries in responses, leading to the discovery of four vulnerable endpoints. The researcher reported them separately and was rewarded $500 each.

## Technical Details
The researcher analyzed the CRM platform's JavaScript files searching for the term "query" in the Burp Suite global search. This revealed requests with a body containing an `executedSql` parameter that displayed SQL queries in the response. The queries were of the form:
```sql
select * from load_div where user_org = '12231' and ...
```

While error-based extraction was prevented by organizational access controls, the researcher discovered time-based SQL injection worked using MySQL's `BENCHMARK` function:
```
{ query: "')+select+benchmark(1000000, md5('a'));# -- " }
```

The `BENCHMARK` function repeatedly executes an expression, causing measurable delays. By increasing the iteration count, the delay increased proportionally.

## Steps to Reproduce
1. Browse the CRM platform and examine JavaScript files for API endpoints
2. Search for "query" in intercepted requests
3. Find endpoints with `executedSql` in the request body
4. Inject time-based payload: `')+select+benchmark(1000000, md5('a'));# -- `
5. Observe response delay increasing with benchmark iterations
6. The same vulnerability existed across 4 different endpoints

## Proof of Concept
```
POST /api/endpoint HTTP/1.1
Host: crm.target.com
Content-Type: application/json

{ "query": "')+select+benchmark(5000000, md5('a'));# -- " }
```

Response time increased from ~200ms to ~15 seconds depending on the benchmark count, confirming SQL injection.

## Impact
- Extraction of data via time-based inference
- Potential access to all CRM data including contacts, deals, and communications
- The `executedSql` parameter was used across multiple endpoints
- Data exfiltration from the database

## Remediation
The program fixed all four endpoints by implementing parameterized queries. User input was no longer concatenated into SQL statements. The `executedSql` parameter was either removed or properly parameterized.

## References
- https://medium.com/@nireshpandian19/sql-injections-and-the-cute-2000-bounty-2d18441ee0e3
