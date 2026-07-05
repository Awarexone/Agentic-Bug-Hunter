# Title: A Journey of Limited Path Traversal To RCE With $40,000 Bounty

- **Platform**: Medium
- **Program**: Private Bug Bounty Program
- **Severity**: Critical
- **Date**: 2025-01-16
- **Researcher**: HX007 & Orwa Atyat
- **Bounty**: $40,000

## Summary
A limited path traversal vulnerability in an admin panel's download functionality was escalated to full remote code execution (RCE). The chain involved log poisoning, credential discovery, and a Groovy console, earning a $40,000 bounty.

## Technical Details
Fuzzing `http://admin.target.com:8443/admin/` revealed a `/download` endpoint that accepted a `filename` parameter. Files could only be downloaded from within the `/admin/` directory (limited path traversal). Further exploration of `/WEB-INF/web.xml` uncovered three endpoints, including `/incident-report` which downloaded a live log file containing admin credentials with an MD5-hashed password.

After cracking the password, the researcher logged into the admin panel and found a Groovy console in `export_step2.xhtml`. Commands executed via the Groovy console had no visible output, but visiting `/incident-report` generated a new log file containing the command output.

## Steps to Reproduce
1. Fuzz the admin panel to discover the `/download` endpoint
2. Use limited path traversal to read `/WEB-INF/web.xml` and discover other endpoints
3. Access `/incident-report` to download live logs containing credentials
4. Crack the password hash and log into the admin panel
5. Execute commands via the Groovy console
6. Retrieve command output by downloading the latest incident report log

## Proof of Concept
```
# Step 1: Read /WEB-INF/web.xml via limited path traversal
GET /admin/download?filename=/WEB-INF/web.xml HTTP/1.1

# Step 2: Access incident report to get logs
GET /admin/incident-report HTTP/1.1

# Step 3: Login with discovered credentials
POST /admin/login HTTP/1.1
username=admin&password=cracked_password

# Step 4: Execute command via Groovy console
print "cat /etc/passwd".execute().text

# Step 5: Retrieve output from logs
GET /admin/incident-report HTTP/1.1
```

## Impact
- Full remote code execution on the server
- Access to sensitive data and internal network pivoting
- Complete server compromise

## Remediation
The program fixed the path traversal by implementing proper input validation on the filename parameter. The Groovy console was removed from production, and credential logging was eliminated.

## References
- https://medium.com/@HX007/a-journey-of-limited-path-traversal-to-rce-with-40-000-bounty-fc63c89576ea
