# Title: SQL Injection in All In One Redirection WordPress Plugin

- **Platform**: OpenBugBounty
- **Program**: All In One Redirection Plugin (WordPress)
- **Severity**: Critical
- **Date**: 2023-07-10
- **Researcher**: WPScan
- **Bounty**: N/A (Coordinated Disclosure)

## Summary
A SQL injection vulnerability was discovered in the All In One Redirection WordPress plugin before version 2.2.0. The plugin failed to properly sanitize and escape multiple parameters before using them in SQL statements, allowing high-privilege users such as admins to extract sensitive database information.

## Technical Details
The vulnerability (CVE-2023-2493) existed in the plugin's handling of redirection rules. Multiple parameters passed to SQL queries were not properly sanitized or escaped. This allowed an authenticated attacker with admin-level access to perform SQL injection attacks, potentially extracting the WordPress database contents including user credentials and sensitive site data.

## Steps to Reproduce
1. Install a vulnerable version of the All In One Redirection plugin (< 2.2.0)
2. Log in as an administrator
3. Navigate to the plugin's settings page
4. Inject a malicious SQL payload into an unsanitized parameter
5. Observe that the SQL query executes the injected code

## Proof of Concept
```
POST /wp-admin/admin.php?page=all-in-one-redirection
Host: target-site.com
Cookie: [admin cookie]

redirection_url=' UNION SELECT user_pass FROM wp_users--
```

## Impact
- Extraction of password hashes from the WordPress database
- Potential privilege escalation to super admin
- Modification or deletion of database contents
- Complete compromise of the WordPress installation
- Data exfiltration of all site content and user data

## Remediation
- Upgrade to version 2.2.0 or later
- Use prepared statements with parameterized queries
- Implement proper input validation and escaping
- Apply principle of least privilege for plugin capabilities

## References
- https://www.openbugbounty.org/
- https://vuldb.com/vuln/233395
- CVE-2023-2493
