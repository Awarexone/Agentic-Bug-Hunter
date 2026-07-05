# Title: Sensitive Information Disclosure via Path Traversal on viewsonic.com

- **Platform**: OpenBugBounty
- **Program**: viewsonic.com
- **Severity**: Medium
- **Date**: 2024-08-20
- **Researcher**: KhanJanny
- **Bounty**: N/A (Coordinated Disclosure)

## Summary
An information disclosure vulnerability was discovered on viewsonic.com where internal server paths and sensitive configuration details were exposed through improper error handling and directory listing.

## Technical Details
The web server was configured to display verbose error messages containing full system paths. Additionally, directory listing was enabled on certain directories, exposing the internal structure of the application and potentially sensitive configuration files.

## Steps to Reproduce
1. Access a non-existent path on the target domain
2. Observe the verbose error message containing full server paths
3. Navigate to sensitive directories to discover exposed file structures

## Proof of Concept
```
GET /nonexistent-page HTTP/1.1
Host: www.viewsonic.com

Response includes full path disclosure:
Warning: include(/var/www/html/includes/config.php)...
```

## Impact
An attacker could:
- Map the internal directory structure of the web application
- Identify technology stack and versions in use
- Discover configuration files and potential entry points for further attacks
- Use disclosed information to craft more targeted attacks

## Remediation
- Disable detailed error messages in production
- Disable directory listing on web servers
- Implement proper access controls on directories
- Use custom error pages that do not reveal system information

## References
- https://www.openbugbounty.org/reports/844356/
