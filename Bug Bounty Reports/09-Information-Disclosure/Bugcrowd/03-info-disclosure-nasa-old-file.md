# Title: Sensitive Information Disclosure - NASA Subdomain Internal .old File

- **Platform**: Bugcrowd
- **Program**: NASA - Vulnerability Disclosure Program
- **Severity**: Low (P5 - Informational)
- **Date**: June 23, 2024
- **Researcher**: Kuldeep_Soni_c1ph3r
- **Bounty**: N/A

## Summary
An information disclosure vulnerability was found on NASA's SOHO project subdomain where an exposed `.old` backup file revealed internal references and system file paths.

## Technical Details
The subdomain `soho.nascom.nasa.gov` had a backup file at `/data/summary/index.html.old` that was left accessible after a system update or migration. This file contained internal references, data formatting details, directory paths, and structural information about the NASA SOHO (Solar and Heliospheric Observatory) project systems.

While the file did not contain highly sensitive data such as credentials or PII, it did reveal enough internal structure to aid an attacker in reconnaissance or chaining attacks with other vulnerabilities.

## Steps to Reproduce
1. Navigate to `https://soho.nascom.nasa.gov/data/summary/index.html.old`
2. Review the contents of the exposed file
3. View the page source to observe internal file path references
4. Note the exposed directory structure and data layout

## Proof of Concept
```
URL: https://soho.nascom.nasa.gov/data/summary/index.html.old

The file contained:
- Internal file path references (/data/archive/, /internal/processing/)
- Data schema and formatting information
- System directory structure
- Legacy code references
```

## Impact
While low severity on its own, this information disclosure could aid attackers in:
- Fingerprinting internal NASA technologies and directory structures
- Understanding legacy system logic or data schemas
- Conducting reconnaissance for further attacks
- Chaining with other vulnerabilities for greater impact

## Remediation
NASA's system owner removed the file from the production server. The recommendation includes regular audits for `.old`, `.bak`, `.swp`, and similar development artifact files in production environments.

## References
- https://bugcrowd.com/disclosures/0c52ff12-28ba-4257-95d6-eae2ba2ec97d/sensitive-information-disclosure
