# Title: CVE-2025-66438 - Server-Side Template Injection in ERPNext Print Format

- **Platform**: GitHub Bug Bounty
- **Program**: Frappe ERPNext
- **Severity**: Critical (CVSS 9.8)
- **Date**: December 15, 2025
- **Researcher**: iamanc
- **Bounty**: N/A

## Summary
A critical SSTI vulnerability exists in Frappe ERPNext through version 15.89.0 in the Print Format rendering mechanism. Although Jinja2 is wrapped in a SandboxedEnvironment, the sandbox exposes sensitive functions like `frappe.db.sql` through `get_safe_globals()`, allowing authenticated attackers with Print Format permissions to execute arbitrary Jinja expressions.

## Technical Details
The vulnerability is in the `frappe.www.printview.get_html_and_style()` API which triggers rendering of the `html` field inside a Print Format document via `frappe.render_template(template, doc)`. The sandbox exposes `frappe.db.sql` and other sensitive functions. An attacker can create a malicious Print Format with injected Jinja expressions to leak database information.

## Steps to Reproduce
1. As authenticated user with Print Format creation permissions, create a new Print Format
2. In the `html` field, inject a Jinja payload: `{{ frappe.db.sql("SELECT VERSION()") }}`
3. Save the malicious Print Format
4. Call `get_html_and_style()` API with a target document (e.g., Supplier or Sales Invoice)
5. Database version information is returned in the rendered output

## Proof of Concept
```
POST /api/method/frappe.www.printview.get_html_and_style HTTP/1.1
Content-Type: application/json

{
  "doc": "Sales Invoice",
  "print_format": "malicious_format"
}

Jinja Payload in Print Format html field:
{{ frappe.db.sql("SELECT table_name FROM information_schema.tables LIMIT 5") }}
```

## Impact
Information disclosure from the database including database version, schema details, and sensitive values. With further exploitation, this could lead to data exfiltration, privilege escalation, and full system compromise.

## Remediation
Restrict the functions exposed through `get_safe_globals()`. Remove `frappe.db.sql` and other sensitive functions from the sandbox globals. Implement proper input validation on Print Format templates.

## References
- https://nvd.nist.gov/vuln/detail/CVE-2025-66438
- https://github.com/advisories/GHSA-5x94-7mhw-9ff6
- https://iamanc.github.io/post/erpnext-ssti-bug-5
