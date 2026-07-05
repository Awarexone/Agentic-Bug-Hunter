# Title: SQL Injection in Formidable Pro WordPress Plugin

- **Platform**: HackerOne
- **Program**: Formidable Pro (WordPress Plugin)
- **Severity**: Critical
- **Date**: 2017-09-26
- **Researcher**: Redacted
- **Bounty**: Undisclosed

## Summary
A previously unknown SQL injection vulnerability was discovered in the Formidable Pro WordPress plugin. The vulnerability existed in the plugin's database query handling, allowing an attacker to execute arbitrary SQL queries against the WordPress database.

## Technical Details
Formidable Pro is a premium WordPress form builder plugin used by thousands of websites. The vulnerability was in how the plugin handled form data submissions and retrievals. User-supplied input from form fields was directly concatenated into SQL queries without proper sanitization or parameterization.

The vulnerable code lacked prepared statements for certain dynamic queries. Instead of using `$wpdb->prepare()` or similar safe methods, the plugin directly interpolated user values into SQL query strings. This allowed an attacker to inject SQL commands via form field values.

The exact vulnerable function was in the plugin's data model layer, where field values from submitted forms were used to build SELECT and UPDATE queries. The plugin failed to escape or parameterize the values before database operations.

## Steps to Reproduce
1. Install the Formidable Pro plugin on a WordPress site
2. Create a form with various field types (text, email, etc.)
3. Submit the form with SQL injection payload in a text field
4. Observe that the payload is processed by the database without escaping
5. Use SQLMap or manual techniques to extract data from the WordPress database

## Proof of Concept
The vulnerability could be triggered by submitting form data with SQL injection payloads in unprotected fields:
```
POST /wp-admin/admin-ajax.php
action=frm_forms_preview
form_id=1
item_meta[0]=test' OR 1=1 --
```

The injected SQL would be executed in the context of the WordPress database.

## Impact
- Extraction of the entire WordPress database including user credentials
- Insertion of malicious admin users
- Modification of site content
- Complete WordPress site takeover
- Since the plugin is used on thousands of sites, the potential impact was widespread

## Remediation
The Formidable Pro developers fixed the vulnerability by implementing proper parameterized queries throughout the plugin. All dynamic queries were converted to use `$wpdb->prepare()` with proper placeholder-based parameter binding. Input validation was also strengthened.

## References
- https://hackerone.com/reports/273946
