#!/usr/bin/env python3
"""
HackerOne Report Generator
Generates formatted bug bounty reports from scan findings.

Usage:
    python3 report_generator.py <findings_dir>
    python3 report_generator.py --finding <finding_file> --type <vuln_type>
    python3 report_generator.py --manual --type xss --url <url> --param <param>
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# Severity mappings
SEVERITY_MAP = {
    "critical": {"cvss_range": "9.0-10.0", "color": "CRITICAL"},
    "high": {"cvss_range": "7.0-8.9", "color": "HIGH"},
    "medium": {"cvss_range": "4.0-6.9", "color": "MEDIUM"},
    "low": {"cvss_range": "0.1-3.9", "color": "LOW"},
    "info": {"cvss_range": "0.0", "color": "INFO"},
}

# Report templates by vulnerability type
VULN_TEMPLATES = {
    "xss": {
        "title": "Cross-Site Scripting (XSS) on {domain}",
        "severity": "medium",
        "impact": (
            "An attacker can execute arbitrary JavaScript in the context of the victim's browser session. "
            "This can lead to session hijacking, credential theft, defacement, or redirection to malicious sites. "
            "If the affected user is an administrator, this could lead to full account takeover."
        ),
        "remediation": (
            "1. Implement proper output encoding/escaping for all user-supplied input\n"
            "2. Use Content-Security-Policy (CSP) headers to restrict script execution\n"
            "3. Enable HttpOnly and Secure flags on session cookies\n"
            "4. Use a templating engine that auto-escapes by default"
        ),
        "cwe": "CWE-79",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ]
    },
    "takeover": {
        "title": "Subdomain Takeover on {domain}",
        "severity": "high",
        "impact": (
            "The subdomain points to a third-party service that is no longer claimed. "
            "An attacker can claim this service and serve arbitrary content on the subdomain. "
            "This enables phishing attacks, cookie theft (if parent domain cookies are scoped broadly), "
            "and can bypass Content-Security-Policy restrictions."
        ),
        "remediation": (
            "1. Remove the dangling DNS record (CNAME/A) pointing to the unclaimed service\n"
            "2. If the service is still needed, reclaim it on the third-party platform\n"
            "3. Audit all DNS records for similar dangling references\n"
            "4. Implement monitoring for subdomain takeover conditions"
        ),
        "cwe": "CWE-284",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
            "https://github.com/EdOverflow/can-i-take-over-xyz"
        ]
    },
    "cors": {
        "title": "CORS Misconfiguration on {domain}",
        "severity": "medium",
        "impact": (
            "The application reflects arbitrary origins in the Access-Control-Allow-Origin header "
            "with Access-Control-Allow-Credentials: true. This allows an attacker to read sensitive "
            "data from authenticated API responses via a malicious website."
        ),
        "remediation": (
            "1. Implement a strict whitelist of allowed origins\n"
            "2. Never reflect the Origin header value directly\n"
            "3. Avoid using Access-Control-Allow-Credentials: true with wildcard origins\n"
            "4. Validate the Origin header against a known list of trusted domains"
        ),
        "cwe": "CWE-942",
        "references": [
            "https://portswigger.net/web-security/cors",
            "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"
        ]
    },
    "ssrf": {
        "title": "Server-Side Request Forgery (SSRF) on {domain}",
        "severity": "high",
        "impact": (
            "An attacker can make the server perform requests to arbitrary internal or external resources. "
            "This can be used to scan internal networks, access cloud metadata endpoints (e.g., AWS IMDSv1 at 169.254.169.254), "
            "read internal services, or bypass firewall restrictions."
        ),
        "remediation": (
            "1. Implement a strict allowlist of permitted URLs/domains\n"
            "2. Block requests to internal/private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x)\n"
            "3. Disable unnecessary URL schemes (file://, gopher://, dict://)\n"
            "4. Use a dedicated egress proxy for outbound requests\n"
            "5. Enable IMDSv2 on cloud instances to prevent metadata access"
        ),
        "cwe": "CWE-918",
        "references": [
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://portswigger.net/web-security/ssrf"
        ]
    },
    "redirect": {
        "title": "Open Redirect on {domain}",
        "severity": "low",
        "impact": (
            "An attacker can craft a URL that redirects victims to a malicious website. "
            "This can be used for phishing (the URL appears to come from a trusted domain), "
            "OAuth token theft, or as a component in chained attacks."
        ),
        "remediation": (
            "1. Avoid user-controlled redirect destinations\n"
            "2. If redirects are necessary, use a whitelist of allowed destinations\n"
            "3. Use relative paths instead of full URLs for internal redirects\n"
            "4. Display a warning page before redirecting to external domains"
        ),
        "cwe": "CWE-601",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            "https://portswigger.net/kb/issues/00500100_open-redirection-reflected"
        ]
    },
    "exposure": {
        "title": "Sensitive Data Exposure on {domain}",
        "severity": "medium",
        "impact": (
            "Sensitive files or information are publicly accessible. Depending on the exposed data, "
            "this could reveal source code (.git), environment variables (.env), database credentials, "
            "API keys, or internal configuration that aids further attacks."
        ),
        "remediation": (
            "1. Remove or restrict access to exposed sensitive files\n"
            "2. Configure web server to deny access to hidden files/directories (.*)\n"
            "3. Review deployment process to prevent accidental file exposure\n"
            "4. Rotate any credentials that may have been exposed\n"
            "5. Add these paths to .gitignore and web server deny rules"
        ),
        "cwe": "CWE-200",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"
        ]
    },
    "cve": {
        "title": "Known CVE ({cve_id}) on {domain}",
        "severity": "high",
        "impact": (
            "The application is running a version of software with a known vulnerability. "
            "Impact depends on the specific CVE — see references for details."
        ),
        "remediation": (
            "1. Update the affected software to the latest patched version\n"
            "2. If immediate patching is not possible, apply vendor-recommended mitigations\n"
            "3. Monitor for exploitation attempts via WAF/IDS rules"
        ),
        "cwe": "CWE-1035",
        "references": []
    },
    "misconfig": {
        "title": "Security Misconfiguration on {domain}",
        "severity": "medium",
        "impact": (
            "The application or server has a security misconfiguration that could be exploited. "
            "This may include missing security headers, verbose error messages, default configurations, "
            "or unnecessary features/services enabled."
        ),
        "remediation": (
            "1. Review and harden server/application configuration\n"
            "2. Implement all recommended security headers\n"
            "3. Disable verbose error messages in production\n"
            "4. Remove default/sample pages and credentials\n"
            "5. Follow vendor security hardening guides"
        ),
        "cwe": "CWE-16",
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        ]
    },
    "idor": {
        "title": "Insecure Direct Object Reference (IDOR) on {domain}",
        "severity": "high",
        "impact": (
            "An attacker can access or modify resources belonging to other users by manipulating "
            "object references (IDs, filenames, keys) in API requests. This can lead to unauthorized "
            "access to user data, account takeover, or data manipulation."
        ),
        "remediation": (
            "1. Implement proper authorization checks on every resource access\n"
            "2. Use indirect references (UUIDs) instead of sequential IDs\n"
            "3. Validate that the authenticated user owns the requested resource\n"
            "4. Apply the principle of least privilege for all API endpoints"
        ),
        "cwe": "CWE-639",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
            "https://portswigger.net/web-security/access-control/idor"
        ]
    },
    "auth_bypass": {
        "title": "Authentication/Authorization Bypass on {domain}",
        "severity": "critical",
        "impact": (
            "An attacker can bypass authentication or authorization controls to access protected "
            "resources or functionality. This may allow unauthenticated access to admin panels, "
            "API endpoints, or user data without proper credentials."
        ),
        "remediation": (
            "1. Enforce authentication on all protected endpoints\n"
            "2. Implement server-side authorization checks (not client-side)\n"
            "3. Use a centralized authentication/authorization middleware\n"
            "4. Deny by default — explicitly allow access only where needed\n"
            "5. Test all HTTP methods (GET, POST, PUT, DELETE) for each endpoint"
        ),
        "cwe": "CWE-287",
        "references": [
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        ]
    },
    "info_disclosure": {
        "title": "Information Disclosure on {domain}",
        "severity": "high",
        "impact": (
            "Sensitive internal information is exposed to unauthenticated users. This may include "
            "production configuration, internal service URLs, API tokens, SSO endpoints, employee data, "
            "or infrastructure details that aid further targeted attacks."
        ),
        "remediation": (
            "1. Remove or restrict access to configuration files (env.js, app_env.js)\n"
            "2. Move sensitive config to server-side environment variables\n"
            "3. Strip internal headers (X-Backend-Host, X-Powered-By) from responses\n"
            "4. Remove developer comments from production HTML\n"
            "5. Rotate any exposed credentials or tokens"
        ),
        "cwe": "CWE-200",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
            "https://cwe.mitre.org/data/definitions/497.html"
        ]
    }
}


def parse_nuclei_line(line):
    """Parse a nuclei output line into structured data."""
    # Nuclei format: [template-id] [protocol] [severity] url [extra-info]
    # Example: [git-config] [http] [medium] https://example.com/.git/config
    parts = line.strip()
    if not parts:
        return None

    result = {
        "raw": parts,
        "template_id": "",
        "severity": "medium",
        "url": "",
        "extra": ""
    }

    # Extract bracketed fields
    brackets = re.findall(r'\[([^\]]+)\]', parts)
    if len(brackets) >= 3:
        result["template_id"] = brackets[0]
        result["severity"] = brackets[2].lower()
    if len(brackets) >= 1:
        result["template_id"] = brackets[0]

    # Extract URL
    url_match = re.search(r'(https?://\S+)', parts)
    if url_match:
        result["url"] = url_match.group(1)

    return result


def parse_dalfox_line(line):
    """Parse a dalfox output line."""
    parts = line.strip()
    if not parts:
        return None

    result = {
        "raw": parts,
        "url": "",
        "payload": "",
        "severity": "medium"
    }

    url_match = re.search(r'(https?://\S+)', parts)
    if url_match:
        result["url"] = url_match.group(1)

    if "POC" in parts or "Verified" in parts:
        result["severity"] = "high"

    return result


def extract_domain(url):
    """Extract domain from URL."""
    match = re.search(r'https?://([^/]+)', url)
    return match.group(1) if match else "unknown"


def generate_report(finding, vuln_type, target_name=None):
    """Generate a HackerOne-formatted report for a finding."""
    template = VULN_TEMPLATES.get(vuln_type, VULN_TEMPLATES["misconfig"])

    url = finding.get("url", "N/A")
    domain = extract_domain(url) if url != "N/A" else (target_name or "unknown")

    # Build title
    title = template["title"].format(
        domain=domain,
        cve_id=finding.get("template_id", "Unknown CVE")
    )

    severity = finding.get("severity", template["severity"])
    severity_info = SEVERITY_MAP.get(severity, SEVERITY_MAP["medium"])

    report = f"""# {title}

## Severity
**{severity.upper()}** (CVSS: {severity_info['cvss_range']})

## Vulnerability Type
{template.get('cwe', 'N/A')} — {vuln_type.upper()}

## Summary
A {vuln_type} vulnerability was discovered on `{domain}`. {template['impact'][:200]}...

## Affected URL
```
{url}
```

## Steps to Reproduce
1. Navigate to the following URL:
   ```
   {url}
   ```
2. Observe the vulnerable behavior as described below.

## Evidence / Proof of Concept
**Scanner Output:**
```
{finding.get('raw', 'N/A')}
```

**Template/Check:** `{finding.get('template_id', 'manual')}`

## Impact
{template['impact']}

## Remediation
{template['remediation']}

## References
"""
    for ref in template.get("references", []):
        report += f"- {ref}\n"

    if finding.get("template_id", "").startswith("CVE-"):
        report += f"- https://nvd.nist.gov/vuln/detail/{finding['template_id']}\n"

    report += f"""
---
*Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
*Scanner: Automated Bug Bounty Pipeline*
"""
    return report, title


def process_findings_dir(findings_dir):
    """Process all findings in a directory and generate reports."""
    target_name = os.path.basename(findings_dir)
    report_dir = os.path.join(REPORTS_DIR, target_name)
    os.makedirs(report_dir, exist_ok=True)

    # Map finding directories to vuln types
    dir_type_map = {
        "xss": "xss",
        "takeover": "takeover",
        "misconfig": "misconfig",
        "exposure": "exposure",
        "ssrf": "ssrf",
        "cves": "cve",
        "redirects": "redirect",
        "idor": "idor",
        "auth_bypass": "auth_bypass",
    }

    total_reports = 0
    report_index = []

    for subdir, vuln_type in dir_type_map.items():
        subdir_path = os.path.join(findings_dir, subdir)
        if not os.path.isdir(subdir_path):
            continue

        for filename in os.listdir(subdir_path):
            filepath = os.path.join(subdir_path, filename)
            if not os.path.isfile(filepath) or not filename.endswith(".txt"):
                continue
            if "manual" in filename:
                continue  # Skip manual review files

            with open(filepath) as f:
                lines = f.readlines()

            for i, line in enumerate(lines):
                line = line.strip()
                if not line:
                    continue

                # Parse based on source
                if "dalfox" in filename:
                    finding = parse_dalfox_line(line)
                else:
                    finding = parse_nuclei_line(line)

                if not finding or not finding.get("url"):
                    continue

                # Generate report
                report_content, title = generate_report(finding, vuln_type, target_name)

                # Save report
                report_id = f"{vuln_type}_{i+1:03d}"
                report_file = os.path.join(report_dir, f"{report_id}.md")
                with open(report_file, "w") as rf:
                    rf.write(report_content)

                total_reports += 1
                report_index.append({
                    "id": report_id,
                    "title": title,
                    "severity": finding.get("severity", "medium"),
                    "url": finding.get("url", ""),
                    "file": report_file,
                    "type": vuln_type
                })

    # Save report index
    if report_index:
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        report_index.sort(key=lambda x: severity_order.get(x["severity"], 5))

        index_file = os.path.join(report_dir, "INDEX.json")
        with open(index_file, "w") as f:
            json.dump({
                "target": target_name,
                "generated_at": datetime.now().isoformat(),
                "total_reports": total_reports,
                "reports": report_index
            }, f, indent=2)

        # Also generate a summary markdown
        summary_file = os.path.join(report_dir, "SUMMARY.md")
        with open(summary_file, "w") as f:
            f.write(f"# Bug Bounty Report Summary — {target_name}\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"Total findings: {total_reports}\n\n")
            f.write("| # | Severity | Type | Title | URL |\n")
            f.write("|---|----------|------|-------|-----|\n")
            for r in report_index:
                f.write(f"| {r['id']} | {r['severity'].upper()} | {r['type']} | {r['title'][:50]} | {r['url'][:60]} |\n")

    return total_reports, report_index


def create_manual_report(vuln_type, url, param=None, evidence=None):
    """Create a report from manual findings."""
    domain = extract_domain(url)
    target_name = domain.replace(".", "_")
    report_dir = os.path.join(REPORTS_DIR, target_name)
    os.makedirs(report_dir, exist_ok=True)

    finding = {
        "raw": evidence or f"Manual finding: {vuln_type} on {url}",
        "url": url,
        "template_id": "manual",
        "severity": VULN_TEMPLATES.get(vuln_type, {}).get("severity", "medium"),
    }

    if param:
        finding["raw"] += f"\nParameter: {param}"

    report_content, title = generate_report(finding, vuln_type, target_name)

    report_id = f"{vuln_type}_manual_{datetime.now().strftime('%H%M%S')}"
    report_file = os.path.join(report_dir, f"{report_id}.md")
    with open(report_file, "w") as f:
        f.write(report_content)

    print(f"[+] Report saved: {report_file}")
    return report_file


def attach_poc_images(report_file, image_paths):
    """Append PoC image references to an existing report."""
    import shutil

    report_dir = os.path.dirname(report_file)
    poc_dir = os.path.join(report_dir, "poc_screenshots")
    os.makedirs(poc_dir, exist_ok=True)

    image_section = "\n\n## PoC Screenshots\n\n"
    for i, img_path in enumerate(image_paths, 1):
        if os.path.exists(img_path):
            filename = os.path.basename(img_path)
            dest = os.path.join(poc_dir, filename)
            if os.path.abspath(img_path) != os.path.abspath(dest):
                shutil.copy2(img_path, dest)
            image_section += f"### Screenshot {i}: {filename}\n"
            image_section += f"![PoC {i}](poc_screenshots/{filename})\n\n"
            print(f"[+] Attached PoC image: {filename}")
        else:
            print(f"[!] Image not found: {img_path}")

    with open(report_file, "a") as f:
        f.write(image_section)

    print(f"[+] PoC images attached to {report_file}")


def main():
    parser = argparse.ArgumentParser(description="Bug Bounty Report Generator")
    parser.add_argument("findings_dir", nargs="?", help="Directory containing scan findings")
    parser.add_argument("--manual", action="store_true", help="Create manual report")
    parser.add_argument("--type", type=str, help="Vulnerability type (xss, ssrf, takeover, etc.)")
    parser.add_argument("--url", type=str, help="Affected URL (for manual reports)")
    parser.add_argument("--param", type=str, help="Affected parameter (for manual reports)")
    parser.add_argument("--evidence", type=str, help="Evidence/PoC text (for manual reports)")
    parser.add_argument("--poc-images", type=str, nargs="+", help="PoC screenshot PNG files to attach")
    args = parser.parse_args()

    print("=============================================")
    print("  Bug Bounty Report Generator")
    print("=============================================")

    if args.manual:
        if not args.type or not args.url:
            print("[-] Manual mode requires --type and --url")
            print("    Types: xss, ssrf, takeover, cors, redirect, exposure, cve, misconfig, idor, auth_bypass, info_disclosure")
            sys.exit(1)
        report_file = create_manual_report(args.type, args.url, args.param, args.evidence)
        # Attach PoC images if provided
        if args.poc_images and report_file:
            attach_poc_images(report_file, args.poc_images)
        return

    if not args.findings_dir:
        print("[-] Please provide a findings directory or use --manual mode")
        print("    Usage: python3 report_generator.py <findings_dir>")
        print("    Usage: python3 report_generator.py --manual --type xss --url https://example.com/search?q=test")
        sys.exit(1)

    if not os.path.isdir(args.findings_dir):
        print(f"[-] Not a directory: {args.findings_dir}")
        sys.exit(1)

    total, index = process_findings_dir(args.findings_dir)

    print(f"\n[+] Generated {total} reports")
    if index:
        print("\nFindings by severity:")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = sum(1 for r in index if r["severity"] == sev)
            if count > 0:
                print(f"  {sev.upper()}: {count}")

        target_name = os.path.basename(args.findings_dir)
        print(f"\nReports saved to: {REPORTS_DIR}/{target_name}/")
        print(f"Summary: {REPORTS_DIR}/{target_name}/SUMMARY.md")
    else:
        print("\n[*] No reportable findings to generate reports for.")


if __name__ == "__main__":
    main()
