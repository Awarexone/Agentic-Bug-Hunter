#!/usr/bin/env python3
"""
report_generator.py — Bug Bounty & VAPT Report Generator
Produces a Burp Suite-style HTML report + Markdown summary from scan findings.
Suitable for HackerOne, Bugcrowd, Intigriti, and professional VAPT engagements.

Usage:
    python3 report_generator.py <findings_dir>
    python3 report_generator.py <findings_dir> --client "Target Corp" --consultant "J. Smith"
    python3 report_generator.py <findings_dir> --title "Web Application Security Assessment"
"""

import argparse
import os
import re
import sys
from datetime import datetime

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# ── Vulnerability templates ────────────────────────────────────────────────────
VULN_TEMPLATES = {
    "sqli": {
        "title": "SQL Injection on {host}",
        "severity": "critical", "cvss": "9.8", "cwe": "CWE-89",
        "impact": (
            "An attacker can read, modify, or delete all data in the database. "
            "Depending on the database server configuration, this may escalate to "
            "remote code execution via xp_cmdshell, UDF, or outfile techniques."
        ),
        "remediation": (
            "Use parameterized queries or prepared statements for all database interactions. "
            "Apply input validation and a WAF as defence-in-depth."
        ),
        "references": [
            ("OWASP SQL Injection", "https://owasp.org/www-community/attacks/SQL_Injection"),
            ("Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"),
        ],
    },
    "xss": {
        "title": "Cross-Site Scripting (XSS) on {host}",
        "severity": "medium", "cvss": "6.1", "cwe": "CWE-79",
        "impact": (
            "An attacker can execute arbitrary JavaScript in the victim's browser session, "
            "enabling session hijacking, credential theft, or redirection to a malicious site."
        ),
        "remediation": (
            "Apply context-aware output encoding for all user-supplied data. "
            "Implement a strict Content-Security-Policy header. "
            "Set HttpOnly and Secure flags on session cookies."
        ),
        "references": [
            ("OWASP XSS", "https://owasp.org/www-community/attacks/xss/"),
            ("XSS Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
        ],
    },
    "ssti": {
        "title": "Server-Side Template Injection (SSTI) on {host}",
        "severity": "high", "cvss": "8.8", "cwe": "CWE-1336",
        "impact": (
            "An attacker can inject malicious template directives evaluated server-side. "
            "Depending on the engine (Jinja2, Freemarker, Thymeleaf, Twig), this typically "
            "leads to remote code execution."
        ),
        "remediation": (
            "Never pass user-controlled input directly to a template engine. "
            "Use sandboxed execution environments. "
            "Reject inputs containing template syntax characters."
        ),
        "references": [
            ("PortSwigger SSTI", "https://portswigger.net/web-security/server-side-template-injection"),
        ],
    },
    "upload": {
        "title": "Unrestricted File Upload / Remote Code Execution on {host}",
        "severity": "critical", "cvss": "9.8", "cwe": "CWE-434",
        "impact": (
            "An attacker can upload a malicious file and execute arbitrary commands "
            "on the server, leading to full system compromise."
        ),
        "remediation": (
            "Restrict allowed file types using an allowlist. Rename uploaded files server-side. "
            "Store uploads outside the web root and serve via a separate static domain."
        ),
        "references": [
            ("OWASP File Upload Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"),
        ],
    },
    "rce": {
        "title": "Remote Code Execution on {host}",
        "severity": "critical", "cvss": "9.8", "cwe": "CWE-78",
        "impact": (
            "An attacker can execute arbitrary OS commands on the server, "
            "gaining full control of the system and potentially the internal network."
        ),
        "remediation": (
            "Apply the vendor patch immediately. Disable unnecessary features. "
            "Implement network segmentation and egress filtering."
        ),
        "references": [
            ("OWASP OS Command Injection", "https://owasp.org/www-community/attacks/Command_Injection"),
        ],
    },
    "lfi": {
        "title": "Local File Inclusion (LFI) on {host}",
        "severity": "high", "cvss": "7.5", "cwe": "CWE-22",
        "impact": "An attacker can read sensitive server files including /etc/passwd, config files, and SSH keys.",
        "remediation": (
            "Use an allowlist for any file path derived from user input. "
            "Never pass raw user values to filesystem functions."
        ),
        "references": [
            ("OWASP Path Traversal", "https://owasp.org/www-community/attacks/Path_Traversal"),
        ],
    },
    "idor": {
        "title": "Insecure Direct Object Reference (IDOR) on {host}",
        "severity": "high", "cvss": "8.1", "cwe": "CWE-639",
        "impact": "An attacker can access or modify data belonging to other users by manipulating object identifiers.",
        "remediation": "Implement server-side authorisation checks on every request. Use indirect references (GUIDs) and verify ownership.",
        "references": [
            ("OWASP IDOR Testing", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"),
        ],
    },
    "ssrf": {
        "title": "Server-Side Request Forgery (SSRF) on {host}",
        "severity": "high", "cvss": "8.6", "cwe": "CWE-918",
        "impact": "An attacker can make the server issue requests to internal services, cloud metadata endpoints, or restricted systems.",
        "remediation": "Allowlist outbound destinations. Block RFC-1918 and link-local ranges. Disable redirects in server-side HTTP clients.",
        "references": [
            ("OWASP SSRF", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"),
        ],
    },
    "cors": {
        "title": "CORS Misconfiguration on {host}",
        "severity": "medium", "cvss": "6.5", "cwe": "CWE-942",
        "impact": "The server reflects arbitrary Origin headers with credentials, allowing cross-origin reads of authenticated API responses.",
        "remediation": "Implement a strict Origin allowlist. Never reflect the Origin header directly. Avoid wildcard origins with credentials.",
        "references": [
            ("PortSwigger CORS", "https://portswigger.net/web-security/cors"),
        ],
    },
    "takeover": {
        "title": "Subdomain Takeover on {host}",
        "severity": "high", "cvss": "7.5", "cwe": "CWE-284",
        "impact": "A dangling DNS record points to an unclaimed service. An attacker can claim it and serve malicious content on the subdomain.",
        "remediation": "Remove dangling DNS records. Audit all CNAME records. Implement DNS monitoring.",
        "references": [
            ("HackTricks Subdomain Takeover", "https://book.hacktricks.xyz/pentesting-web/domain-subdomain-takeover"),
        ],
    },
    "exposure": {
        "title": "Sensitive Data Exposure on {host}",
        "severity": "high", "cvss": "7.5", "cwe": "CWE-200",
        "impact": "Sensitive information (credentials, API keys, PII) is exposed without authentication.",
        "remediation": "Remove exposed secrets and rotate all credentials immediately. Add secret scanning to CI/CD.",
        "references": [
            ("OWASP Cryptographic Failures", "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
        ],
    },
    "cves": {
        "title": "Known CVE Vulnerability on {host}",
        "severity": "critical", "cvss": "9.0", "cwe": "CWE-1035",
        "impact": "A publicly known vulnerability with an available exploit was identified. May lead to RCE, data breach, or service disruption.",
        "remediation": "Apply the vendor patch or upgrade to a non-vulnerable version immediately. Apply compensating controls if patching is delayed.",
        "references": [
            ("NVD", "https://nvd.nist.gov/"),
        ],
    },
    "misconfig": {
        "title": "Security Misconfiguration on {host}",
        "severity": "medium", "cvss": "5.3", "cwe": "CWE-16",
        "impact": "The application or server is insecurely configured, exposing sensitive information or additional attack vectors.",
        "remediation": "Follow CIS hardening benchmarks. Disable default credentials, debug endpoints, and unnecessary services.",
        "references": [
            ("OWASP Security Misconfiguration", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
        ],
    },
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLOR = {
    "critical": "#dc3545",
    "high":     "#fd7e14",
    "medium":   "#e6c229",
    "low":      "#17a2b8",
    "info":     "#6c757d",
}
CVSS_DEFAULT = {"critical": "9.0", "high": "7.5", "medium": "5.0", "low": "2.5", "info": "0.0"}
SUBDIR_VTYPE = {
    "sqli": "sqli", "xss": "xss", "ssti": "ssti", "upload": "upload",
    "rce": "rce", "lfi": "lfi", "idor": "idor", "ssrf": "ssrf",
    "cors": "cors", "takeover": "takeover", "exposure": "exposure",
    "cves": "cves", "cloud": "misconfig", "metasploit": "rce",
    "misconfig": "misconfig",
}


# ── Parsing ────────────────────────────────────────────────────────────────────

def parse_custom_line(line: str, default_vtype: str = "misconfig") -> dict:
    sev = "medium"
    if any(k in line for k in ("SQLI-POC-VERIFIED", "RCE-POC", "CRITICAL", "CONFIRMED")):
        sev = "critical"
    elif "HIGH" in line:
        sev = "high"
    elif "LOW" in line or "INFO" in line:
        sev = "low"
    url = "N/A"
    m = re.search(r'https?://\S+', line)
    if m:
        url = m.group(0).rstrip(".,;)")
    tags = re.findall(r'\[([^\]]+)\]', line)
    return {"raw": line, "url": url, "severity": sev,
            "template_id": tags[0] if tags else default_vtype,
            "vtype": default_vtype}


def load_findings(findings_dir: str) -> list:
    results = []
    for subdir, vtype in SUBDIR_VTYPE.items():
        path = os.path.join(findings_dir, subdir)
        if not os.path.isdir(path):
            continue
        for fn in sorted(os.listdir(path)):
            if not fn.endswith(".txt"):
                continue
            with open(os.path.join(path, fn), errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    results.append(parse_custom_line(line, vtype))
    results.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 4))
    return results


def resolve_target_and_report_dir(findings_dir: str) -> tuple:
    findings_dir = os.path.abspath(findings_dir)
    parts = findings_dir.split(os.sep)
    if len(parts) >= 3 and parts[-2] == "sessions":
        target = parts[-3]
        session = parts[-1]
        report_dir = os.environ.get("REPORTS_OUT_DIR") or \
                     os.path.join(REPORTS_DIR, target, "sessions", session)
    else:
        target  = os.path.basename(findings_dir)
        session = ""
        report_dir = os.environ.get("REPORTS_OUT_DIR") or \
                     os.path.join(REPORTS_DIR, target)
    return target, session, report_dir


# ── HTML Report ────────────────────────────────────────────────────────────────

def _badge(sev: str) -> str:
    c = SEVERITY_COLOR.get(sev, "#6c757d")
    return (f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:3px;'
            f'font-size:0.85em;font-weight:bold">{sev.upper()}</span>')


def render_html_report(findings: list, target: str, report_dir: str,
                       client: str, consultant: str, title: str) -> str:
    date_str = datetime.now().strftime("%d %B %Y")
    counts   = {s: sum(1 for f in findings if f["severity"] == s)
                for s in SEVERITY_COLOR}
    total    = len(findings)

    # Risk bar
    bar = ""
    for sev, col in SEVERITY_COLOR.items():
        n = counts[sev]
        if not n:
            continue
        pct = int(n / max(total, 1) * 100)
        bar += (f'<tr><td style="width:80px;text-align:right;padding-right:8px">'
                f'<b style="color:{col}">{sev.upper()}</b></td>'
                f'<td><div style="background:#e9ecef;border-radius:3px;height:18px">'
                f'<div style="background:{col};width:{pct}%;height:18px;border-radius:3px;min-width:4px"></div>'
                f'</div></td><td style="width:30px;padding-left:6px"><b>{n}</b></td></tr>')

    # Summary table
    tbl = ""
    for i, f in enumerate(findings, 1):
        tmpl  = VULN_TEMPLATES.get(f["vtype"], VULN_TEMPLATES["misconfig"])
        host  = re.search(r'https?://([^/]+)', f["url"])
        host  = host.group(1) if host else target
        vtitle = tmpl["title"].format(host=host)
        cvss  = tmpl.get("cvss") or CVSS_DEFAULT.get(f["severity"], "N/A")
        tbl  += (f'<tr><td><a href="#VN-{i:03d}">VN-{i:03d}</a></td>'
                 f'<td>{vtitle}</td><td>{_badge(f["severity"])}</td>'
                 f'<td>{cvss}</td>'
                 f'<td style="word-break:break-all"><code>{f["url"][:80]}</code></td>'
                 f'<td>{tmpl.get("cwe","N/A")}</td></tr>\n')

    # Detailed findings
    details = ""
    for i, f in enumerate(findings, 1):
        tmpl   = VULN_TEMPLATES.get(f["vtype"], VULN_TEMPLATES["misconfig"])
        host   = re.search(r'https?://([^/]+)', f["url"])
        host   = host.group(1) if host else target
        vtitle = tmpl["title"].format(host=host)
        sev    = f["severity"]
        cvss   = tmpl.get("cvss") or CVSS_DEFAULT.get(sev, "N/A")
        refs   = "".join(f'<li><a href="{u}" target="_blank">{n}</a></li>'
                         for n, u in tmpl.get("references", []))
        details += f"""
<div id="VN-{i:03d}" style="margin-bottom:36px;border:1px solid #dee2e6;border-radius:6px;overflow:hidden">
  <div style="background:{SEVERITY_COLOR[sev]};padding:12px 18px;color:#fff">
    <b>VN-{i:03d} — {vtitle}</b>
    <span style="float:right;font-size:0.9em">CVSS: {cvss} | {tmpl.get("cwe","N/A")}</span>
  </div>
  <div style="padding:18px">
    <table style="border-collapse:collapse;margin-bottom:14px">
      <tr><td style="width:130px;font-weight:bold;color:#495057;padding:4px 12px 4px 0">Severity</td><td>{_badge(sev)}</td></tr>
      <tr><td style="font-weight:bold;color:#495057;padding:4px 12px 4px 0">CVSS</td><td>{cvss}</td></tr>
      <tr><td style="font-weight:bold;color:#495057;padding:4px 12px 4px 0">CWE</td><td>{tmpl.get("cwe","N/A")}</td></tr>
      <tr><td style="font-weight:bold;color:#495057;padding:4px 12px 4px 0;vertical-align:top">Affected URL</td>
          <td><code style="word-break:break-all">{f["url"]}</code></td></tr>
    </table>
    <h4 style="color:#343a40;margin:10px 0 6px">Description / Impact</h4>
    <p style="margin:0 0 10px">{tmpl["impact"]}</p>
    <h4 style="color:#343a40;margin:10px 0 6px">Evidence / Proof of Concept</h4>
    <pre style="background:#f8f9fa;border:1px solid #dee2e6;border-radius:4px;padding:12px;overflow-x:auto;font-size:0.85em;white-space:pre-wrap">{f["raw"]}</pre>
    <h4 style="color:#343a40;margin:10px 0 6px">Remediation</h4>
    <p style="margin:0 0 10px">{tmpl["remediation"]}</p>
    <h4 style="color:#343a40;margin:4px 0 6px">References</h4>
    <ul style="margin:0;padding-left:18px">{refs}</ul>
  </div>
</div>"""

    sev_counts_rows = "".join(
        f'<tr><td>{_badge(s)}</td><td><b>{counts[s]}</b></td></tr>'
        for s in ("critical", "high", "medium", "low", "info"))

    tools = ("subfinder, assetfinder, amass, dnsx, httpx, katana, waybackurls, gau, "
             "nmap, naabu, nuclei, dalfox, sqlmap, ffuf, Arjun, Kiterunner, "
             "trufflehog, gitleaks, subzy, interactsh-client")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — {target}</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:0;color:#212529;background:#fff}}
a{{color:#0d6efd}}code{{background:#f8f9fa;padding:1px 5px;border-radius:3px;font-size:0.9em}}
.tbl{{width:100%;border-collapse:collapse}}.tbl th{{background:#f1f3f5;text-align:left;padding:8px 12px;border:1px solid #dee2e6;font-size:0.9em}}
.tbl td{{padding:8px 12px;border:1px solid #dee2e6;vertical-align:top;font-size:0.9em}}.tbl tr:hover{{background:#f8f9fa}}
@media print{{.page-break{{page-break-after:always}}body{{font-size:11pt}}}}
</style>
</head>
<body>

<div style="background:#1a1a2e;color:#fff;min-height:100vh;display:flex;flex-direction:column;justify-content:center;padding:60px 80px" class="page-break">
  <div style="font-size:.85em;letter-spacing:2px;text-transform:uppercase;color:#adb5bd;margin-bottom:20px">Confidential</div>
  <h1 style="font-size:2.4em;font-weight:700;margin:0 0 12px;color:#fff">{title}</h1>
  <div style="font-size:1.3em;color:#adb5bd;margin-bottom:36px">Target: <b style="color:#e9ecef">{target}</b></div>
  <table style="border-collapse:collapse;max-width:480px">
    <tr><td style="padding:5px 20px 5px 0;color:#adb5bd;width:140px">Client</td><td style="color:#fff;font-weight:600">{client or "—"}</td></tr>
    <tr><td style="padding:5px 20px 5px 0;color:#adb5bd">Consultant</td><td style="color:#fff;font-weight:600">{consultant or "—"}</td></tr>
    <tr><td style="padding:5px 20px 5px 0;color:#adb5bd">Date</td><td style="color:#fff;font-weight:600">{date_str}</td></tr>
    <tr><td style="padding:5px 20px 5px 0;color:#adb5bd">Total Findings</td><td style="color:#fff;font-weight:600">{total}</td></tr>
    <tr><td style="padding:5px 20px 5px 0;color:#adb5bd">Classification</td><td style="color:#e05252;font-weight:700">CONFIDENTIAL</td></tr>
  </table>
</div>

<div style="max-width:1100px;margin:0 auto;padding:40px">

<h2 style="border-bottom:2px solid #1a1a2e;padding-bottom:8px">Table of Contents</h2>
<ol style="line-height:2.2">
  <li><a href="#exec">Executive Summary</a></li>
  <li><a href="#scope">Scope &amp; Methodology</a></li>
  <li><a href="#vtable">Vulnerability Summary</a></li>
  <li><a href="#details">Detailed Findings</a></li>
  <li><a href="#appendix-a">Appendix A: Tools</a></li>
  <li><a href="#appendix-b">Appendix B: Methodology</a></li>
</ol>
<div class="page-break"></div>

<h2 id="exec" style="border-bottom:2px solid #1a1a2e;padding-bottom:8px">1. Executive Summary</h2>
<p>A vulnerability assessment and penetration test was conducted against <b>{target}</b>.
The assessment identified <b>{total}</b> security finding(s).
{"" if not (counts["critical"] or counts["high"]) else
f'<b style="color:{SEVERITY_COLOR["critical"]}">{counts["critical"]} critical</b> and '
f'<b style="color:{SEVERITY_COLOR["high"]}">{counts["high"]} high</b> severity issues require immediate remediation.'}</p>
<h3>Risk Overview</h3>
<table style="border-collapse:collapse;max-width:550px;margin-bottom:16px">{bar}</table>
<table class="tbl" style="max-width:360px">
  <tr><th>Severity</th><th>Count</th></tr>
  {sev_counts_rows}
  <tr style="background:#f1f3f5"><td><b>Total</b></td><td><b>{total}</b></td></tr>
</table>
<div class="page-break"></div>

<h2 id="scope" style="border-bottom:2px solid #1a1a2e;padding-bottom:8px">2. Scope &amp; Methodology</h2>
<table class="tbl" style="max-width:580px;margin-bottom:16px">
  <tr><th>Item</th><th>Detail</th></tr>
  <tr><td>Target</td><td><code>{target}</code></td></tr>
  <tr><td>Assessment Type</td><td>Web Application Security Assessment</td></tr>
  <tr><td>Methodology</td><td>PTES, OWASP Testing Guide v4.2</td></tr>
  <tr><td>Date</td><td>{date_str}</td></tr>
  <tr><td>Consultant</td><td>{consultant or "—"}</td></tr>
</table>
<ol>
  <li><b>Reconnaissance</b> — Subdomain enumeration, port scanning, tech fingerprinting</li>
  <li><b>Vulnerability Identification</b> — Automated and manual testing</li>
  <li><b>Exploitation</b> — Controlled PoC to confirm impact</li>
  <li><b>Analysis</b> — AI-assisted triage, CVSS v3.1 scoring</li>
  <li><b>Reporting</b> — Structured findings with remediation guidance</li>
</ol>
<div class="page-break"></div>

<h2 id="vtable" style="border-bottom:2px solid #1a1a2e;padding-bottom:8px">3. Vulnerability Summary</h2>
<table class="tbl">
  <tr><th style="width:80px">ID</th><th>Vulnerability</th><th style="width:100px">Severity</th>
      <th style="width:60px">CVSS</th><th>Affected Host / URL</th><th style="width:90px">CWE</th></tr>
  {tbl or '<tr><td colspan="6" style="text-align:center;color:#6c757d">No findings.</td></tr>'}
</table>
<div class="page-break"></div>

<h2 id="details" style="border-bottom:2px solid #1a1a2e;padding-bottom:8px">4. Detailed Findings</h2>
{details or '<p style="color:#6c757d">No findings.</p>'}

<h2 id="appendix-a" style="border-bottom:2px solid #1a1a2e;padding-bottom:8px;margin-top:40px">Appendix A: Tools Used</h2>
<p>{tools}</p>

<h2 id="appendix-b" style="border-bottom:2px solid #1a1a2e;padding-bottom:8px;margin-top:30px">Appendix B: Methodology Reference</h2>
<ul>
  <li><a href="https://www.pentest-standard.org/" target="_blank">Penetration Testing Execution Standard (PTES)</a></li>
  <li><a href="https://owasp.org/www-project-web-security-testing-guide/" target="_blank">OWASP WSTG v4.2</a></li>
  <li><a href="https://www.first.org/cvss/" target="_blank">CVSS v3.1</a></li>
  <li><a href="https://cwe.mitre.org/" target="_blank">MITRE CWE</a></li>
</ul>

<hr style="margin-top:50px;border-color:#dee2e6">
<p style="color:#6c757d;font-size:.85em;text-align:center">Generated by claude-bug-bounty &nbsp;|&nbsp; {date_str} &nbsp;|&nbsp; CONFIDENTIAL</p>
</div>
</body></html>"""
    return html


def render_markdown_report(findings: list, target: str, report_dir: str,
                           client: str, consultant: str, title: str) -> str:
    date_str = datetime.now().strftime("%d %B %Y")
    counts   = {s: sum(1 for f in findings if f["severity"] == s)
                for s in SEVERITY_COLOR}
    lines    = [
        f"# {title}",
        f"**Target:** {target}  \n**Client:** {client or '—'}  \n"
        f"**Consultant:** {consultant or '—'}  \n**Date:** {date_str}  \n"
        "**Classification:** CONFIDENTIAL",
        "", "---", "", "## Executive Summary", "",
        f"Total findings: **{len(findings)}**", "",
        "| Severity | Count |", "|----------|-------|",
    ]
    for s in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {s.upper()} | {counts[s]} |")
    lines += ["", "---", "", "## Vulnerability Summary", "",
              "| ID | Vulnerability | Severity | CVSS | Host |",
              "|----|---------------|----------|------|------|"]
    for i, f in enumerate(findings, 1):
        tmpl  = VULN_TEMPLATES.get(f["vtype"], VULN_TEMPLATES["misconfig"])
        host  = re.search(r'https?://([^/]+)', f["url"])
        host  = host.group(1) if host else target
        cvss  = tmpl.get("cvss") or CVSS_DEFAULT.get(f["severity"], "N/A")
        lines.append(f"| VN-{i:03d} | {tmpl['title'].format(host=host)} | {f['severity'].upper()} | {cvss} | {host} |")
    lines += ["", "---", "", "## Detailed Findings", ""]
    for i, f in enumerate(findings, 1):
        tmpl  = VULN_TEMPLATES.get(f["vtype"], VULN_TEMPLATES["misconfig"])
        host  = re.search(r'https?://([^/]+)', f["url"])
        host  = host.group(1) if host else target
        cvss  = tmpl.get("cvss") or CVSS_DEFAULT.get(f["severity"], "N/A")
        refs  = "\n".join(f"- [{n}]({u})" for n, u in tmpl.get("references", []))
        lines += [
            f"### VN-{i:03d} — {tmpl['title'].format(host=host)}",
            f"**Severity:** {f['severity'].upper()} | **CVSS:** {cvss} | **CWE:** {tmpl.get('cwe','N/A')}  ",
            f"**Affected URL:** `{f['url']}`", "",
            f"**Impact:** {tmpl['impact']}", "",
            "**Evidence:**", "```", f["raw"], "```", "",
            f"**Remediation:** {tmpl['remediation']}", "",
            "**References:**", refs, "", "---", "",
        ]
    lines.append(f"*Generated by claude-bug-bounty — {date_str}*")
    return "\n".join(lines)


def process_findings_dir(findings_dir: str, client: str = "",
                         consultant: str = "", title: str = "") -> tuple:
    target, session, report_dir = resolve_target_and_report_dir(findings_dir)
    os.makedirs(report_dir, exist_ok=True)
    findings = load_findings(findings_dir)
    if not title:
        title = "Vulnerability Assessment & Penetration Test Report"
    html = render_html_report(findings, target, report_dir, client, consultant, title)
    md   = render_markdown_report(findings, target, report_dir, client, consultant, title)
    return len(findings), findings, report_dir, html, md


def main() -> None:
    parser = argparse.ArgumentParser(
        description="claude-bug-bounty Report Generator — Burp Suite-style HTML reports")
    parser.add_argument("findings_dir")
    parser.add_argument("--client",     default="")
    parser.add_argument("--consultant", default="")
    parser.add_argument("--title",      default="Vulnerability Assessment & Penetration Test Report")
    args = parser.parse_args()

    if not os.path.isdir(args.findings_dir):
        print(f"[!] Not a directory: {args.findings_dir}", file=sys.stderr)
        sys.exit(1)

    count, _, report_dir, html, md = process_findings_dir(
        args.findings_dir, args.client, args.consultant, args.title)

    html_path = os.path.join(report_dir, "pentest_report.html")
    md_path   = os.path.join(report_dir, "pentest_report.md")

    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(md)

    print(f"[+] {count} finding(s) — {os.path.basename(report_dir)}")
    print(f"[+] HTML : {html_path}")
    print(f"[+] MD   : {md_path}")

    import shutil
    if shutil.which("wkhtmltopdf"):
        pdf = html_path.replace(".html", ".pdf")
        os.system(f'wkhtmltopdf --quiet "{html_path}" "{pdf}" 2>/dev/null')
        if os.path.isfile(pdf):
            print(f"[+] PDF  : {pdf}")


if __name__ == "__main__":
    main()
