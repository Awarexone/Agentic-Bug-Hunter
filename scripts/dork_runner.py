#!/usr/bin/env python3
"""
dork_runner.py — Google Dork Automation Script
Author: Shuvonsec (@shuvonsec)
Usage: python3 dork_runner.py -d target.com [-c category] [-o output.txt]
"""

import argparse
import time
import sys
import json
import random
import urllib.parse
from datetime import datetime

# ── Colors ────────────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"

# ── Dork Templates ────────────────────────────────────────────────────────────
DORK_CATEGORIES = {

    "credentials": [
        'site:{target} ext:env',
        'site:{target} ext:env "DB_PASSWORD"',
        'site:{target} ext:env "API_KEY"',
        'site:{target} "api_key" OR "apikey"',
        'site:{target} "secret_key" OR "SECRET_KEY"',
        'site:{target} "password" filetype:log',
        'site:{target} "password" filetype:txt',
        'site:{target} ext:yaml "password:"',
        'site:{target} ext:json "private_key"',
        'site:{target} inurl:".git/config"',
        'site:{target} ext:pem "BEGIN RSA PRIVATE KEY"',
        'site:{target} "aws_secret_access_key"',
        'site:{target} "AKIA" intext:AKIA',
        'site:{target} ext:json "type: service_account"',
    ],

    "pii": [
        'site:{target} ext:csv intext:"email" intext:"phone"',
        'site:{target} ext:xls intext:"ssn"',
        'site:{target} ext:xlsx intext:"date of birth"',
        'site:{target} ext:csv "first name" "last name" "email"',
        'site:{target} filetype:csv "password" "username"',
        'site:{target} intitle:"index of" "users.csv"',
        'site:{target} intitle:"index of" "customers.csv"',
        'site:{target} ext:log intext:"email"',
        'site:{target} filetype:xls "employee" "salary"',
    ],

    "admin": [
        'site:{target} inurl:admin',
        'site:{target} inurl:/admin/login',
        'site:{target} inurl:/phpmyadmin',
        'site:{target} inurl:/jenkins',
        'site:{target} inurl:/grafana',
        'site:{target} inurl:/kibana',
        'site:{target} inurl:/actuator',
        'site:{target} inurl:/swagger-ui',
        'site:{target} inurl:/api-docs',
        'site:{target} intitle:"admin panel"',
        'site:{target} intitle:"control panel"',
        'site:{target} inurl:"/wp-login.php"',
    ],

    "errors": [
        'site:{target} "SQL syntax" OR "mysql_fetch"',
        'site:{target} "Warning: mysql_"',
        'site:{target} "Fatal error:" filetype:php',
        'site:{target} "Stack trace:" filetype:html',
        'site:{target} "Traceback (most recent call last)"',
        'site:{target} "NullPointerException"',
        'site:{target} "DEBUG = True" filetype:py',
        'site:{target} "APP_DEBUG=true" ext:env',
        'site:{target} inurl:phpinfo.php',
        'site:{target} ext:log "error"',
        'site:{target} intitle:"index of" "error.log"',
    ],

    "cloud": [
        '"{target}" site:s3.amazonaws.com',
        '"{target}" site:blob.core.windows.net',
        '"{target}" site:storage.googleapis.com',
        '"{target}" site:firebaseio.com',
        '{target}.s3.amazonaws.com',
        'intitle:"index of" site:{target}',
    ],

    "subdomains": [
        'site:*.{target}',
        'site:*.*.{target}',
        'site:*.{target} inurl:login',
        'site:*.{target} inurl:admin',
        'site:*.{target} inurl:api',
        'site:*.{target} inurl:staging',
        'site:*.{target} inurl:dev',
        'site:*.{target} inurl:test',
    ],

    "params": [
        'site:{target} inurl:url=http',
        'site:{target} inurl:redirect=http',
        'site:{target} inurl:next=http',
        'site:{target} inurl:?id=',
        'site:{target} inurl:?user_id=',
        'site:{target} inurl:search=',
        'site:{target} inurl:q=',
        'site:{target} inurl:file=',
        'site:{target} inurl:path=',
        'site:{target} inurl:include=',
        'site:{target} inurl:page=',
        'site:{target} inurl:debug=',
    ],

    "leaks": [
        'site:pastebin.com "{target}"',
        'site:pastebin.com "{target}" "password"',
        'site:github.com "{target}" "password"',
        'site:github.com "{target}" "api_key"',
        'site:github.com "{target}" ".env"',
        'site:gist.github.com "{target}"',
        'site:notion.so "{target}"',
        'site:docs.google.com "{target}"',
        'site:trello.com "{target}"',
    ],

    "github": [
        'site:github.com "{target}" "password"',
        'site:github.com "{target}" "api_key"',
        'site:github.com "{target}" "secret"',
        'site:github.com "{target}" "token"',
        'site:github.com "{target}" extension:env',
        'site:github.com "{target}" filename:config.yml',
        'site:github.com "{target}" filename:.env',
        'site:github.com "{target}" "BEGIN RSA PRIVATE KEY"',
    ],

    "juicy": [
        'site:{target} intitle:"index of" "backup"',
        'site:{target} intitle:"index of" "sql"',
        'site:{target} intitle:"index of" "dump"',
        'site:{target} ext:sql',
        'site:{target} ext:bak',
        'site:{target} ext:old',
        'site:{target} inurl:backup',
        'site:{target} filetype:pdf "confidential"',
        'site:{target} filetype:pdf "internal use only"',
    ],

    "all": []  # Filled dynamically below
}

# Fill "all" with all dorks
for cat, dorks in DORK_CATEGORIES.items():
    if cat != "all":
        DORK_CATEGORIES["all"].extend(dorks)


def banner():
    print(f"""
{C.RED}{C.BOLD}
  ██████╗  ██████╗ ██████╗ ██╗  ██╗    ██████╗ ██╗   ██╗███╗   ██╗███╗   ██╗███████╗██████╗
  ██╔══██╗██╔═══██╗██╔══██╗██║ ██╔╝    ██╔══██╗██║   ██║████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ██║  ██║██║   ██║██████╔╝█████╔╝     ██████╔╝██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ██║  ██║██║   ██║██╔══██╗██╔═██╗     ██╔══██╗██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
  ██████╔╝╚██████╔╝██║  ██║██║  ██╗    ██║  ██║╚██████╔╝██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{C.RESET}
{C.CYAN}  Google Dork Runner by Shuvonsec | Ethical Bug Bounty Use Only{C.RESET}
""")


def generate_google_url(dork: str) -> str:
    """Generate Google search URL for a dork."""
    encoded = urllib.parse.quote(dork)
    return f"https://www.google.com/search?q={encoded}&num=50"


def generate_html_report(target: str, results: list, output_file: str):
    """Generate a clickable HTML report of all dorks."""
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Dork Report — {target}</title>
<style>
  body {{ font-family: monospace; background: #1a1a1a; color: #e0e0e0; padding: 20px; }}
  h1 {{ color: #ff4444; }}
  h2 {{ color: #44aaff; border-bottom: 1px solid #333; padding-bottom: 5px; }}
  a {{ color: #44ff44; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .dork {{ background: #2a2a2a; padding: 8px 12px; margin: 4px 0; border-radius: 4px; border-left: 3px solid #44aaff; }}
  .count {{ color: #888; font-size: 12px; }}
</style>
</head>
<body>
<h1>🔍 Dork Arsenal Report</h1>
<p>Target: <strong>{target}</strong> | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p class="count">Total dorks: {len(results)}</p>
"""
    current_cat = ""
    for item in results:
        if item["category"] != current_cat:
            current_cat = item["category"]
            html += f"<h2>📁 {current_cat.upper()}</h2>\n"
        google_url = generate_google_url(item["dork"])
        html += f'<div class="dork"><a href="{google_url}" target="_blank">🔗 {item["dork"]}</a></div>\n'

    html += "</body></html>"

    with open(output_file, "w") as f:
        f.write(html)
    print(f"{C.GREEN}[+] HTML report saved: {output_file}{C.RESET}")


def run(args):
    target = args.domain
    category = args.category
    output = args.output
    html_out = args.html

    banner()
    print(f"{C.YELLOW}[*] Target: {target}{C.RESET}")
    print(f"{C.YELLOW}[*] Category: {category}{C.RESET}")
    print(f"{C.YELLOW}[*] Time: {datetime.now().strftime('%Y-%m-%d %H:%M')}{C.RESET}")
    print()

    if category not in DORK_CATEGORIES:
        print(f"{C.RED}[!] Unknown category: {category}{C.RESET}")
        print(f"    Available: {', '.join(DORK_CATEGORIES.keys())}")
        sys.exit(1)

    dork_templates = DORK_CATEGORIES[category]
    results = []

    print(f"{C.CYAN}[*] Generating {len(dork_templates)} dorks for {target}...{C.RESET}\n")

    for template in dork_templates:
        dork = template.replace("{target}", target)
        google_url = generate_google_url(dork)
        results.append({"category": category, "dork": dork, "url": google_url})
        print(f"{C.GREEN}[DORK]{C.RESET} {dork}")
        print(f"       {C.BLUE}→ {google_url}{C.RESET}\n")

    # Save text output
    if output:
        with open(output, "w") as f:
            for item in results:
                f.write(f"# [{item['category']}]\n")
                f.write(f"DORK: {item['dork']}\n")
                f.write(f"URL:  {item['url']}\n\n")
        print(f"{C.GREEN}[+] Text output saved: {output}{C.RESET}")

    # Save HTML report
    if html_out:
        generate_html_report(target, results, html_out)
    else:
        # Auto-save HTML
        auto_html = f"dork_report_{target.replace('.', '_')}.html"
        generate_html_report(target, results, auto_html)

    # Save JSON
    json_out = output.replace(".txt", ".json") if output else f"dork_results_{target.replace('.', '_')}.json"
    with open(json_out, "w") as f:
        json.dump({"target": target, "category": category, "total": len(results), "dorks": results}, f, indent=2)
    print(f"{C.GREEN}[+] JSON saved: {json_out}{C.RESET}")

    print(f"\n{C.BOLD}{C.GREEN}[✓] Done! {len(results)} dorks generated for {target}{C.RESET}")
    print(f"{C.YELLOW}[*] Open the HTML report to click each dork directly in Google.{C.RESET}")
    print(f"{C.YELLOW}[*] Pro tip: Use pagodo to automate Google searching:{C.RESET}")
    print(f"    python3 pagodo.py -d {target} -g dorks.txt -l 50 -s -e 35.0 -j 1.1\n")


def main():
    parser = argparse.ArgumentParser(
        description="Google Dork Runner by Shuvonsec",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python3 dork_runner.py -d target.com
  python3 dork_runner.py -d target.com -c credentials
  python3 dork_runner.py -d target.com -c all -o results.txt
  python3 dork_runner.py -d target.com -c leaks --html report.html

CATEGORIES:
  credentials  — .env files, API keys, passwords, SSH keys
  pii          — PII leaks, CSV dumps, user data
  admin        — Admin panels, dashboards, login pages
  errors       — Stack traces, debug pages, PHP errors
  cloud        — S3 buckets, Azure blobs, Firebase
  subdomains   — Subdomain enumeration via Google
  params       — Juicy parameters (SSRF, redirect, SQLi, LFI)
  leaks        — Pastebin, GitHub, Notion leaks
  github       — GitHub code search dorks
  juicy        — Backup files, SQL dumps, confidential PDFs
  all          — Run ALL categories
        """
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., target.com)")
    parser.add_argument("-c", "--category", default="all",
                        choices=list(DORK_CATEGORIES.keys()), help="Dork category (default: all)")
    parser.add_argument("-o", "--output", help="Output text file (e.g., results.txt)")
    parser.add_argument("--html", help="Output HTML report file")

    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
