#!/usr/bin/env python3
"""
learn.py  Fetches recent bug intelligence for a tech stack.
Queries GitHub Advisory Database, NVD CVE API, and HackerOne Hacktivity.

Usage:
  python3 tools/learn.py --tech "nextjs,graphql"
  python3 tools/learn.py --tech "nextjs,graphql" --target target.com --output recon/target.com/intel.md
  python3 tools/learn.py --tech "solidity" --hackerone-program target-program
"""

import argparse
import json
import os
import ssl
import sys
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime

# macOS: Python may not have system SSL certs. Use unverified context for API queries.
_SSL_CTX = ssl.create_default_context()
try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE

# ─── Color codes ──────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ─── Tech → npm/pypi/cargo package name mapping ───────────────────────────────
TECH_TO_PACKAGE = {
    "nextjs":    ("npm", "next"),
    "next.js":   ("npm", "next"),
    "graphql":   ("npm", "graphql"),
    "react":     ("npm", "react"),
    "express":   ("npm", "express"),
    "hasura":    ("npm", "hasura"),
    "jwt":       ("npm", "jsonwebtoken"),
    "jsonwebtoken": ("npm", "jsonwebtoken"),
    "axios":     ("npm", "axios"),
    "webpack":   ("npm", "webpack"),
    "lodash":    ("npm", "lodash"),
    "node":      ("npm", "node"),
    "django":    ("pip", "django"),
    "flask":     ("pip", "flask"),
    "rails":     ("gem", "rails"),
    "spring":    ("maven", "spring"),
}

# ─── Tech → grep patterns to search for in source code ────────────────────────
TECH_GREP_PATTERNS = {
    "nextjs": [
        "grep -rn 'getServerSideProps' --include='*.ts' --include='*.tsx' | grep 'fetch'",
        "grep -rn 'middleware' --include='*.ts' | grep -v test",
        "grep -rn 'rewrite\\|redirect' next.config",
    ],
    "graphql": [
        "grep -rn 'internalId\\|id:' --include='*.graphql' --include='*.ts'",
        "grep -rn 'introspection\\|__schema' --include='*.ts'",
        "grep -rn 'context\\.user\\|context\\.auth' --include='*.ts' | grep -v test",
    ],
    "jwt": [
        "grep -rn \"=== \" --include='*.ts' | grep -i 'token\\|secret\\|key'",
        "grep -rn 'alg.*none\\|algorithm.*none' --include='*.ts'",
        "grep -rn 'jwt\\.verify\\|jwt\\.decode' --include='*.ts'",
    ],
    "hasura": [
        "grep -rn 'x-hasura-role\\|x-hasura-admin-secret' --include='*.ts'",
        "grep -rn 'HASURA_GRAPHQL_JWT_SECRET\\|HASURA_SECRET' --include='*.env*'",
        "grep -rn 'hasuraClaims\\|hasura_claims' --include='*.ts'",
    ],
    "solidity": [
        "grep -rn 'tx\\.origin\\|delegatecall\\|selfdestruct' --include='*.sol'",
        "grep -rn 'transfer(\\|send(\\|call{' --include='*.sol'",
        "grep -rn 'block\\.timestamp\\|now' --include='*.sol'",
    ],
    "oauth": [
        "grep -rn 'redirect_uri\\|returnTo\\|next=' --include='*.ts'",
        "grep -rn 'state.*param\\|csrf.*oauth' --include='*.ts' -i",
        "grep -rn 'code_verifier\\|PKCE' --include='*.ts' -i",
    ],
}

# ─── HackerOne tech keyword mapping ───────────────────────────────────────────
TECH_H1_KEYWORDS = {
    "nextjs":   ["next.js", "nextjs", "vercel"],
    "graphql":  ["graphql", "introspection", "graphql idor"],
    "jwt":      ["jwt", "json web token", "token forgery"],
    "hasura":   ["hasura", "graphql engine"],
    "solidity": ["solidity", "smart contract", "reentrancy"],
    "oauth":    ["oauth", "oidc", "redirect_uri", "open redirect oauth"],
    "ssrf":     ["ssrf", "server-side request forgery"],
    "idor":     ["idor", "insecure direct object"],
    "xss":      ["xss", "cross-site scripting"],
    "csrf":     ["csrf", "cross-site request forgery"],
}


def fetch_url(url: str, headers: dict = None, data: bytes = None, timeout: int = 10) -> dict | None:
    """Simple HTTP fetch, returns parsed JSON or None on error."""
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return json.loads(body)
    except urllib.error.HTTPError as e:
        print(f"  {YELLOW}HTTP {e.code} for {url}{RESET}")
        return None
    except Exception as e:
        print(f"  {YELLOW}Error fetching {url}: {e}{RESET}")
        return None


def fetch_github_advisories(tech: str) -> list[dict]:
    """Query GitHub Advisory Database for a package."""
    ecosystem, package = TECH_TO_PACKAGE.get(tech.lower(), (None, None))
    if not ecosystem or not package:
        return []

    url = f"https://api.github.com/advisories?ecosystem={ecosystem}&affects={urllib.parse.quote(package)}&per_page=10"
    data = fetch_url(url, headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    if not data or not isinstance(data, list):
        return []

    results = []
    for item in data:
        severity = item.get("severity", "unknown").upper()
        summary  = item.get("summary", "No summary")[:120]
        ghsa_id  = item.get("ghsa_id", "")
        published = item.get("published_at", "")[:10]
        cves     = [x.get("value", "") for x in item.get("identifiers", []) if x.get("type") == "CVE"]
        cve_str  = cves[0] if cves else ghsa_id
        results.append({
            "id":        cve_str,
            "source":    "GitHub Advisory",
            "tech":      tech,
            "severity":  severity,
            "summary":   summary,
            "published": published,
            "grep":      TECH_GREP_PATTERNS.get(tech.lower(), ["(see tech grep patterns above)"]),
        })
    return results


def fetch_nvd_cves(tech: str) -> list[dict]:
    """Query NVD CVE API by keyword."""
    query = TECH_TO_PACKAGE.get(tech.lower(), (None, tech))[1]
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(query)}&resultsPerPage=5"
    data = fetch_url(url, timeout=15)
    if not data:
        return []

    results = []
    for item in (data.get("vulnerabilities") or []):
        cve = item.get("cve", {})
        cve_id   = cve.get("id", "")
        desc     = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")[:120]
        metrics  = cve.get("metrics", {})
        score    = None
        severity = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                score    = m.get("cvssData", {}).get("baseScore")
                severity = m.get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                break
        published = cve.get("published", "")[:10]
        results.append({
            "id":        cve_id,
            "source":    "NVD",
            "tech":      tech,
            "severity":  severity,
            "summary":   desc,
            "published": published,
            "score":     score,
            "grep":      TECH_GREP_PATTERNS.get(tech.lower(), []),
        })
    return results


def fetch_hackerone_hacktivity(keyword: str, limit: int = 5) -> list[dict]:
    """Query HackerOne Hacktivity public GraphQL for a keyword."""
    query = {
        "query": f"""{{
          hacktivity_items(
            first: {limit},
            order_by: {{ field: popular, direction: DESC }},
            where: {{
              report: {{ title: {{ _icontains: "{keyword}" }} }},
              disclosed_at: {{ _is_null: false }}
            }}
          ) {{
            nodes {{
              ... on HacktivityDocument {{
                report {{
                  title
                  severity_rating
                  disclosed_at
                  url
                }}
              }}
            }}
          }}
        }}"""
    }
    data = fetch_url(
        "https://hackerone.com/graphql",
        headers={"Content-Type": "application/json"},
        data=json.dumps(query).encode(),
    )
    if not data:
        return []

    results = []
    nodes = (data.get("data") or {}).get("hacktivity_items", {}).get("nodes", [])
    for node in nodes:
        report = node.get("report")
        if not report:
            continue
        results.append({
            "id":        report.get("url", ""),
            "source":    "HackerOne",
            "tech":      keyword,
            "severity":  (report.get("severity_rating") or "unknown").upper(),
            "summary":   report.get("title", ""),
            "published": (report.get("disclosed_at") or "")[:10],
            "grep":      [],
        })
    return results


def fetch_intel(techs: list[str]) -> list[dict]:
    """Collect intel from all sources for all techs."""
    all_results = []
    for tech in techs:
        print(f"  {CYAN}[{tech}]{RESET} Querying GitHub Advisory Database...")
        all_results.extend(fetch_github_advisories(tech))

        print(f"  {CYAN}[{tech}]{RESET} Querying NVD CVE API...")
        all_results.extend(fetch_nvd_cves(tech))

        # HackerOne — use keyword variations
        keywords = TECH_H1_KEYWORDS.get(tech.lower(), [tech])
        for kw in keywords[:2]:  # limit to 2 keywords per tech to avoid slow queries
            print(f"  {CYAN}[{tech}]{RESET} Querying HackerOne Hacktivity for '{kw}'...")
            all_results.extend(fetch_hackerone_hacktivity(kw, limit=5))

    return all_results


def severity_order(s: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "MODERATE": 2, "LOW": 3, "UNKNOWN": 4}.get(s.upper(), 4)


def build_markdown(techs: list[str], results: list[dict]) -> str:
    """Build intel.md content."""
    lines = [
        f"# Bug Intelligence Report",
        f"",
        f"**Technologies:** {', '.join(techs)}",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"**Sources:** GitHub Advisory DB, NVD CVE API, HackerOne Hacktivity",
        f"",
        f"---",
        f"",
    ]

    # Group by tech
    by_tech: dict[str, list[dict]] = {}
    for r in results:
        t = r["tech"]
        by_tech.setdefault(t, []).append(r)

    for tech in techs:
        tech_results = by_tech.get(tech, [])
        tech_results.sort(key=lambda x: severity_order(x.get("severity", "UNKNOWN")))

        lines.append(f"## {tech.upper()}")
        lines.append("")

        if not tech_results:
            lines.append("_No results found. Check manually at https://security.snyk.io_")
            lines.append("")
            continue

        lines.append("| ID | Source | Severity | Summary | Published |")
        lines.append("|---|---|---|---|---|")
        for r in tech_results[:15]:
            id_str   = f"[{r['id']}]({r['id']})" if r['id'].startswith("http") else r['id']
            sev      = r.get("severity", "?")
            summary  = r.get("summary", "")[:100].replace("|", "\\|")
            pub      = r.get("published", "")
            source   = r.get("source", "")
            lines.append(f"| {id_str} | {source} | {sev} | {summary} | {pub} |")

        lines.append("")

        # Add grep patterns if available
        patterns = TECH_GREP_PATTERNS.get(tech.lower(), [])
        if patterns:
            lines.append(f"### Grep Patterns for `{tech}` (run in target repo)")
            lines.append("")
            lines.append("```bash")
            for p in patterns:
                lines.append(p)
            lines.append("```")
            lines.append("")

    lines += [
        "---",
        "",
        "## Manual Research Links",
        "",
        "```bash",
        "# Snyk vulnerability DB",
        "open https://security.snyk.io/vuln?type=npm&search=PACKAGE_NAME",
        "",
        "# GitHub Security Advisories",
        "open https://github.com/advisories?query=TECH",
        "",
        "# HackerOne Hacktivity search",
        "open https://hackerone.com/hacktivity?querystring=TECH",
        "",
        "# pentester.land writeup aggregator",
        "open https://pentester.land/writeups/?search=TECH",
        "```",
    ]

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Fetch bug intelligence for a tech stack")
    parser.add_argument("--tech",    required=True, help="Comma-separated technologies (e.g., nextjs,graphql)")
    parser.add_argument("--target",  default="",    help="Target name for output folder (optional)")
    parser.add_argument("--output",  default="",    help="Output file path")
    parser.add_argument("--hackerone-program", default="", help="HackerOne program handle for targeted search")
    args = parser.parse_args()

    techs = [t.strip() for t in args.tech.split(",") if t.strip()]

    # Determine output path
    if args.output:
        output_path = args.output
    elif args.target:
        base_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "recon", args.target)
        os.makedirs(base_dir, exist_ok=True)
        output_path = os.path.join(base_dir, "intel.md")
    else:
        output_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "intel.md")

    print(f"\n{BOLD}Bug Intelligence Fetcher{RESET}")
    print(f"Technologies: {CYAN}{', '.join(techs)}{RESET}")
    print(f"Output: {output_path}\n")

    results = fetch_intel(techs)

    # If program specified, add program-specific HackerOne results
    if args.hackerone_program:
        print(f"  {CYAN}Fetching HackerOne disclosures for program: {args.hackerone_program}{RESET}")
        query = {
            "query": f"""{{
              hacktivity_items(
                first: 20,
                order_by: {{ field: popular, direction: DESC }},
                where: {{
                  team: {{ handle: {{ _eq: "{args.hackerone_program}" }} }},
                  disclosed_at: {{ _is_null: false }}
                }}
              ) {{
                nodes {{
                  ... on HacktivityDocument {{
                    report {{
                      title
                      severity_rating
                      disclosed_at
                      url
                    }}
                  }}
                }}
              }}
            }}"""
        }
        data = fetch_url(
            "https://hackerone.com/graphql",
            headers={"Content-Type": "application/json"},
            data=json.dumps(query).encode(),
        )
        if data:
            nodes = (data.get("data") or {}).get("hacktivity_items", {}).get("nodes", [])
            for node in nodes:
                report = node.get("report")
                if report:
                    results.append({
                        "id":        report.get("url", ""),
                        "source":    f"HackerOne/{args.hackerone_program}",
                        "tech":      "program-disclosures",
                        "severity":  (report.get("severity_rating") or "unknown").upper(),
                        "summary":   report.get("title", ""),
                        "published": (report.get("disclosed_at") or "")[:10],
                        "grep":      [],
                    })
            techs.append("program-disclosures")

    content = build_markdown(techs, results)
    with open(output_path, "w") as f:
        f.write(content)

    total = len(results)
    high  = sum(1 for r in results if severity_order(r.get("severity", "")) <= 1)
    print(f"\n{BOLD}{GREEN}Done!{RESET}  {total} findings ({RED}{high} HIGH/CRITICAL{RESET})")
    print(f"Report: {output_path}\n")

    # Print top findings to terminal
    results.sort(key=lambda x: severity_order(x.get("severity", "UNKNOWN")))
    print(f"{BOLD}Top findings:{RESET}")
    for r in results[:10]:
        sev = r.get("severity", "?")
        c   = RED if severity_order(sev) <= 1 else (YELLOW if severity_order(sev) == 2 else GREEN)
        print(f"  {c}[{sev}]{RESET} [{r['source']}] {r['summary'][:90]}")
    print()


if __name__ == "__main__":
    main()
