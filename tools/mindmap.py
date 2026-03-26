#!/usr/bin/env python3
"""
mindmap.py — Generates a Mermaid mind map + prioritized hunting checklist
based on target type and detected technologies.

Usage:
  python3 tools/mindmap.py --target target.com --type opensrc --tech "nextjs,graphql,solidity"
  python3 tools/mindmap.py --target example.com --type website --tech "nginx,react"
  python3 tools/mindmap.py --target api.example.com --type api --tech "jwt,openapi"
"""

import argparse
import os
import sys
from datetime import datetime

# ─── Color codes ──────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ─── Checklist definitions ────────────────────────────────────────────────────
# Format: (impact_color, description, section_ref)
# impact: "HIGH" = red, "MED" = yellow, "LOW" = green

WEBSITE_CHECKS = [
    ("HIGH", "IDOR/ATO — enumerate user IDs in API endpoints", "bug-bounty-hunt → IDOR section"),
    ("HIGH", "Authentication bypass — test all auth flows (login, reset, OAuth)", "bug-bounty-hunt → Auth Bypass section"),
    ("HIGH", "SSRF — find server-side URL fetch params (`url=`, `webhook=`, `redirect=`)", "bug-bounty-hunt → SSRF section"),
    ("HIGH", "Race condition — parallel requests on transactions, coupons, credits", "bug-bounty-hunt → Race Conditions section"),
    ("MED",  "Stored XSS — user input reflected in other users' views", "bug-bounty-hunt → XSS section"),
    ("MED",  "CSRF — state-changing requests without CSRF tokens", "bug-bounty-hunt → CSRF section"),
    ("MED",  "Open redirect — `returnTo`, `next`, `url` params with unvalidated URLs", "bug-bounty-hunt → Open Redirect"),
    ("MED",  "Subdomain takeover — dangling CNAMEs to unclaimed services", "bug-bounty-recon → Phase 8"),
    ("LOW",  "Information disclosure — error messages, stack traces, debug endpoints", "manual"),
    ("LOW",  "Missing security headers — CSP, HSTS, X-Frame-Options", "manual"),
]

OPENSRC_CHECKS = [
    ("HIGH", "Timing side-channel — `===` on HMAC/token/secret comparisons", "bug-bounty-hunt → Timing Side-Channel section"),
    ("HIGH", "JWT/token forgery — `alg:none`, weak secret, claim injection", "bug-bounty-hunt → OIDC/OAuth section"),
    ("HIGH", "Smart contract reentrancy / access control", "bug-bounty-hunt → Smart Contract section"),
    ("HIGH", "SSRF in server-side fetch — user-controlled URL passed to fetch/axios", "bug-bounty-hunt → SSRF section"),
    ("MED",  "Event spoofing — SDK public `trigger()` / `postMessage` without origin check", "bug-bounty-hunt → SDK/Client-Library section"),
    ("MED",  "Open redirect — `new URL(userInput, base)` does NOT prevent open redirect", "bug-bounty-hunt → Open Redirect"),
    ("MED",  "SIWE double-hash / nonce reuse", "bug-bounty-hunt → SIWE section"),
    ("MED",  "Hardcoded secrets in `.env.test` / config files", "manual grep"),
    ("MED",  "Prototype pollution — unsafe `Object.assign` / deep merge on user input", "bug-bounty-hunt → Prototype Pollution"),
    ("LOW",  "Dev breadcrumbs — TODO/FIXME/HACK near security-sensitive code", "grep -rn 'TODO|FIXME|HACK'"),
]

API_CHECKS = [
    ("HIGH", "Auth bypass — test endpoints without Authorization header", "bug-bounty-hunt → Auth Bypass section"),
    ("HIGH", "IDOR — change numeric/UUID IDs in all requests", "bug-bounty-hunt → IDOR section"),
    ("HIGH", "Webhook SSRF — webhook URL field = SSRF vector", "bug-bounty-hunt → SSRF section"),
    ("HIGH", "JWT claim forgery — `x-hasura-role`, `sub`, `iss` manipulation", "bug-bounty-hunt → OIDC/OAuth section"),
    ("MED",  "Endpoint enumeration — undocumented v1/v2 endpoints, hidden routes", "kiterunner scan"),
    ("MED",  "Rate limit bypass — no rate limit on auth, OTP, or sensitive endpoints", "bug-bounty-hunt → rate limiting"),
    ("MED",  "Race condition on batch/parallel operations", "bug-bounty-hunt → Race Conditions section"),
    ("LOW",  "CORS misconfiguration — wildcard on credentialed endpoints", "bug-bounty-hunt → CORS"),
    ("LOW",  "API key in URL — logs exposure of credentials", "manual review"),
]

MOBILE_CHECKS = [
    ("HIGH", "WebView JS injection — `addJavascriptInterface` without origin check", "bug-bounty-hunt → SDK/Client-Library section"),
    ("HIGH", "Deep link hijack — register same URI scheme, steal OAuth codes", "manual + AndroidManifest review"),
    ("HIGH", "Certificate pinning bypass — Frida/Objection to intercept traffic", "Frida setup guide"),
    ("MED",  "Plaintext secrets — AsyncStorage, SQLite, SharedPreferences", "manual + strings/decompile"),
    ("MED",  "SDK event spoofing — MiniKit/WalletConnect postMessage without origin check", "bug-bounty-hunt → SDK section"),
    ("MED",  "Backend API same as web — test mobile JWT on web endpoints", "all web checks apply"),
    ("LOW",  "Insecure data backup — Android allowBackup=true", "AndroidManifest check"),
    ("LOW",  "Hardcoded API keys in decompiled code", "grep after apktool decompile"),
]

# Tech-specific additions
TECH_CHECKS = {
    "graphql": [
        ("HIGH", "GraphQL IDOR — swap internalId in queries/mutations", "bug-bounty-hunt → GraphQL section"),
        ("MED",  "Introspection enabled — schema leakage, hidden fields/types", "bug-bounty-hunt → GraphQL section"),
        ("MED",  "Batch/alias abuse — 10k mutations to bypass rate limit", "bug-bounty-hunt → GraphQL section"),
    ],
    "nextjs": [
        ("HIGH", "Next.js middleware bypass — check _next/static path for auth bypass", "CVE-2025-29927"),
        ("MED",  "SSRF in getServerSideProps — user-controlled fetch URL", "bug-bounty-hunt → SSRF section"),
        ("MED",  "Server Actions CSRF — test server actions without CSRF token", "bug-bounty-hunt → CSRF section"),
    ],
    "solidity": [
        ("HIGH", "Reentrancy — check all ETH transfer calls", "bug-bounty-hunt → Smart Contract section"),
        ("HIGH", "Signature replay — EIP-712 domain separator, nullifier check", "bug-bounty-hunt → Smart Contract section"),
        ("HIGH", "Access control — `onlyOwner` missing on privileged functions", "bug-bounty-hunt → Smart Contract section"),
        ("MED",  "Front-running — any state-dependent transaction ordering", "bug-bounty-hunt → Smart Contract section"),
    ],
    "jwt": [
        ("HIGH", "alg:none attack — remove signature entirely", "bug-bounty-payloads → JWT section"),
        ("HIGH", "Weak secret — brute force with hashcat/jwt-cracker", "bug-bounty-payloads → JWT section"),
        ("MED",  "Claim injection — add `role: admin` or `x-hasura-role: admin`", "bug-bounty-hunt → OIDC section"),
    ],
    "oauth": [
        ("HIGH", "Open redirect in redirect_uri — steal auth code", "bug-bounty-hunt → OIDC/OAuth section"),
        ("HIGH", "CSRF on OAuth flow — missing state parameter check", "bug-bounty-hunt → OIDC/OAuth section"),
        ("MED",  "Token leakage via referrer — access token in URL fragment", "bug-bounty-hunt → OIDC/OAuth section"),
    ],
    "hasura": [
        ("HIGH", "JWT claim forgery — `x-hasura-role: admin` in JWT payload", "bug-bounty-payloads → Hasura section"),
        ("HIGH", "Admin secret in .env.test — check if reused in staging/prod", "manual check"),
        ("MED",  "Action handler SSRF — Hasura action webhook URL configurable", "bug-bounty-hunt → SSRF section"),
    ],
    "aws": [
        ("HIGH", "SSRF to IMDSv1 — 169.254.169.254/latest/meta-data/iam/security-credentials", "bug-bounty-hunt → SSRF section"),
        ("MED",  "S3 bucket misconfiguration — public read/write", "awscli: aws s3 ls s3://BUCKET --no-sign-request"),
        ("MED",  "Exposed credentials in environment or error responses", "manual review"),
    ],
    "react": [
        ("MED",  "dangerouslySetInnerHTML with user input — DOM XSS", "bug-bounty-hunt → XSS section"),
        ("LOW",  "Prototype pollution via props", "bug-bounty-hunt → Prototype Pollution"),
    ],
}

# ─── Mermaid generation ───────────────────────────────────────────────────────

def build_mermaid(target: str, target_type: str, techs: list[str]) -> str:
    """Generate a Mermaid mind map for the target."""
    lines = ["```mermaid", "mindmap", f'  root(("{target}"))', f"    {target_type.upper()}"]

    if target_type == "website":
        lines += [
            "      Auth flow",
            '        "IDOR / ATO"',
            '        "CSRF"',
            "      User-controlled IDs",
            '        "IDOR (horizontal + vertical)"',
            "      File uploads",
            '        "File Upload bugs"',
            "      Payments/transactions",
            '        "Race Conditions"',
            "      Search/filter inputs",
            '        "SQLi / SSTI"',
            "      URL params",
            '        "SSRF"',
            "      Reflected input",
            '        "XSS (reflected, stored, DOM)"',
            "      Subdomains",
            '        "Takeover / Forgotten apps"',
        ]
    elif target_type == "opensrc":
        lines += [
            "      Hash/token comparisons",
            '        "Timing side-channel"',
            "      JWT handling",
            '        "alg:none / claim forgery"',
            "      Smart contracts",
            '        "Reentrancy / replay / access control"',
            "      SDK public methods",
            '        "Event spoofing"',
            "      URL redirects",
            '        "Open redirect"',
            "      Fix history",
            '        "Anti-pattern grep"',
            "      .env / config",
            '        "Hardcoded secrets"',
        ]
    elif target_type == "api":
        lines += [
            "      All endpoints",
            '        "Auth bypass on undocumented routes"',
            "      ID parameters",
            '        "IDOR"',
            "      Webhook URLs",
            '        "SSRF"',
            "      Auth tokens",
            '        "JWT claim forgery"',
            "      Parallel requests",
            '        "Race conditions"',
            "      Rate limits",
            '        "Brute force / enumeration"',
        ]
    elif target_type == "mobile":
        lines += [
            "      WebView",
            '        "JS bridge injection"',
            "      Deep links",
            '        "URI scheme hijack"',
            "      Certificate pinning",
            '        "Frida bypass → traffic analysis"',
            "      Local storage",
            '        "Secrets in AsyncStorage/SQLite"',
            "      SDK callbacks",
            '        "Event spoofing"',
        ]

    # Add tech-specific nodes
    for tech in techs:
        tech_lower = tech.lower().strip()
        if tech_lower in TECH_CHECKS:
            lines.append(f"    {tech.upper()}")
            for _, desc, _ in TECH_CHECKS[tech_lower]:
                short = desc.split(" — ")[0]
                lines.append(f'      "{short}"')

    lines.append("```")
    return "\n".join(lines)


# ─── Checklist generation ─────────────────────────────────────────────────────

def build_checklist(target_type: str, techs: list[str]) -> str:
    """Generate a prioritized hunting checklist."""
    type_map = {
        "website": WEBSITE_CHECKS,
        "opensrc": OPENSRC_CHECKS,
        "api":     API_CHECKS,
        "mobile":  MOBILE_CHECKS,
    }
    checks = list(type_map.get(target_type, WEBSITE_CHECKS))

    # Add tech-specific checks
    for tech in techs:
        tech_lower = tech.lower().strip()
        if tech_lower in TECH_CHECKS:
            checks.extend(TECH_CHECKS[tech_lower])

    # Sort by impact: HIGH first, then MED, then LOW
    order = {"HIGH": 0, "MED": 1, "LOW": 2}
    checks.sort(key=lambda x: order.get(x[0], 3))

    lines = ["### Prioritized Hunting Checklist\n"]
    lines.append("| Priority | Check | Reference |")
    lines.append("|---|---|---|")
    for impact, desc, ref in checks:
        if impact == "HIGH":
            badge = "🔴 HIGH"
        elif impact == "MED":
            badge = "🟡 MED"
        else:
            badge = "🟢 LOW"
        lines.append(f"| {badge} | {desc} | `{ref}` |")

    return "\n".join(lines)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generate bug bounty mind map and checklist")
    parser.add_argument("--target", required=True, help="Target domain or name (e.g., worldcoin.org)")
    parser.add_argument("--type",   required=True, choices=["website", "opensrc", "api", "mobile"],
                        help="Target type")
    parser.add_argument("--tech",   default="", help="Comma-separated technologies (e.g., nextjs,graphql,solidity)")
    parser.add_argument("--output", default="", help="Output file path (default: findings/TARGET/mindmap.md)")
    args = parser.parse_args()

    target = args.target
    target_type = args.type
    techs = [t.strip() for t in args.tech.split(",") if t.strip()] if args.tech else []

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        base_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "findings", target)
        os.makedirs(base_dir, exist_ok=True)
        output_path = os.path.join(base_dir, "mindmap.md")

    # Build content
    mermaid = build_mermaid(target, target_type, techs)
    checklist = build_checklist(target_type, techs)

    content = f"""# Bug Bounty Mind Map — {target}

**Target:** {target}
**Type:** {target_type}
**Technologies:** {', '.join(techs) if techs else 'unknown'}
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}

---

## Attack Surface Mind Map

{mermaid}

---

{checklist}

---

## Quick-Start Commands

```bash
# Start recon
/bug-bounty-recon

# Learn about this tech stack
/bug-bounty-learn

# Hunt specific vuln type from checklist
/bug-bounty-hunt

# Generate payloads
/bug-bounty-payloads

# Validate a finding and write report
/bug-bounty-report
```

## Notes

<!-- Add your testing notes here -->
"""

    with open(output_path, "w") as f:
        f.write(content)

    print(f"{BOLD}{CYAN}Mind map generated:{RESET} {output_path}")
    print()

    # Print checklist to terminal too
    print(f"{BOLD}Target:{RESET} {target}  |  {BOLD}Type:{RESET} {target_type}  |  {BOLD}Tech:{RESET} {', '.join(techs) or 'none'}")
    print()

    type_map = {
        "website": WEBSITE_CHECKS,
        "opensrc": OPENSRC_CHECKS,
        "api":     API_CHECKS,
        "mobile":  MOBILE_CHECKS,
    }
    checks = list(type_map.get(target_type, WEBSITE_CHECKS))
    for tech in techs:
        if tech.lower() in TECH_CHECKS:
            checks.extend(TECH_CHECKS[tech.lower()])

    order = {"HIGH": 0, "MED": 1, "LOW": 2}
    checks.sort(key=lambda x: order.get(x[0], 3))

    color_map = {"HIGH": RED, "MED": YELLOW, "LOW": GREEN}
    for impact, desc, ref in checks:
        c = color_map.get(impact, "")
        print(f"  {c}[{impact}]{RESET}  {desc}")
        print(f"         → {ref}")
    print()


if __name__ == "__main__":
    main()
