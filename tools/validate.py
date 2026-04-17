#!/usr/bin/env python3
"""
validate.py — Interactive bug validation assistant.
Walks through the 4 validation gates, checks for duplicates, calculates CVSS,
and generates a skeleton HackerOne report.

Usage:
  python3 tools/validate.py
  python3 tools/validate.py --output findings/myreport.md
"""

import argparse
import json
import os
import ssl
import sys
import urllib.request
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
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ─── CVSS 4.0 scoring ─────────────────────────────────────────────────────────
# Implements the CVSS 4.0 macro-vector approach from FIRST.org.
# For authoritative scores verify at: https://www.first.org/cvss/calculator/4.0

def _eq1(av: str, pr: str, ui: str) -> int:
    """EQ1: Attack Vector / Privileges Required / User Interaction (0=highest severity)."""
    if av == "N" and (pr == "N" or ui == "N"):
        return 0
    if av == "N" or pr == "N" or ui == "N":
        return 1
    return 2

def _eq2(ac: str, at: str) -> int:
    """EQ2: Attack Complexity / Attack Requirements."""
    return 0 if (ac == "L" and at == "N") else 1

def _eq3(vc: str, vi: str, va: str) -> int:
    """EQ3: Vulnerable System CIA impact."""
    if vc == "H" and vi == "H":
        return 0
    if vc == "H" or vi == "H" or va == "H":
        return 1
    return 2

def _eq4(sc: str, si: str, sa: str) -> int:
    """EQ4: Subsequent System impact (Safety > High > Low/None)."""
    if si == "S" or sa == "S":
        return 0
    if sc == "H" or si == "H" or sa == "H":
        return 1
    return 2

# CVSS 4.0 base score lookup by macro vector (eq1, eq2, eq3, eq4).
# EQ5=0 (E=Active, default for base metrics).
# EQ6 is derived from EQ3 with default CR=IR=AR=High.
# Values approximate FIRST.org CVSS 4.0 specification.
# Verify exact scores at: https://www.first.org/cvss/calculator/4.0
#
# eq1: 0=Network+(no-auth or no-UI), 1=partial advantage, 2=local/physical/high-priv+UI
# eq2: 0=Low-complexity+no-prereqs, 1=otherwise
# eq3: 0=VC+VI both High, 1=partial High, 2=no High CIA on vulnerable system
# eq4: 0=Safety impact, 1=High subsequent-system impact, 2=no subsequent impact
_CVSS40_TABLE: dict[tuple[int, int, int, int], float] = {
    # eq1=0 (widest attack reach: network + no-auth OR no-UI)
    (0, 0, 0, 0): 10.0, (0, 0, 0, 1): 10.0, (0, 0, 0, 2): 9.3,
    (0, 0, 1, 0): 9.5,  (0, 0, 1, 1): 9.1,  (0, 0, 1, 2): 7.1,
    (0, 0, 2, 0): 7.9,  (0, 0, 2, 1): 6.9,  (0, 0, 2, 2): 4.8,
    (0, 1, 0, 0): 9.5,  (0, 1, 0, 1): 9.1,  (0, 1, 0, 2): 8.0,
    (0, 1, 1, 0): 8.9,  (0, 1, 1, 1): 8.5,  (0, 1, 1, 2): 6.5,
    (0, 1, 2, 0): 7.0,  (0, 1, 2, 1): 5.5,  (0, 1, 2, 2): 4.0,
    # eq1=1 (some network/auth/UI advantage)
    (1, 0, 0, 0): 9.3,  (1, 0, 0, 1): 9.0,  (1, 0, 0, 2): 7.8,
    (1, 0, 1, 0): 8.8,  (1, 0, 1, 1): 8.5,  (1, 0, 1, 2): 6.5,
    (1, 0, 2, 0): 7.0,  (1, 0, 2, 1): 6.0,  (1, 0, 2, 2): 4.5,
    (1, 1, 0, 0): 9.0,  (1, 1, 0, 1): 8.5,  (1, 1, 0, 2): 7.5,
    (1, 1, 1, 0): 8.5,  (1, 1, 1, 1): 7.5,  (1, 1, 1, 2): 5.9,
    (1, 1, 2, 0): 6.0,  (1, 1, 2, 1): 5.5,  (1, 1, 2, 2): 3.5,
    # eq1=2 (local/physical or high-privileges + active UI required)
    (2, 0, 0, 0): 9.0,  (2, 0, 0, 1): 8.5,  (2, 0, 0, 2): 7.5,
    (2, 0, 1, 0): 8.0,  (2, 0, 1, 1): 7.5,  (2, 0, 1, 2): 6.5,
    (2, 0, 2, 0): 6.0,  (2, 0, 2, 1): 5.5,  (2, 0, 2, 2): 4.0,
    (2, 1, 0, 0): 8.5,  (2, 1, 0, 1): 8.0,  (2, 1, 0, 2): 7.0,
    (2, 1, 1, 0): 7.5,  (2, 1, 1, 1): 7.0,  (2, 1, 1, 2): 5.5,
    (2, 1, 2, 0): 5.5,  (2, 1, 2, 1): 5.0,  (2, 1, 2, 2): 3.5,
}


def calculate_cvss40(av, ac, at, pr, ui, vc, vi, va, sc, si, sa) -> tuple[float, str]:
    """Calculate CVSS 4.0 base score (approximate) and return (score, vector_string)."""
    e1 = _eq1(av, pr, ui)
    e2 = _eq2(ac, at)
    e3 = _eq3(vc, vi, va)
    e4 = _eq4(sc, si, sa)
    score = _CVSS40_TABLE.get((e1, e2, e3, e4), 5.0)
    vector = (
        f"CVSS:4.0/AV:{av}/AC:{ac}/AT:{at}/PR:{pr}/UI:{ui}"
        f"/VC:{vc}/VI:{vi}/VA:{va}/SC:{sc}/SI:{si}/SA:{sa}"
    )
    return score, vector


def severity_from_score(score: float) -> str:
    if score == 0.0:  return "NONE"
    if score < 4.0:   return "LOW"
    if score < 7.0:   return "MEDIUM"
    if score < 9.0:   return "HIGH"
    return "CRITICAL"


# ─── HackerOne dup check ──────────────────────────────────────────────────────

def check_h1_dups(program_handle: str, vuln_keyword: str) -> list[dict]:
    """Search HackerOne for potential duplicates."""
    if not program_handle:
        return []

    query = {
        "query": f"""{{
          hacktivity_items(
            first: 10,
            order_by: {{ field: popular, direction: DESC }},
            where: {{
              team: {{ handle: {{ _eq: "{program_handle}" }} }},
              report: {{ title: {{ _icontains: "{vuln_keyword}" }} }}
            }}
          ) {{
            nodes {{
              ... on HacktivityDocument {{
                report {{
                  title
                  severity_rating
                  disclosed_at
                  url
                  state
                }}
              }}
            }}
          }}
        }}"""
    }
    try:
        req = urllib.request.Request(
            "https://hackerone.com/graphql",
            data=json.dumps(query).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10, context=_SSL_CTX) as resp:
            data = json.loads(resp.read().decode())
        nodes = (data.get("data") or {}).get("hacktivity_items", {}).get("nodes", [])
        results = []
        for node in nodes:
            r = node.get("report")
            if r:
                results.append(r)
        return results
    except Exception:
        return []


# ─── Interactive prompt helpers ───────────────────────────────────────────────

def ask(prompt: str, default: str = "") -> str:
    if default:
        val = input(f"  {prompt} [{default}]: ").strip()
        return val if val else default
    return input(f"  {prompt}: ").strip()


def ask_yn(prompt: str, default: bool = True) -> bool:
    yn = "Y/n" if default else "y/N"
    val = input(f"  {prompt} [{yn}]: ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes")


def ask_choice(prompt: str, choices: list[tuple[str, str]]) -> str:
    """Ask user to pick from labeled choices. Returns the choice key."""
    print(f"\n  {prompt}")
    for key, label in choices:
        print(f"    {CYAN}{key}{RESET}) {label}")
    while True:
        val = input(f"  Choice: ").strip().upper()
        if val in [k for k, _ in choices]:
            return val
        print(f"  {YELLOW}Invalid — enter one of: {', '.join(k for k,_ in choices)}{RESET}")


def section(title: str):
    print(f"\n{BOLD}{BLUE}{'─' * 60}{RESET}")
    print(f"{BOLD}{BLUE}  {title}{RESET}")
    print(f"{BOLD}{BLUE}{'─' * 60}{RESET}\n")


def gate_header(n: int, name: str, status: str | None = None):
    status_str = ""
    if status == "PASS":
        status_str = f" {GREEN}✓ PASS{RESET}"
    elif status == "FAIL":
        status_str = f" {RED}✗ FAIL{RESET}"
    print(f"\n{BOLD}Gate {n}: {name}{RESET}{status_str}")
    print(f"{'─' * 40}")


# ─── Gate implementations ─────────────────────────────────────────────────────

def gate1_is_real() -> tuple[bool, dict]:
    gate_header(1, "Is It Real?")
    print("  Can you reproduce the bug from scratch — clean browser, no Burp artifacts?")
    print()
    repro3   = ask_yn("Reproduced 3/3 times deterministically?")
    no_burp  = ask_yn("Works with plain curl or fresh browser (not just in Burp)?")
    no_state = ask_yn("No unusual preconditions (doesn't require specific timing or race)?")
    rtfm     = ask_yn("Checked documentation — this isn't expected/documented behavior?")

    passed = repro3 and no_burp and no_state and rtfm
    notes = {
        "repro_3_3": repro3,
        "works_without_proxy": no_burp,
        "no_special_state": no_state,
        "not_documented_behavior": rtfm,
    }

    if not passed:
        print(f"\n  {RED}GATE 1 FAIL: Not reliably reproducible.{RESET}")
        print(f"  {DIM}Do not submit yet. Verify the bug is deterministic first.{RESET}")
    else:
        print(f"\n  {GREEN}GATE 1 PASS{RESET}")

    return passed, notes


def gate2_in_scope(program_handle: str) -> tuple[bool, dict]:
    gate_header(2, "Is It In Scope?")
    print("  Check the program scope page explicitly — don't assume.")
    print()

    asset_in_scope  = ask_yn("The affected domain/asset is listed on the program's scope page?")
    not_excluded    = ask_yn("Not in the out-of-scope list (check staging, third-party exclusions)?")
    version_ok      = ask_yn("Affected software version is in scope (not an excluded old version)?")

    if program_handle:
        print(f"\n  {DIM}Checking HackerOne scope for '{program_handle}'...{RESET}")
        try:
            query = {
                "query": f'{{ team(handle: "{program_handle}") {{ policy_scopes(archived: false) {{ edges {{ node {{ asset_type asset_identifier eligible_for_bounty }} }} }} }} }}'
            }
            req = urllib.request.Request(
                "https://hackerone.com/graphql",
                data=json.dumps(query).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=8, context=_SSL_CTX) as resp:
                data = json.loads(resp.read().decode())
            scopes = (data.get("data") or {}).get("team", {}).get("policy_scopes", {}).get("edges", [])
            if scopes:
                print(f"\n  {CYAN}In-scope assets for {program_handle}:{RESET}")
                for edge in scopes[:10]:
                    node = edge.get("node", {})
                    bounty = " (eligible)" if node.get("eligible_for_bounty") else ""
                    print(f"    • [{node.get('asset_type','?')}] {node.get('asset_identifier','?')}{bounty}")
        except Exception:
            print(f"  {YELLOW}Could not fetch scope (network error){RESET}")

    passed = asset_in_scope and not_excluded and version_ok
    notes = {
        "asset_in_scope": asset_in_scope,
        "not_excluded": not_excluded,
        "version_ok": version_ok,
    }

    if not passed:
        print(f"\n  {RED}GATE 2 FAIL: May be out of scope.{RESET}")
        print(f"  {DIM}Confirm scope before submitting.{RESET}")
    else:
        print(f"\n  {GREEN}GATE 2 PASS{RESET}")

    return passed, notes


def gate3_exploitable() -> tuple[bool, dict]:
    gate_header(3, "Is It Exploitable?")
    print("  Can you demonstrate concrete impact without unrealistic preconditions?")
    print()

    concrete_impact  = ask_yn("Can you show concrete impact (not just 'theoretically an attacker could')?")
    no_unrealistic   = ask_yn("No unrealistic preconditions (not 'must be admin already', not 'victim must run JS')?")
    can_demonstrate  = ask_yn("Have proof you can show a triager (screenshot, curl, PoC)?")

    print()
    print("  What is the concrete impact? (be specific)")
    impact_desc = ask("Describe the impact")

    passed = concrete_impact and no_unrealistic and can_demonstrate
    notes = {
        "concrete_impact": concrete_impact,
        "no_unrealistic_preconditions": no_unrealistic,
        "has_proof": can_demonstrate,
        "impact_description": impact_desc,
    }

    if not passed:
        print(f"\n  {RED}GATE 3 FAIL: Exploitability not demonstrated.{RESET}")
        print(f"  {DIM}Build a working PoC before submitting.{RESET}")
    else:
        print(f"\n  {GREEN}GATE 3 PASS{RESET}")

    return passed, notes


def gate4_not_dup(vuln_type: str, endpoint: str, program_handle: str) -> tuple[bool, dict]:
    gate_header(4, "Is It a Dup?")
    print("  Check HackerOne disclosed reports, GitHub issues, and recent changelog.")
    print()

    # Auto-check HackerOne
    h1_results = []
    if program_handle and vuln_type:
        print(f"  {DIM}Searching HackerOne for '{vuln_type}' in '{program_handle}'...{RESET}")
        h1_results = check_h1_dups(program_handle, vuln_type)
        if h1_results:
            print(f"\n  {YELLOW}Found {len(h1_results)} potentially similar disclosed reports:{RESET}")
            for r in h1_results:
                disclosed = (r.get("disclosed_at") or "")[:10]
                print(f"    • [{r.get('severity_rating','?').upper()}] {r.get('title','')} ({disclosed})")
                if r.get("url"):
                    print(f"      {DIM}{r['url']}{RESET}")
        else:
            print(f"  {GREEN}No similar disclosed reports found on HackerOne.{RESET}")

    print()
    not_disclosed   = ask_yn("Not found in HackerOne disclosed reports for this program?")
    not_in_issues   = ask_yn("Not already fixed/reported in GitHub issues or CHANGELOG?")
    checked_history = ask_yn("Checked git log for recent security fixes with this pattern?")

    passed = not_disclosed and not_in_issues and checked_history
    notes = {
        "not_in_h1_disclosed": not_disclosed,
        "not_in_github_issues": not_in_issues,
        "checked_git_history": checked_history,
        "h1_similar_reports": [r.get("title") for r in h1_results],
    }

    if not passed:
        print(f"\n  {RED}GATE 4 FAIL: Possible duplicate.{RESET}")
        print(f"  {DIM}Verify it's not already known before submitting.{RESET}")
    else:
        print(f"\n  {GREEN}GATE 4 PASS{RESET}")

    return passed, notes


# ─── CVSS 4.0 interactive scorer ─────────────────────────────────────────────

def score_cvss() -> tuple[float, str, dict]:
    section("CVSS 4.0 Scoring")
    print(f"  {DIM}Scores are approximate — verify at https://www.first.org/cvss/calculator/4.0{RESET}\n")

    av = ask_choice("Attack Vector (AV)", [
        ("N", "Network — exploitable remotely over the internet"),
        ("A", "Adjacent — same network segment, Bluetooth, or VLAN"),
        ("L", "Local — requires local OS access or authenticated session"),
        ("P", "Physical — requires physical device access"),
    ])
    ac = ask_choice("Attack Complexity (AC)", [
        ("L", "Low — reliable, reproducible, no special conditions"),
        ("H", "High — requires specific conditions, evasion, or timing"),
    ])
    at = ask_choice("Attack Requirements (AT)  [NEW in 4.0]", [
        ("N", "None — no prerequisite deployment or execution conditions"),
        ("P", "Present — depends on specific target configuration or state"),
    ])
    pr = ask_choice("Privileges Required (PR)", [
        ("N", "None — no account or elevated access needed"),
        ("L", "Low — regular user account"),
        ("H", "High — admin or elevated privileges"),
    ])
    ui = ask_choice("User Interaction (UI)  [Changed in 4.0]", [
        ("N", "None — no victim interaction required"),
        ("P", "Passive — victim must access a URL or open an email (no explicit action)"),
        ("A", "Active — victim must explicitly click, download, or interact"),
    ])

    print(f"\n  {CYAN}Vulnerable System Impact{RESET}  (the component directly attacked)")
    vc = ask_choice("Confidentiality — Vulnerable System (VC)", [
        ("H", "High — complete or significant confidentiality loss"),
        ("L", "Low — partial or constrained disclosure"),
        ("N", "None"),
    ])
    vi = ask_choice("Integrity — Vulnerable System (VI)", [
        ("H", "High — complete or significant integrity loss"),
        ("L", "Low — limited modification possible"),
        ("N", "None"),
    ])
    va = ask_choice("Availability — Vulnerable System (VA)", [
        ("H", "High — complete denial of service"),
        ("L", "Low — reduced performance or intermittent outages"),
        ("N", "None"),
    ])

    print(f"\n  {CYAN}Subsequent System Impact{RESET}  (other systems or users beyond the attacked component)")
    sc = ask_choice("Confidentiality — Subsequent System (SC)", [
        ("H", "High — significant data exposure in downstream systems/users"),
        ("L", "Low — limited disclosure in downstream systems/users"),
        ("N", "None — no impact beyond the vulnerable component"),
    ])
    si = ask_choice("Integrity — Subsequent System (SI)", [
        ("S", "Safety — impacts physical safety of people"),
        ("H", "High — complete integrity loss in downstream system"),
        ("L", "Low — limited modification in downstream system"),
        ("N", "None"),
    ])
    sa = ask_choice("Availability — Subsequent System (SA)", [
        ("S", "Safety — impacts physical safety of people"),
        ("H", "High — complete denial of service in downstream system"),
        ("L", "Low — reduced performance in downstream system"),
        ("N", "None"),
    ])

    score, vector = calculate_cvss40(av, ac, at, pr, ui, vc, vi, va, sc, si, sa)
    sev = severity_from_score(score)

    sev_color = RED if sev in ("CRITICAL", "HIGH") else (YELLOW if sev == "MEDIUM" else GREEN)
    print(f"\n  {BOLD}CVSS 4.0 Score: {sev_color}{score} {sev}{RESET}")
    print(f"  {BOLD}Vector:{RESET} {vector}")
    print(f"  {DIM}Verify: https://www.first.org/cvss/calculator/4.0#{vector}{RESET}")

    params = {
        "AV": av, "AC": ac, "AT": at, "PR": pr, "UI": ui,
        "VC": vc, "VI": vi, "VA": va, "SC": sc, "SI": si, "SA": sa,
    }
    return score, vector, params


# ─── Report skeleton generator ────────────────────────────────────────────────

def generate_report_skeleton(info: dict) -> str:
    """Generate a HackerOne-style report skeleton."""
    vuln_type  = info.get("vuln_type", "VULN_TYPE")
    target     = info.get("target", "TARGET")
    endpoint   = info.get("endpoint", "ENDPOINT")
    impact     = info.get("impact", "IMPACT_DESCRIPTION")
    score      = info.get("cvss_score", 0.0)
    vector     = info.get("cvss_vector", "CVSS:3.1/...")
    sev        = severity_from_score(score)
    date       = datetime.now().strftime("%Y-%m-%d")

    return f"""# {vuln_type} on {endpoint} — [fill in specific impact]

**Program:** {target}
**Severity:** {sev} ({score}) — {vector}
**Date Found:** {date}

---

## Summary

[2-3 sentences. What is the vulnerability? Where is it? What can an attacker do?]

The `{endpoint}` endpoint [describe the vulnerability in one sentence]. By [describe
the attack], an attacker can [describe the concrete impact].

---

## Steps to Reproduce

> **Setup:** Create two accounts — Attacker (email: attacker@test.com) and Victim (email: victim@test.com).

1. Log in as **Attacker**
2. [Step 2 — specific action]
3. [Step 3 — specific request with actual parameter names]
   ```
   [INSERT ACTUAL HTTP REQUEST HERE — e.g., curl command or Burp request]
   ```
4. [Step 4 — what to observe in the response]
5. Confirm: [what proves the vulnerability — e.g., victim's data appears in response]

---

## Proof of Concept

**Request:**
```http
[PASTE ACTUAL REQUEST — METHOD, URL, HEADERS, BODY]
```

**Response:**
```json
[PASTE ACTUAL RESPONSE SHOWING THE VULNERABILITY]
```

**Screenshots:** [attach: TARGET-{vuln_type.lower().replace(' ','-')}-step1.png, etc.]

---

## Impact

{impact}

[Quantify: number of users affected, type of data exposed, what actions an attacker can take]

---

## CVSS

**Vector:** `{vector}`
**Score:** {score} ({sev})

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector (AV) | {info.get('cvss_params', {}).get('AV', '?')} | [explain] |
| Attack Complexity (AC) | {info.get('cvss_params', {}).get('AC', '?')} | [explain] |
| Attack Requirements (AT) | {info.get('cvss_params', {}).get('AT', '?')} | [explain] |
| Privileges Required (PR) | {info.get('cvss_params', {}).get('PR', '?')} | [explain] |
| User Interaction (UI) | {info.get('cvss_params', {}).get('UI', '?')} | [explain] |
| Vuln. Confidentiality (VC) | {info.get('cvss_params', {}).get('VC', '?')} | [explain] |
| Vuln. Integrity (VI) | {info.get('cvss_params', {}).get('VI', '?')} | [explain] |
| Vuln. Availability (VA) | {info.get('cvss_params', {}).get('VA', '?')} | [explain] |
| Subseq. Confidentiality (SC) | {info.get('cvss_params', {}).get('SC', '?')} | [explain] |
| Subseq. Integrity (SI) | {info.get('cvss_params', {}).get('SI', '?')} | [explain] |
| Subseq. Availability (SA) | {info.get('cvss_params', {}).get('SA', '?')} | [explain] |

---

## Fix Recommendation

[Specific code-level fix — name the file, function, and what to change]

Example: In `path/to/file.ts`, the `functionName` function should verify
`resource.user_id === req.user.id` before returning data.

---

## Validation Notes

| Gate | Result |
|---|---|
| Is it real? | {'PASS' if info.get('gate1_pass') else 'FAIL'} |
| Is it in scope? | {'PASS' if info.get('gate2_pass') else 'FAIL'} |
| Is it exploitable? | {'PASS' if info.get('gate3_pass') else 'FAIL'} |
| Is it a dup? | {'PASS' if info.get('gate4_pass') else 'FAIL'} |
"""


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Interactive bug validation assistant")
    parser.add_argument("--output",  default="", help="Output path for generated report skeleton")
    parser.add_argument("--program", default="", help="HackerOne program handle for dup check")
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  Bug Bounty Validation Assistant{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")
    print(f"\nThis will walk you through the 4 validation gates,")
    print(f"calculate your CVSS score, and generate a report skeleton.\n")

    # Collect basic info upfront
    section("Target Information")
    target_program = args.program or ask("HackerOne program handle (e.g., 'target-program')", "unknown")
    vuln_type      = ask("Vulnerability type (e.g., 'IDOR', 'Stored XSS', 'SSRF')")
    endpoint       = ask("Affected endpoint (e.g., '/api/invoices/:id')")

    # Run the 4 gates
    g1_pass, g1_notes = gate1_is_real()
    g2_pass, g2_notes = gate2_in_scope(target_program)
    g3_pass, g3_notes = gate3_exploitable()
    g4_pass, g4_notes = gate4_not_dup(vuln_type, endpoint, target_program)

    # Summary
    section("Validation Summary")
    gates = [
        (1, "Is it real?",       g1_pass),
        (2, "Is it in scope?",   g2_pass),
        (3, "Is it exploitable?",g3_pass),
        (4, "Is it a dup?",      g4_pass),
    ]
    all_pass = all(p for _, _, p in gates)

    for n, name, passed in gates:
        icon = f"{GREEN}✓{RESET}" if passed else f"{RED}✗{RESET}"
        print(f"  Gate {n} — {name}: {icon}")

    print()
    if all_pass:
        print(f"  {BOLD}{GREEN}All gates passed! This looks like a valid finding.{RESET}")
    else:
        failed = [name for _, name, p in gates if not p]
        print(f"  {BOLD}{RED}Failed: {', '.join(failed)}{RESET}")
        print(f"  {DIM}Resolve the failed gates before submitting.{RESET}")

    if not all_pass:
        if not ask_yn("\nContinue to CVSS scoring anyway?", default=False):
            sys.exit(0)

    # CVSS scoring
    cvss_score, cvss_vector, cvss_params = score_cvss()

    # Generate report skeleton
    section("Report Generation")
    impact_desc = g3_notes.get("impact_description", "")

    info = {
        "target":      target_program,
        "vuln_type":   vuln_type,
        "endpoint":    endpoint,
        "impact":      impact_desc,
        "cvss_score":  cvss_score,
        "cvss_vector": cvss_vector,
        "cvss_params": cvss_params,
        "gate1_pass":  g1_pass,
        "gate2_pass":  g2_pass,
        "gate3_pass":  g3_pass,
        "gate4_pass":  g4_pass,
    }

    skeleton = generate_report_skeleton(info)

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        safe_name = vuln_type.lower().replace(" ", "-").replace("/", "-")
        safe_target = target_program.replace(" ", "-")
        base_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "findings", f"{safe_target}-{safe_name}"
        )
        os.makedirs(base_dir, exist_ok=True)
        output_path = os.path.join(base_dir, "hackerone-report.md")

    with open(output_path, "w") as f:
        f.write(skeleton)

    print(f"  {BOLD}{GREEN}Report skeleton generated:{RESET} {output_path}")
    print(f"\n  {BOLD}Next steps:{RESET}")
    print(f"    1. Fill in the actual HTTP request + response in the PoC section")
    print(f"    2. Attach screenshots (naming: TARGET-VULN-TYPE-STEP-N.png)")
    print(f"    3. Replace all [bracketed] placeholders with specific details")
    print(f"    4. Run /bug-bounty-report for the submission checklist")
    print()


if __name__ == "__main__":
    main()
