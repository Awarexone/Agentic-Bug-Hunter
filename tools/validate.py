#!/usr/bin/env python3
"""
validate.py — Interactive bug validation assistant.
Walks through the 4 validation gates, checks for duplicates, calculates CVSS,
and generates a skeleton HackerOne report.

The 4 gates and the CVSS 4.0 calculator are pure functions in
tools/validation_core.py — this file is a thin interactive wrapper around
them (prompts, printing, network dup-checks, file output). That's what lets
the exact same gate logic run headless via --non-interactive for the
autonomous path.

Usage:
  python3 tools/validate.py
  python3 tools/validate.py --output findings/myreport.md
  python3 tools/validate.py --json --non-interactive --input finding.json
"""

import argparse
import json
import os
import ssl
import sys
import urllib.request
import urllib.error
from datetime import datetime

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
from tools.banner import print_banner  # noqa: E402
from tools import validation_core as vcore  # noqa: E402
from tools.validation_core import (  # noqa: E402,F401
    calculate_cvss40,
    severity_from_score,
    ValidationInputError,
)

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


def ask_yn_required(prompt: str) -> bool:
    """Ask a required yes/no question. Blank answers auto-fail."""
    while True:
        val = input(f"  {prompt} [y/n]: ").strip().lower()
        if val in ("y", "yes"):
            return True
        if val in ("n", "no"):
            return False
        if not val:
            print(f"  {YELLOW}Blank answer auto-fails this check.{RESET}")
            return False
        print(f"  {YELLOW}Enter y or n.{RESET}")


def load_json_file(path: str) -> dict:
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {}
    except Exception as exc:
        print(f"  {YELLOW}Could not read JSON file {path}: {exc}{RESET}")
        return {}


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


# ─── Gate implementations (thin wrappers over validation_core) ───────────────
# Each gate collects the same prompts in the same order as before, then hands
# the answers to validation_core's pure gate function for the pass/fail
# decision — that decision is made in exactly one place now.

def gate1_is_real(vuln_type: str = "") -> tuple[bool, dict]:
    gate_header(1, "Is It Real?")
    print("  Can you reproduce the bug from scratch — clean browser, no Burp artifacts?")
    print()
    repro3   = ask_yn("Reproduced 3/3 times deterministically?")
    no_burp  = ask_yn("Works with plain curl or fresh browser (not just in Burp)?")
    no_state = ask_yn("No unusual preconditions (doesn't require specific timing or race)?")
    rtfm     = ask_yn("Checked documentation — this isn't expected/documented behavior?")

    data = {
        "vuln_type":               vuln_type,
        "repro_3_3":               repro3,
        "works_without_proxy":     no_burp,
        "no_special_state":        no_state,
        "not_documented_behavior": rtfm,
    }

    # Identity check for auth/access-control findings.
    # The #1 reason IDOR/ATO get N/A: tester only accessed their own data.
    if vcore.is_auth_related(vuln_type):
        print(f"\n  {CYAN}Identity Check  (required — auth-related vuln type detected){RESET}")
        print(f"  {DIM}Most IDOR/ATO N/As happen because the tester only read their own data.{RESET}\n")
        cross_account = ask_yn_required("Tested with two accounts: Session A read Session B's data (not your own)?")
        fresh_session = ask_yn_required("Reproduced with a fresh session (not your existing logged-in cookie)?")
        anon_delta    = ask_yn_required("Confirmed the delta: anonymous is blocked, attacker-authenticated succeeds?")
        data.update({
            "cross_account_tested": cross_account,
            "fresh_session_tested": fresh_session,
            "anon_vs_auth_delta":   anon_delta,
        })

    result = vcore.gate1_is_real(data)
    passed, notes = result["passed"], result["notes"]

    if notes.get("identity_required") and notes.get("rejection_reason") == "identity_not_proven":
        print(f"\n  {RED}Identity check FAIL — gate cannot pass without cross-account proof.{RESET}")

    if not passed:
        print(f"\n  {RED}GATE 1 FAIL: {notes['rejection_reason']}{RESET}")
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

    result = vcore.gate2_in_scope({
        "asset_in_scope": asset_in_scope,
        "not_excluded":   not_excluded,
        "version_ok":     version_ok,
    })
    passed, notes = result["passed"], result["notes"]

    if not passed:
        print(f"\n  {RED}GATE 2 FAIL: out_of_scope{RESET}")
        print(f"  {DIM}Confirm scope before submitting.{RESET}")
    else:
        print(f"\n  {GREEN}GATE 2 PASS{RESET}")

    return passed, notes


def gate3_exploitable() -> tuple[bool, dict]:
    gate_header(3, "Is It Exploitable?")
    print("  Can you demonstrate concrete impact without unrealistic preconditions?")
    print()

    concrete_impact = ask_yn("Can you show concrete impact (not just 'theoretically an attacker could')?")
    no_unrealistic  = ask_yn("No unrealistic preconditions (not 'must be admin already', not 'victim must run JS')?")

    print()
    print("  What is the concrete impact? (be specific)")
    impact_desc = ask("Describe the impact")

    # Require a real curl PoC — yes/no on "have proof" is not enough.
    # A blank answer here is an automatic FAIL. This is the primary false-positive filter.
    print()
    print(f"  {BOLD}Paste the exact curl command that reproduces this.{RESET}")
    print(f"  {DIM}Example: curl -s 'https://target.com/api/user/456' -H 'Cookie: sess=ATTACKER'{RESET}")
    print(f"  {YELLOW}Leave blank or type 'skip' → auto-FAIL (no proof = no submit){RESET}")
    curl_poc = ask("curl PoC").strip()

    result = vcore.gate3_exploitable({
        "concrete_impact":              concrete_impact,
        "no_unrealistic_preconditions": no_unrealistic,
        "curl_poc":                     curl_poc,
        "impact_description":           impact_desc,
    })
    passed, notes = result["passed"], result["notes"]

    if not notes["has_proof"]:
        print(f"\n  {RED}No PoC provided — this is a scanner hit, not a confirmed finding.{RESET}")
        print(f"  {DIM}Reproduce it with curl, then come back.{RESET}")

    if not passed:
        print(f"\n  {RED}GATE 3 FAIL: {notes['rejection_reason']}{RESET}")
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

    result = vcore.gate4_not_dup({
        "not_in_h1_disclosed":  not_disclosed,
        "not_in_github_issues": not_in_issues,
        "checked_git_history":  checked_history,
        "h1_similar_reports":   [r.get("title") for r in h1_results],
    })
    passed, notes = result["passed"], result["notes"]

    if not passed:
        print(f"\n  {RED}GATE 4 FAIL: duplicate_or_already_disclosed{RESET}")
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
    scanner_confidence = info.get("scanner_confidence", "unknown")
    validation_status = info.get("validation_status", "scanner_hit")
    scanner_summary = info.get("scanner_summary", {})
    date       = datetime.now().strftime("%Y-%m-%d")

    return f"""# {vuln_type} on {endpoint} — [fill in specific impact]

**Program:** {target}
**Severity:** {sev} ({score}) — {vector}
**Scanner Confidence:** {scanner_confidence}
**Validation Status:** {validation_status}
**Scanner Summary:** {scanner_summary if scanner_summary else "n/a"}
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


PRE_SUBMIT_CHECKLIST = [
    "Title follows formula: [Class] in [endpoint] allows [actor] to [impact]",
    "First sentence states exact impact in plain English",
    "Steps to Reproduce has exact HTTP request (copy-paste ready)",
    "Response showing the bug is included (screenshot or JSON body)",
    "Two test accounts used — not just one account testing itself",
    "CVSS score calculated and included",
    "Recommended fix is 1-2 sentences (not a lecture)",
    "No typos in endpoint paths or parameter names",
    "Report is < 600 words — triagers skim long reports",
    "Severity claimed matches impact described — don't overclaim",
    "Never used \"could potentially\" or \"may allow\"",
    "PoC is reproducible by triager from a fresh state",
]


def write_submission_notes(
    output_dir: str,
    report_path: str,
    info: dict,
    gates: list[tuple[int, str, bool]],
    all_pass: bool,
    notes_path: str = "",
) -> str:
    """Persist terminal guidance that would otherwise be lost in scrollback."""
    path = notes_path or os.path.join(output_dir, "submission-notes.md")
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    gate_rows = "\n".join(
        f"| Gate {n} | {name} | {'PASS' if passed else 'FAIL'} |"
        for n, name, passed in gates
    )
    checklist = "\n".join(f"- [ ] {item}" for item in PRE_SUBMIT_CHECKLIST)
    verdict = (
        "All validation gates passed. The report is a submission candidate after "
        "you fill in the exact request, response, screenshots, and fix notes."
        if all_pass else
        "One or more validation gates failed. Keep this as a draft until the "
        "failed gates are resolved; do not submit it yet."
    )

    content = f"""# Submission Notes

Generated: {date}

## Finding

- Program: {info.get('target', 'unknown')}
- Vulnerability type: {info.get('vuln_type', 'unknown')}
- Endpoint: {info.get('endpoint', 'unknown')}
- Scanner confidence: {info.get('scanner_confidence', 'unknown')}
- Validation status: {info.get('validation_status', 'scanner_hit')}
- Report draft: {report_path}
- CVSS: {info.get('cvss_score', 'n/a')} — `{info.get('cvss_vector', 'n/a')}`

## Validation Summary

| Gate | Question | Result |
|---|---|---|
{gate_rows}

## One Note Before Submitting

{verdict}

## Final Checklist Before Submitting

{checklist}

## References

- `commands/report.md` — platform-specific report structure.
- `skills/report-writing/SKILL.md` — impact-first templates, downgrade counters, and pre-submit checklist.
- `skills/triage-validation/SKILL.md` — 7-Question Gate and never-submit list.
- https://www.first.org/cvss/calculator/4.0 — verify the CVSS 4.0 vector.
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def write_validation_json(output_dir: str, info: dict, gate_notes: dict) -> str:
    """Persist the structured validation answers for future tmux/session pickup."""
    path = os.path.join(output_dir, "validation.json")

    all_pass = all([
        info.get("gate1_pass"), info.get("gate2_pass"),
        info.get("gate3_pass"), info.get("gate4_pass"),
    ])

    # Collect rejection reasons across all failed gates (chain-not-proven is set by caller)
    rejection_reasons = [
        n.get("rejection_reason")
        for n in gate_notes.values()
        if n.get("rejection_reason")
    ]

    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        # scanner_confidence comes from --scanner-confidence CLI arg (confirmed/possible/informational/unknown)
        "scanner_confidence": info.get("scanner_confidence", "unknown"),
        # validated_finding = all 4 gates passed with real curl PoC
        # scanner_hit = gates failed or no PoC — do not submit
        "status": "validated_finding" if all_pass else "scanner_hit",
        "curl_poc": info.get("curl_poc", ""),
        "scanner_summary": info.get("scanner_summary", {}),
        "rejection_reasons": rejection_reasons,
        "finding": {
            "program":            info.get("target"),
            "vulnerability_type": info.get("vuln_type"),
            "endpoint":           info.get("endpoint"),
            "impact":             info.get("impact"),
            "curl_poc":           info.get("curl_poc", ""),
            "cvss_score":         info.get("cvss_score"),
            "cvss_vector":        info.get("cvss_vector"),
            "cvss_params":        info.get("cvss_params"),
        },
        "gates": {
            "is_real":      {"passed": info.get("gate1_pass"), "notes": gate_notes["gate1"]},
            "in_scope":     {"passed": info.get("gate2_pass"), "notes": gate_notes["gate2"]},
            "exploitable":  {"passed": info.get("gate3_pass"), "notes": gate_notes["gate3"]},
            "not_duplicate":{"passed": info.get("gate4_pass"), "notes": gate_notes["gate4"]},
        },
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")
    return path


# ─── Non-interactive / headless mode ──────────────────────────────────────────

def _run_non_interactive(args) -> int:
    """Read a finding dict from --input, run validation_core.evaluate_finding(),
    print the result as JSON on stdout. Exit 0 if overall_pass, 1 if not,
    2 on a malformed/missing input file (usage error, not a gate failure)."""
    if not args.input:
        print(json.dumps({"error": "--non-interactive requires --input <finding.json>"}))
        return 2

    try:
        with open(args.input, "r", encoding="utf-8") as fh:
            finding = json.load(fh)
    except FileNotFoundError:
        print(json.dumps({"error": f"input file not found: {args.input}"}))
        return 2
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"invalid JSON in {args.input}: {exc}"}))
        return 2

    try:
        result = vcore.evaluate_finding(finding)
    except ValidationInputError as exc:
        print(json.dumps({"error": str(exc)}))
        return 2

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["overall_pass"] else 1


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Interactive bug validation assistant")
    parser.add_argument("--output",  default="", help="Output path for generated report skeleton")
    parser.add_argument("--notes-output", default="", help="Output path for persisted submission notes")
    parser.add_argument("--program", default="", help="HackerOne program handle for dup check")
    parser.add_argument(
        "--scanner-summary",
        default="",
        help="Path to tools/vuln_scanner.sh summary.json for calibration handoff",
    )
    parser.add_argument(
        "--scanner-confidence",
        default="unknown",
        choices=["confirmed", "possible", "informational", "unknown"],
        help="Confidence level from the scanner that produced this finding",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Skip all prompts. Read a finding dict from --input, run the 4 gates "
             "+ CVSS headlessly, print gate verdicts + overall pass/fail as JSON. "
             "Exit 0 if all gates pass, 1 if any fail, 2 on malformed input.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Alias for --non-interactive's output format (JSON is always used "
             "in --non-interactive mode; this flag exists for command-line clarity).",
    )
    parser.add_argument(
        "--input",
        default="",
        help="Path to a finding JSON file (required with --non-interactive). "
             "See validation_core.evaluate_finding() for the expected shape.",
    )
    args = parser.parse_args()

    if args.non_interactive:
        return _run_non_interactive(args)

    print_banner(
        "Bug Validation Assistant",
        target=args.program or None,
        steps=[
            ("Gate 1 — Real",        "is the finding reproducible / not a placebo?"),
            ("Gate 2 — In scope",    "matches program scope + asset list"),
            ("Gate 3 — Exploitable", "real attacker, real impact, right now"),
            ("Gate 4 — Not dup",     "search disclosures + Hacktivity"),
            ("CVSS + report",        "score + H1 report skeleton"),
        ],
    )

    # Collect basic info upfront
    section("Target Information")
    target_program = args.program or ask("HackerOne program handle (e.g., 'target-program')", "unknown")
    vuln_type      = ask("Vulnerability type (e.g., 'IDOR', 'Stored XSS', 'SSRF')")
    endpoint       = ask("Affected endpoint (e.g., '/api/invoices/:id')")
    scanner_summary = load_json_file(args.scanner_summary)

    # Run the 4 gates
    g1_pass, g1_notes = gate1_is_real(vuln_type)
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
        "target":             target_program,
        "vuln_type":          vuln_type,
        "endpoint":           endpoint,
        "impact":             impact_desc,
        "curl_poc":           g3_notes.get("curl_poc", ""),
        "scanner_confidence": args.scanner_confidence,
        "scanner_summary":    scanner_summary,
        "cvss_score":         cvss_score,
        "cvss_vector":        cvss_vector,
        "cvss_params":        cvss_params,
        "gate1_pass":         g1_pass,
        "gate2_pass":         g2_pass,
        "gate3_pass":         g3_pass,
        "gate4_pass":         g4_pass,
        "validation_status":  "validated_finding" if all_pass else "scanner_hit",
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

    output_dir = os.path.dirname(os.path.abspath(output_path)) or "."
    os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(skeleton)

    notes_path = write_submission_notes(output_dir, output_path, info, gates, all_pass, args.notes_output)
    validation_path = write_validation_json(output_dir, info, {
        "gate1": g1_notes,
        "gate2": g2_notes,
        "gate3": g3_notes,
        "gate4": g4_notes,
    })

    print(f"  {BOLD}{GREEN}Report skeleton generated:{RESET} {output_path}")
    print(f"  {BOLD}{GREEN}Submission notes saved:{RESET} {notes_path}")
    print(f"  {BOLD}{GREEN}Validation JSON saved:{RESET} {validation_path}")
    print(f"\n  {BOLD}Next steps:{RESET}")
    print(f"    1. Fill in the actual HTTP request + response in the PoC section")
    print(f"    2. Attach screenshots (naming: TARGET-VULN-TYPE-STEP-N.png)")
    print(f"    3. Replace all [bracketed] placeholders with specific details")
    print(f"    4. Review submission-notes.md before sending the report")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
