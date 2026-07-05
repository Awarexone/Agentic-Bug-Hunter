#!/usr/bin/env python3
"""
HackerOne Target Selector
Fetches public bug bounty programs, ranks them, and outputs top targets.

Usage:
    python3 target_selector.py [--top N] [--output FILE]
"""

import json
import subprocess
import sys
import os
import argparse
from datetime import datetime

TARGETS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "targets")
DEFAULT_OUTPUT = os.path.join(TARGETS_DIR, "selected_targets.json")

# HackerOne directory API (public data)
H1_DIRECTORY_URL = "https://hackerone.com/opportunities/all/search?ordering=started_accepting_at&asset_types=URL&asset_types=WILDCARD&asset_types=DOMAIN"


def fetch_programs():
    """Fetch public HackerOne programs via their directory API."""
    print("[*] Fetching HackerOne programs...")

    programs = []

    # Method 1: HackerOne directory GraphQL-like endpoint
    try:
        result = subprocess.run(
            [
                "curl", "-s", "-H", "Accept: application/json",
                "https://hackerone.com/opportunities/all/search?ordering=started_accepting_at&limit=100&asset_types=URL&asset_types=WILDCARD&asset_types=DOMAIN"
            ],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            if "data" in data:
                for prog in data["data"]:
                    programs.append(parse_h1_program(prog))
                print(f"    [+] Fetched {len(programs)} programs from HackerOne directory")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
        print(f"    [!] HackerOne directory fetch failed: {e}")

    # Method 2: Fallback - fetch from public program list
    if not programs:
        print("    [*] Trying fallback: HackerOne public program list...")
        try:
            result = subprocess.run(
                [
                    "curl", "-s",
                    "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json"
                ],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                for prog in data:
                    programs.append(parse_bounty_targets_program(prog))
                print(f"    [+] Fetched {len(programs)} programs from bounty-targets-data")
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
            print(f"    [!] Fallback fetch failed: {e}")

    # Method 3: Second fallback - use curated list
    if not programs:
        print("    [*] Using curated fallback program list...")
        programs = get_curated_programs()

    return programs


def parse_h1_program(prog):
    """Parse a program from HackerOne directory API."""
    return {
        "name": prog.get("name", "Unknown"),
        "handle": prog.get("handle", ""),
        "url": f"https://hackerone.com/{prog.get('handle', '')}",
        "managed": prog.get("triage_active", False),
        "bounty_min": prog.get("minimum_bounty_table_value", 0),
        "bounty_max": prog.get("maximum_bounty_table_value", 0),
        "response_efficiency": prog.get("response_efficiency_percentage", 0),
        "assets": prog.get("scopes", []),
        "has_wildcard": any(
            "*" in (s.get("asset_identifier", "") if isinstance(s, dict) else str(s))
            for s in prog.get("scopes", [])
        ),
        "started_accepting_at": prog.get("started_accepting_at", ""),
        "source": "hackerone_directory"
    }


def parse_bounty_targets_program(prog):
    """Parse a program from bounty-targets-data."""
    targets = prog.get("targets", {})
    in_scope = targets.get("in_scope", [])

    # Extract domains from in_scope
    domains = []
    has_wildcard = False
    for scope in in_scope:
        identifier = scope.get("asset_identifier", "")
        asset_type = scope.get("asset_type", "")
        if asset_type in ("URL", "WILDCARD", "DOMAIN") or "." in identifier:
            domains.append({
                "asset_identifier": identifier,
                "asset_type": asset_type,
                "eligible_for_bounty": scope.get("eligible_for_bounty", False)
            })
            if "*" in identifier:
                has_wildcard = True

    return {
        "name": prog.get("name", "Unknown"),
        "handle": prog.get("handle", ""),
        "url": f"https://hackerone.com/{prog.get('handle', '')}",
        "managed": prog.get("managed", False),
        "bounty_min": 0,
        "bounty_max": 0,
        "response_efficiency": 0,
        "assets": domains,
        "has_wildcard": has_wildcard,
        "started_accepting_at": prog.get("started_accepting_at", ""),
        "source": "bounty_targets_data"
    }


def get_curated_programs():
    """Curated list of known good bug bounty targets for when APIs are down."""
    return [
        {
            "name": "Example Program (placeholder)",
            "handle": "example",
            "url": "https://hackerone.com/example",
            "managed": False,
            "bounty_min": 100,
            "bounty_max": 10000,
            "response_efficiency": 80,
            "assets": [],
            "has_wildcard": True,
            "started_accepting_at": "",
            "source": "curated_fallback",
            "note": "Replace with actual targets - run with internet access to fetch real programs"
        }
    ]


def score_program(prog):
    """Score a program for targeting priority (higher = better)."""
    score = 0

    # Wildcard scope is very valuable (more attack surface)
    if prog.get("has_wildcard"):
        score += 30

    # More assets = more attack surface
    asset_count = len(prog.get("assets", []))
    score += min(asset_count * 2, 20)

    # Higher bounties are better
    bounty_max = prog.get("bounty_max", 0)
    if bounty_max >= 10000:
        score += 25
    elif bounty_max >= 5000:
        score += 20
    elif bounty_max >= 1000:
        score += 15
    elif bounty_max > 0:
        score += 10

    # Good response efficiency means faster triage
    efficiency = prog.get("response_efficiency", 0)
    if efficiency >= 90:
        score += 15
    elif efficiency >= 70:
        score += 10
    elif efficiency >= 50:
        score += 5

    # Newer programs may have more low-hanging fruit
    start_date = prog.get("started_accepting_at", "")
    if start_date:
        try:
            start = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
            age_days = (datetime.now(start.tzinfo) - start).days
            if age_days < 90:
                score += 20  # Very new
            elif age_days < 365:
                score += 10  # Less than a year
        except (ValueError, TypeError):
            pass

    # Managed programs have faster triage
    if prog.get("managed"):
        score += 5

    return score


def extract_scope_domains(prog):
    """Extract in-scope domains for scanning."""
    domains = []
    for asset in prog.get("assets", []):
        if isinstance(asset, dict):
            identifier = asset.get("asset_identifier", "")
        else:
            identifier = str(asset)

        # Clean up the identifier
        identifier = identifier.strip()
        if not identifier:
            continue

        # Remove protocol prefixes
        for prefix in ("https://", "http://", "*."):
            if identifier.startswith(prefix):
                identifier = identifier[len(prefix):]

        # Remove trailing paths
        identifier = identifier.split("/")[0]

        if "." in identifier and identifier not in domains:
            domains.append(identifier)

    return domains


def select_targets(programs, top_n=10):
    """Score and rank programs, return top N."""
    print(f"\n[*] Scoring {len(programs)} programs...")

    scored = []
    for prog in programs:
        prog["score"] = score_program(prog)
        prog["scope_domains"] = extract_scope_domains(prog)
        scored.append(prog)

    # Sort by score descending
    scored.sort(key=lambda x: x["score"], reverse=True)

    selected = scored[:top_n]

    print(f"[+] Selected top {len(selected)} targets:\n")
    for i, prog in enumerate(selected, 1):
        domains = prog["scope_domains"]
        domain_str = ", ".join(domains[:3])
        if len(domains) > 3:
            domain_str += f" (+{len(domains)-3} more)"

        print(f"  {i:2d}. [{prog['score']:3d} pts] {prog['name']}")
        print(f"      URL: {prog['url']}")
        print(f"      Wildcard: {'Yes' if prog['has_wildcard'] else 'No'} | "
              f"Bounty: ${prog.get('bounty_min', '?')}-${prog.get('bounty_max', '?')} | "
              f"Assets: {len(prog.get('assets', []))}")
        if domain_str:
            print(f"      Domains: {domain_str}")
        print()

    return selected


def save_targets(targets, output_file):
    """Save selected targets to JSON."""
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    output = {
        "generated_at": datetime.now().isoformat(),
        "total_targets": len(targets),
        "targets": targets,
        "scope_checklist": [
            "Verify each target's scope on their HackerOne page before scanning",
            "Check for out-of-scope domains and IP ranges",
            "Review program policy for rate limiting requirements",
            "Check if automated scanning is allowed",
            "Note any specific testing restrictions (no DoS, no social engineering, etc.)",
            "Verify bounty eligibility for asset types you plan to test"
        ]
    }

    with open(output_file, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print(f"[+] Saved to {output_file}")
    return output_file


def main():
    parser = argparse.ArgumentParser(description="HackerOne Target Selector")
    parser.add_argument("--top", type=int, default=10, help="Number of top targets to select")
    parser.add_argument("--output", type=str, default=DEFAULT_OUTPUT, help="Output JSON file")
    args = parser.parse_args()

    print("=============================================")
    print("  HackerOne Target Selector")
    print("=============================================")

    programs = fetch_programs()
    if not programs:
        print("[-] No programs found. Check your internet connection.")
        sys.exit(1)

    selected = select_targets(programs, top_n=args.top)
    save_targets(selected, args.output)

    print("\n=============================================")
    print("  IMPORTANT: Scope Checklist")
    print("=============================================")
    print("  Before scanning ANY target:")
    print("  1. Visit the program page and read the full policy")
    print("  2. Verify domains are in-scope")
    print("  3. Check for rate limiting / automation rules")
    print("  4. Note out-of-scope areas")
    print("  5. Only test assets eligible for bounty")
    print("=============================================")


if __name__ == "__main__":
    main()
