#!/usr/bin/env python3
"""
intel_engine.py — On-demand intelligence fetch for a target.

Wraps learn.py data sources + HackerOne MCP + hunt memory context.
Called by /intel command. Outputs prioritized intel with memory context.

Usage:
    python3 intel_engine.py --target target.com --tech "nextjs,graphql"
    python3 intel_engine.py --target target.com --tech "nextjs" --program target-program
    python3 intel_engine.py --target target.com --tech "nextjs" --memory-dir ~/.claude/projects/proj/hunt-memory
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

# Import learn.py functions (same repo)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from learn import fetch_github_advisories, fetch_nvd_cves, severity_order

# Try importing HackerOne MCP server
try:
    sys.path.insert(0, os.path.join(BASE_DIR, "..", "mcp", "hackerone-mcp"))
    from server import search_disclosed_reports, get_program_stats, HackerOneAPIError
    H1_MCP_AVAILABLE = True
except ImportError:
    H1_MCP_AVAILABLE = False

# ─── Color codes ─────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


def load_memory_context(memory_dir: str, target: str) -> dict:
    """Load hunt memory context for a target.

    Returns:
        Dict with tested_endpoints, findings, tech_stack, last_hunted, patterns.
    """
    context = {
        "tested_endpoints": [],
        "findings": [],
        "tech_stack": [],
        "last_hunted": None,
        "hunt_sessions": 0,
        "patterns": [],
        "tested_cves": [],
    }

    if not memory_dir or not os.path.isdir(memory_dir):
        return context

    # Load target profile
    targets_dir = os.path.join(memory_dir, "targets")
    if os.path.isdir(targets_dir):
        # Normalize target name to filename
        target_file = target.replace(".", "-").replace("/", "-") + ".json"
        target_path = os.path.join(targets_dir, target_file)
        if os.path.isfile(target_path):
            try:
                with open(target_path) as f:
                    profile = json.load(f)
                context["tested_endpoints"] = profile.get("tested_endpoints", [])
                context["findings"] = profile.get("findings", [])
                context["tech_stack"] = profile.get("tech_stack", [])
                context["last_hunted"] = profile.get("last_hunted")
                context["hunt_sessions"] = profile.get("hunt_sessions", 0)
            except (json.JSONDecodeError, OSError):
                pass

    # Load journal entries for this target to find tested CVEs
    journal_path = os.path.join(memory_dir, "journal.jsonl")
    if os.path.isfile(journal_path):
        try:
            with open(journal_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if entry.get("target") == target:
                            # Check if any tag looks like a CVE
                            for tag in entry.get("tags", []):
                                if tag.upper().startswith("CVE-"):
                                    context["tested_cves"].append(tag.upper())
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass

    # Load patterns
    patterns_path = os.path.join(memory_dir, "patterns.jsonl")
    if os.path.isfile(patterns_path):
        try:
            with open(patterns_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        pattern = json.loads(line)
                        context["patterns"].append(pattern)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass

    return context


def fetch_all_intel(techs: list[str], target: str, program: str = "") -> list[dict]:
    """Fetch intel from all sources."""
    all_results = []

    for tech in techs:
        print(f"  {CYAN}[{tech}]{RESET} GitHub Advisory DB...")
        all_results.extend(fetch_github_advisories(tech))

        print(f"  {CYAN}[{tech}]{RESET} NVD CVE API...")
        all_results.extend(fetch_nvd_cves(tech))

    # HackerOne via MCP server (preferred) or learn.py fallback
    if H1_MCP_AVAILABLE:
        print(f"  {CYAN}[H1 MCP]{RESET} Searching disclosed reports...")
        try:
            if program:
                reports = search_disclosed_reports(program=program, limit=15)
            else:
                for tech in techs[:3]:
                    reports = search_disclosed_reports(keyword=tech, limit=5)
                    for r in reports:
                        all_results.append({
                            "id": r.get("url", ""),
                            "source": "HackerOne",
                            "tech": tech,
                            "severity": r.get("severity", "UNKNOWN"),
                            "summary": r.get("title", ""),
                            "published": r.get("disclosed_at", ""),
                            "program": r.get("program", ""),
                        })
            if program:
                for r in reports:
                    all_results.append({
                        "id": r.get("url", ""),
                        "source": f"HackerOne/{program}",
                        "tech": "program",
                        "severity": r.get("severity", "UNKNOWN"),
                        "summary": r.get("title", ""),
                        "published": r.get("disclosed_at", ""),
                        "program": r.get("program", ""),
                    })
        except HackerOneAPIError as e:
            print(f"  {YELLOW}HackerOne MCP error: {e}{RESET}")
    else:
        print(f"  {DIM}[H1 MCP not available — using learn.py fallback]{RESET}")
        from learn import fetch_hackerone_hacktivity, TECH_H1_KEYWORDS
        for tech in techs:
            keywords = TECH_H1_KEYWORDS.get(tech.lower(), [tech])
            for kw in keywords[:2]:
                print(f"  {CYAN}[{tech}]{RESET} HackerOne Hacktivity '{kw}'...")
                h1_results = fetch_hackerone_hacktivity(kw, limit=5)
                all_results.extend(h1_results)

    # Program stats if available
    if program and H1_MCP_AVAILABLE:
        print(f"  {CYAN}[H1 MCP]{RESET} Program stats for {program}...")
        try:
            stats = get_program_stats(program)
            if "error" not in stats:
                all_results.append({
                    "id": f"program:{program}",
                    "source": "HackerOne/stats",
                    "tech": "program",
                    "severity": "INFO",
                    "summary": (
                        f"{stats.get('name', program)}: "
                        f"{'bounty' if stats.get('offers_bounties') else 'no bounty'}, "
                        f"{stats.get('resolved_reports', '?')} resolved, "
                        f"avg {stats.get('avg_days_to_first_response', '?')}d response"
                    ),
                    "published": stats.get("launched_at", ""),
                    "stats": stats,
                })
        except HackerOneAPIError as e:
            print(f"  {YELLOW}Stats error: {e}{RESET}")

    return all_results


def prioritize_intel(results: list[dict], memory: dict) -> dict:
    """Prioritize intel against memory context.

    Returns:
        Dict with categorized alerts: critical, high, info, memory_context.
    """
    tested_endpoints = set(memory.get("tested_endpoints", []))
    tested_cves = set(memory.get("tested_cves", []))

    critical = []
    high = []
    info = []

    for r in results:
        sev = r.get("severity", "UNKNOWN").upper()
        cve_id = r.get("id", "")

        # Check if this CVE was already tested
        already_tested = cve_id.upper() in tested_cves if cve_id.startswith("CVE") else False

        entry = {
            **r,
            "already_tested": already_tested,
        }

        if already_tested:
            entry["note"] = "Already tested in a previous hunt session."
            info.append(entry)
        elif sev in ("CRITICAL",):
            entry["note"] = "Untested critical vulnerability. Hunt candidate."
            critical.append(entry)
        elif sev in ("HIGH",):
            entry["note"] = "Untested high-severity finding. Priority target."
            high.append(entry)
        else:
            info.append(entry)

    # Sort each category by severity
    critical.sort(key=lambda x: severity_order(x.get("severity", "UNKNOWN")))
    high.sort(key=lambda x: severity_order(x.get("severity", "UNKNOWN")))

    memory_context = {}
    if memory.get("last_hunted"):
        memory_context["last_hunted"] = memory["last_hunted"]
    if memory.get("tech_stack"):
        memory_context["tech_stack"] = memory["tech_stack"]
    if memory.get("hunt_sessions"):
        memory_context["hunt_sessions"] = memory["hunt_sessions"]
    memory_context["tested_endpoints_count"] = len(tested_endpoints)
    memory_context["tested_cves_count"] = len(tested_cves)

    # Find matching patterns from other targets
    matching_patterns = []
    target_tech = set(t.lower() for t in memory.get("tech_stack", []))
    for pattern in memory.get("patterns", []):
        pattern_tech = set(t.lower() for t in pattern.get("tech_stack", []))
        if target_tech & pattern_tech:
            matching_patterns.append({
                "target": pattern.get("target", ""),
                "technique": pattern.get("technique", ""),
                "vuln_class": pattern.get("vuln_class", ""),
                "payout": pattern.get("payout", 0),
            })
    if matching_patterns:
        memory_context["matching_patterns"] = matching_patterns

    return {
        "critical": critical,
        "high": high,
        "info": info,
        "memory_context": memory_context,
        "total": len(results),
    }


def format_output(target: str, intel: dict) -> str:
    """Format intel output for terminal display."""
    lines = [
        f"",
        f"{BOLD}INTEL: {target}{RESET}",
        f"{'═' * 50}",
        f"",
    ]

    if intel["critical"]:
        lines.append(f"{BOLD}ALERTS:{RESET}")
        for item in intel["critical"]:
            lines.append(f"  {RED}[CRITICAL]{RESET} {item.get('id', '')} — {item.get('summary', '')}")
            if item.get("note"):
                lines.append(f"    → {item['note']}")
        lines.append("")

    if intel["high"]:
        if not intel["critical"]:
            lines.append(f"{BOLD}ALERTS:{RESET}")
        for item in intel["high"]:
            lines.append(f"  {YELLOW}[HIGH]{RESET} {item.get('id', '')} — {item.get('summary', '')}")
            if item.get("note"):
                lines.append(f"    → {item['note']}")
        lines.append("")

    if intel["info"]:
        info_count = len(intel["info"])
        tested = sum(1 for i in intel["info"] if i.get("already_tested"))
        lines.append(f"  {GREEN}[INFO]{RESET} {info_count} additional findings ({tested} already tested)")
        lines.append("")

    # Memory context
    mc = intel.get("memory_context", {})
    if mc:
        lines.append(f"{BOLD}MEMORY CONTEXT:{RESET}")
        if mc.get("last_hunted"):
            lines.append(f"  Last hunted: {mc['last_hunted']}")
        if mc.get("hunt_sessions"):
            lines.append(f"  Hunt sessions: {mc['hunt_sessions']}")
        if mc.get("tech_stack"):
            lines.append(f"  Tech stack: {', '.join(mc['tech_stack'])}")
        lines.append(f"  Tested endpoints: {mc.get('tested_endpoints_count', 0)}")
        lines.append(f"  Tested CVEs: {mc.get('tested_cves_count', 0)}")

        if mc.get("matching_patterns"):
            lines.append(f"  {CYAN}Cross-target patterns:{RESET}")
            for p in mc["matching_patterns"][:3]:
                payout = f" (${p['payout']})" if p.get("payout") else ""
                lines.append(f"    • {p['target']}: {p['technique']} [{p['vuln_class']}]{payout}")

    lines.append("")
    lines.append(f"{DIM}Total: {intel['total']} findings from GitHub Advisory, NVD, HackerOne{RESET}")
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="On-demand intel for a target")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--tech", default="", help="Comma-separated tech stack")
    parser.add_argument("--program", default="", help="HackerOne program handle")
    parser.add_argument("--memory-dir", default="", help="Path to hunt-memory directory")
    parser.add_argument("--json", action="store_true", help="Output as JSON instead of formatted text")
    args = parser.parse_args()

    techs = [t.strip() for t in args.tech.split(",") if t.strip()] if args.tech else []

    if not techs:
        print(f"{YELLOW}No tech stack specified. Use --tech to specify technologies.{RESET}")
        print(f"Example: python3 intel_engine.py --target {args.target} --tech nextjs,graphql")
        sys.exit(1)

    # Load memory context
    memory = load_memory_context(args.memory_dir, args.target)

    # If memory has tech stack, merge with CLI args
    if memory.get("tech_stack"):
        for t in memory["tech_stack"]:
            if t.lower() not in [x.lower() for x in techs]:
                techs.append(t)

    print(f"\n{BOLD}Intel Engine{RESET}")
    print(f"Target: {CYAN}{args.target}{RESET}")
    print(f"Tech: {CYAN}{', '.join(techs)}{RESET}")
    if args.program:
        print(f"Program: {CYAN}{args.program}{RESET}")
    print()

    # Fetch all intel
    results = fetch_all_intel(techs, args.target, args.program)

    # Prioritize against memory
    intel = prioritize_intel(results, memory)

    if args.json:
        print(json.dumps(intel, indent=2))
    else:
        print(format_output(args.target, intel))


if __name__ == "__main__":
    main()
