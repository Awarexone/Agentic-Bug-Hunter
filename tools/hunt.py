#!/usr/bin/env python3
"""
Bug Bounty Hunt Orchestrator
Main script that chains target selection, recon, scanning, and reporting.

Usage:
    python3 hunt.py                         # Full pipeline: select targets + hunt
    python3 hunt.py --target <domain>       # Hunt a specific target
    python3 hunt.py --quick --target <domain>  # Quick scan mode
    python3 hunt.py --recon-only --target <domain>  # Only run recon
    python3 hunt.py --scan-only --target <domain>   # Only run vuln scanner (requires prior recon)
    python3 hunt.py --status                # Show current progress
    python3 hunt.py --setup-wordlists       # Download common wordlists
    python3 hunt.py --cve-hunt --target <domain>   # Run CVE hunter
    python3 hunt.py --zero-day --target <domain>   # Run zero-day fuzzer
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(TOOLS_DIR)
TARGETS_DIR = os.path.join(BASE_DIR, "targets")
RECON_DIR = os.path.join(BASE_DIR, "recon")
FINDINGS_DIR = os.path.join(BASE_DIR, "findings")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
WORDLIST_DIR = os.path.join(BASE_DIR, "wordlists")

# Colors
GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"


def log(level, msg):
    colors = {"ok": GREEN, "err": RED, "warn": YELLOW, "info": CYAN}
    symbols = {"ok": "+", "err": "-", "warn": "!", "info": "*"}
    print(f"{colors.get(level, '')}{BOLD}[{symbols.get(level, '*')}]{NC} {msg}")


def run_cmd(cmd, cwd=None, timeout=600):
    """Run a shell command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            cwd=cwd, timeout=timeout
        )
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def check_tools():
    """Check which tools are installed."""
    tools = ["subfinder", "httpx", "nuclei", "ffuf", "nmap", "amass", "gau", "dalfox", "subjack"]
    installed = []
    missing = []

    for tool in tools:
        success, _ = run_cmd(f"command -v {tool}")
        if success:
            installed.append(tool)
        else:
            missing.append(tool)

    return installed, missing


def setup_wordlists():
    """Download common wordlists for fuzzing."""
    os.makedirs(WORDLIST_DIR, exist_ok=True)

    wordlists = {
        "common.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "raft-medium-dirs.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt",
        "api-endpoints.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
        "params.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
    }

    for name, url in wordlists.items():
        filepath = os.path.join(WORDLIST_DIR, name)
        if os.path.exists(filepath):
            log("ok", f"Wordlist exists: {name}")
            continue

        log("info", f"Downloading {name}...")
        success, output = run_cmd(f'curl -sL "{url}" -o "{filepath}"')
        if success and os.path.getsize(filepath) > 100:
            lines = sum(1 for _ in open(filepath))
            log("ok", f"Downloaded {name} ({lines} entries)")
        else:
            log("err", f"Failed to download {name}")

    log("ok", f"Wordlists ready in {WORDLIST_DIR}")


def select_targets(top_n=10):
    """Run target selector."""
    log("info", "Running target selector...")
    script = os.path.join(TOOLS_DIR, "target_selector.py")
    success, output = run_cmd(
        f'python3 "{script}" --top {top_n}',
        timeout=60
    )
    print(output)

    if not success:
        log("err", "Target selection failed")
        return []

    # Load selected targets
    targets_file = os.path.join(TARGETS_DIR, "selected_targets.json")
    if os.path.exists(targets_file):
        with open(targets_file) as f:
            data = json.load(f)
        return data.get("targets", [])

    return []


def run_recon(domain, quick=False):
    """Run recon engine on a domain."""
    log("info", f"Running recon on {domain}...")
    script = os.path.join(TOOLS_DIR, "recon_engine.sh")
    quick_flag = "--quick" if quick else ""

    # Run with live output
    try:
        proc = subprocess.Popen(
            f'bash "{script}" "{domain}" {quick_flag}',
            shell=True, cwd=BASE_DIR
        )
        proc.wait(timeout=1800)  # 30 min timeout
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc.kill()
        log("err", f"Recon timed out for {domain}")
        return False


def run_vuln_scan(domain, quick=False):
    """Run vulnerability scanner on recon results."""
    recon_dir = os.path.join(RECON_DIR, domain)
    if not os.path.isdir(recon_dir):
        log("err", f"No recon data found for {domain}. Run recon first.")
        return False

    log("info", f"Running vulnerability scanner on {domain}...")
    script = os.path.join(TOOLS_DIR, "vuln_scanner.sh")
    quick_flag = "--quick" if quick else ""

    try:
        proc = subprocess.Popen(
            f'bash "{script}" "{recon_dir}" {quick_flag}',
            shell=True, cwd=BASE_DIR
        )
        proc.wait(timeout=1800)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc.kill()
        log("err", f"Vulnerability scan timed out for {domain}")
        return False


def generate_reports(domain):
    """Generate reports for findings."""
    findings_dir = os.path.join(FINDINGS_DIR, domain)
    if not os.path.isdir(findings_dir):
        log("warn", f"No findings for {domain}")
        return 0

    log("info", f"Generating reports for {domain}...")
    script = os.path.join(TOOLS_DIR, "report_generator.py")
    success, output = run_cmd(f'python3 "{script}" "{findings_dir}"')
    print(output)

    # Count generated reports
    report_dir = os.path.join(REPORTS_DIR, domain)
    if os.path.isdir(report_dir):
        return len([f for f in os.listdir(report_dir) if f.endswith(".md") and f != "SUMMARY.md"])
    return 0


def show_status():
    """Show current pipeline status."""
    print(f"\n{BOLD}{'='*50}{NC}")
    print(f"{BOLD}  Bug Bounty Pipeline Status{NC}")
    print(f"{BOLD}{'='*50}{NC}\n")

    # Check tools
    installed, missing = check_tools()
    print(f"  Tools: {len(installed)}/{len(installed)+len(missing)} installed")
    if missing:
        print(f"  Missing: {', '.join(missing)}")

    # Check targets
    targets_file = os.path.join(TARGETS_DIR, "selected_targets.json")
    if os.path.exists(targets_file):
        with open(targets_file) as f:
            data = json.load(f)
        print(f"  Selected targets: {data.get('total_targets', 0)}")
    else:
        print("  Selected targets: None (run target selector first)")

    # Check recon results
    if os.path.isdir(RECON_DIR):
        recon_targets = [d for d in os.listdir(RECON_DIR) if os.path.isdir(os.path.join(RECON_DIR, d))]
        print(f"  Recon completed: {len(recon_targets)} targets")
        for t in recon_targets:
            subs_file = os.path.join(RECON_DIR, t, "subdomains", "all.txt")
            live_file = os.path.join(RECON_DIR, t, "live", "urls.txt")
            subs = sum(1 for _ in open(subs_file)) if os.path.exists(subs_file) else 0
            live = sum(1 for _ in open(live_file)) if os.path.exists(live_file) else 0
            print(f"    - {t}: {subs} subdomains, {live} live hosts")

    # Check findings
    if os.path.isdir(FINDINGS_DIR):
        finding_targets = [d for d in os.listdir(FINDINGS_DIR) if os.path.isdir(os.path.join(FINDINGS_DIR, d))]
        print(f"  Scanned targets: {len(finding_targets)}")
        for t in finding_targets:
            summary = os.path.join(FINDINGS_DIR, t, "summary.txt")
            if os.path.exists(summary):
                with open(summary) as f:
                    content = f.read()
                total_match = content.split("TOTAL FINDINGS:")
                if len(total_match) > 1:
                    total = total_match[1].strip().split("\n")[0].strip()
                    print(f"    - {t}: {total} findings")

    # Check reports
    if os.path.isdir(REPORTS_DIR):
        report_targets = [d for d in os.listdir(REPORTS_DIR) if os.path.isdir(os.path.join(REPORTS_DIR, d))]
        print(f"  Reports generated: {len(report_targets)} targets")
        for t in report_targets:
            reports = [f for f in os.listdir(os.path.join(REPORTS_DIR, t)) if f.endswith(".md") and f != "SUMMARY.md"]
            print(f"    - {t}: {len(reports)} reports")

    print(f"\n{'='*50}\n")


def print_dashboard(results):
    """Print final summary dashboard."""
    print(f"\n{BOLD}{'='*60}{NC}")
    print(f"{BOLD}  HUNT COMPLETE — Summary Dashboard{NC}")
    print(f"{BOLD}{'='*60}{NC}\n")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    total_findings = 0
    total_reports = 0

    for r in results:
        status_icon = f"{GREEN}OK{NC}" if r["success"] else f"{RED}FAIL{NC}"
        print(f"  [{status_icon}] {r['domain']}")
        print(f"       Recon: {'Done' if r.get('recon') else 'Skipped'} | "
              f"Scan: {'Done' if r.get('scan') else 'Skipped'} | "
              f"Reports: {r.get('reports', 0)}")
        total_findings += r.get("findings", 0)
        total_reports += r.get("reports", 0)

    print(f"\n  Total reports generated: {total_reports}")
    print(f"\n  Reports directory: {REPORTS_DIR}/")
    print(f"\n{'='*60}")

    if total_reports > 0:
        print(f"\n  {YELLOW}Next steps:{NC}")
        print("  1. Review each report in the reports/ directory")
        print("  2. Manually verify findings before submitting")
        print("  3. Add PoC screenshots where applicable")
        print("  4. Submit via HackerOne program pages")
        print(f"\n{'='*60}\n")


def run_cve_hunt(domain):
    """Run CVE hunter on a target."""
    log("info", f"Running CVE hunter on {domain}...")
    script = os.path.join(TOOLS_DIR, "cve_hunter.py")
    recon_dir = os.path.join(RECON_DIR, domain)
    recon_flag = f'--recon-dir "{recon_dir}"' if os.path.isdir(recon_dir) else ""

    try:
        proc = subprocess.Popen(
            f'python3 "{script}" "{domain}" {recon_flag}',
            shell=True, cwd=BASE_DIR
        )
        proc.wait(timeout=600)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc.kill()
        log("err", f"CVE hunt timed out for {domain}")
        return False


def run_zero_day_fuzzer(domain, deep=False):
    """Run zero-day fuzzer on a target."""
    log("info", f"Running zero-day fuzzer on {domain}...")
    script = os.path.join(TOOLS_DIR, "zero_day_fuzzer.py")
    deep_flag = "--deep" if deep else ""

    # Check if we have recon data with live URLs
    recon_dir = os.path.join(RECON_DIR, domain)
    if os.path.isdir(recon_dir):
        cmd = f'python3 "{script}" "https://{domain}" --recon-dir "{recon_dir}" {deep_flag}'
    else:
        cmd = f'python3 "{script}" "https://{domain}" {deep_flag}'

    try:
        proc = subprocess.Popen(cmd, shell=True, cwd=BASE_DIR)
        proc.wait(timeout=900)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc.kill()
        log("err", f"Zero-day fuzzer timed out for {domain}")
        return False


def hunt_target(domain, quick=False, recon_only=False, scan_only=False, cve_hunt=False, zero_day=False):
    """Run the full hunt pipeline on a single target."""
    result = {"domain": domain, "success": True, "recon": False, "scan": False, "reports": 0}

    if not scan_only:
        result["recon"] = run_recon(domain, quick=quick)
        if not result["recon"]:
            log("warn", f"Recon had issues for {domain}, continuing anyway...")

    if recon_only:
        return result

    result["scan"] = run_vuln_scan(domain, quick=quick)

    # CVE hunting (only when explicitly requested)
    if cve_hunt:
        run_cve_hunt(domain)

    # Zero-day fuzzing (disabled by default — high false positive rate)
    if zero_day:
        log("warn", "Zero-day fuzzer enabled — results require manual verification")
        run_zero_day_fuzzer(domain, deep=not quick)

    result["reports"] = generate_reports(domain)

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Bug Bounty Hunt Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 hunt.py                            Full pipeline (select + hunt)
  python3 hunt.py --target example.com       Hunt specific target
  python3 hunt.py --quick --target example.com  Quick scan
  python3 hunt.py --status                   Show progress
  python3 hunt.py --setup-wordlists          Download wordlists
        """
    )
    parser.add_argument("--target", type=str, help="Specific target domain to hunt")
    parser.add_argument("--quick", action="store_true", help="Quick scan mode (fewer checks)")
    parser.add_argument("--recon-only", action="store_true", help="Only run reconnaissance")
    parser.add_argument("--scan-only", action="store_true", help="Only run vulnerability scanner")
    parser.add_argument("--report-only", action="store_true", help="Only generate reports")
    parser.add_argument("--status", action="store_true", help="Show pipeline status")
    parser.add_argument("--setup-wordlists", action="store_true", help="Download wordlists")
    parser.add_argument("--cve-hunt", action="store_true", help="Run CVE hunter")
    parser.add_argument("--zero-day", action="store_true", help="Run zero-day fuzzer")
    parser.add_argument("--select-targets", action="store_true", help="Only run target selection")
    parser.add_argument("--top", type=int, default=10, help="Number of targets to select")
    args = parser.parse_args()

    print(f"""
{BOLD}╔══════════════════════════════════════════╗
║     Bug Bounty Automation Pipeline       ║
╚══════════════════════════════════════════╝{NC}
    """)

    # Status check
    if args.status:
        show_status()
        return

    # Setup wordlists
    if args.setup_wordlists:
        setup_wordlists()
        return

    # Check tools
    installed, missing = check_tools()
    log("info", f"Tools: {len(installed)}/{len(installed)+len(missing)} installed")
    if missing:
        log("warn", f"Missing tools: {', '.join(missing)}")
        log("warn", "Run: bash tools/install_tools.sh")

    # Target selection only
    if args.select_targets:
        select_targets(top_n=args.top)
        return

    # Report only
    if args.report_only:
        if args.target:
            generate_reports(args.target)
        else:
            if os.path.isdir(FINDINGS_DIR):
                for d in os.listdir(FINDINGS_DIR):
                    if os.path.isdir(os.path.join(FINDINGS_DIR, d)):
                        generate_reports(d)
        return

    # Hunt specific target
    if args.target:
        log("info", f"Hunting target: {args.target}")

        # Setup wordlists if missing
        if not os.path.exists(os.path.join(WORDLIST_DIR, "common.txt")):
            setup_wordlists()

        result = hunt_target(
            args.target,
            quick=args.quick,
            recon_only=args.recon_only,
            scan_only=args.scan_only,
            cve_hunt=args.cve_hunt,
            zero_day=args.zero_day
        )
        print_dashboard([result])
        return

    # Full pipeline: select targets then hunt each
    log("info", "Starting full pipeline...")

    # Setup wordlists
    if not os.path.exists(os.path.join(WORDLIST_DIR, "common.txt")):
        setup_wordlists()

    # Select targets
    targets = select_targets(top_n=args.top)
    if not targets:
        log("err", "No targets selected. Exiting.")
        sys.exit(1)

    # Hunt each target
    results = []
    for i, target in enumerate(targets):
        domains = target.get("scope_domains", [])
        if not domains:
            log("warn", f"No domains for {target.get('name', 'unknown')} — skipping")
            continue

        # Hunt the primary domain
        primary_domain = domains[0]
        log("info", f"[{i+1}/{len(targets)}] Hunting: {target.get('name', primary_domain)}")
        log("info", f"  Domain: {primary_domain}")
        log("info", f"  Program: {target.get('url', 'N/A')}")

        result = hunt_target(primary_domain, quick=args.quick)
        results.append(result)

    print_dashboard(results)


if __name__ == "__main__":
    main()
