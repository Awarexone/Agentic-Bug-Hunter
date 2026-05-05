#!/usr/bin/env python3
"""
recon_to_json.py — Generate structured JSON inventory from recon_engine.sh output.

Reads the per-source .txt outputs in a recon directory and produces:
    <recon_dir>/inventory/subdomains.json

Output schema is defined in memory/schemas.py (RECON_INVENTORY_*).

Usage:
    python3 tools/recon_to_json.py recon/example.com
    python3 tools/recon_to_json.py recon/example.com --no-dns
    python3 tools/recon_to_json.py recon/example.com --strict
    python3 tools/recon_to_json.py recon/example.com --output /tmp/inv.json
"""

import argparse
import json
import os
import re
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

# Make `memory` package importable when this script is run directly.
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from memory.schemas import (
    CURRENT_SCHEMA_VERSION,
    SchemaError,
    validate_recon_inventory,
)


# ─── Source files (relative to recon dir) ─────────────────────────────────
# Each maps to a discovery_method label written into the JSON output.
SOURCE_FILES = {
    "subfinder": "subdomains/subfinder.txt",
    "amass":     "subdomains/amass.txt",
    "crtsh":     "subdomains/crtsh.txt",
    "wayback":   "subdomains/wayback_subs.txt",
}


# ─── Simple CDN heuristic by IP prefix (TODO: integrate cdncheck for accuracy) ──
# Not exhaustive — only flags the most common cases. Returns None for unknowns.
CDN_IP_PREFIXES: dict[str, list[str]] = {
    "CloudFront": [
        "13.32.", "13.33.", "13.224.", "13.225.", "13.226.", "13.227.", "13.249.",
        "52.84.", "52.85.", "54.182.", "54.192.", "54.230.", "54.239.",
        "99.86.", "204.246.",
    ],
    "Cloudflare": [
        "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
        "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
        "172.64.", "172.65.", "172.66.", "172.67.",
        "162.159.", "188.114.", "190.93.", "198.41.", "131.0.72.",
    ],
    "Fastly":    ["151.101.", "199.232.", "23.235."],
    "Akamai":    [
        "23.32.", "23.33.", "23.34.", "23.35.", "23.36.", "23.37.", "23.38.", "23.39.",
        "23.192.", "23.193.", "23.194.", "23.195.", "23.196.", "23.197.", "23.198.", "23.199.",
        "23.200.", "23.201.", "23.202.", "23.203.", "23.204.", "23.205.", "23.206.", "23.207.",
        "23.208.", "23.209.", "23.210.", "23.211.", "23.212.", "23.213.", "23.214.", "23.215.",
        "23.216.", "23.217.", "23.218.", "23.219.", "23.220.", "23.221.", "23.222.", "23.223.",
        "104.64.", "104.65.", "104.66.", "104.67.", "104.68.", "104.69.", "104.70.", "104.71.",
        "104.72.", "104.73.", "104.74.", "104.75.", "104.76.", "104.77.", "104.78.", "104.79.",
        "184.24.", "184.25.", "184.26.", "184.27.", "184.28.", "184.29.", "184.30.", "184.31.",
    ],
    "GoogleCloud": ["34.96.", "34.149.", "35.190.", "35.191.", "35.197.", "35.241."],
    "AzureCDN":    ["13.107.", "152.199."],
}


def detect_cdn(ip: str | None) -> str | None:
    """Heuristic CDN detection by IP prefix. Returns provider name or None."""
    if not ip:
        return None
    for provider, prefixes in CDN_IP_PREFIXES.items():
        for prefix in prefixes:
            if ip.startswith(prefix):
                return provider
    return None


# ─── httpx output parser ──────────────────────────────────────────────────
# Format produced by recon_engine.sh's httpx invocation:
#   URL [status] [title] [tech] [length]
# Brackets may be empty: https://x.example.com [403] [] [nginx] [180]
HTTPX_LINE_RE = re.compile(
    r"^(?P<url>\S+)"
    r"(?:\s+\[(?P<status>\d+)\])?"
    r"(?:\s+\[(?P<title>[^\]]*)\])?"
    r"(?:\s+\[(?P<tech>[^\]]*)\])?"
    r"(?:\s+\[(?P<length>\d+)\])?"
    r"\s*$"
)


def parse_httpx_line(line: str) -> dict | None:
    """Parse a single httpx output line. Returns dict or None on failure."""
    line = line.strip()
    if not line:
        return None
    m = HTTPX_LINE_RE.match(line)
    if not m:
        return None

    url = m.group("url")
    hostname = re.sub(r"^https?://", "", url).split("/", 1)[0].split(":", 1)[0]

    status = int(m.group("status")) if m.group("status") else 0
    title = (m.group("title") or "").strip()
    tech_str = (m.group("tech") or "").strip()
    tech = [t.strip() for t in tech_str.split(",") if t.strip()] if tech_str else []

    return {
        "hostname": hostname,
        "url": url,
        "status": status,
        "title": title,
        "tech": tech,
    }


# ─── Source attribution: which subdomain came from which tool ─────────────
def load_sources(recon_dir: Path) -> dict[str, set[str]]:
    """Load each source file as {source_name: set of lowercase hostnames}."""
    sources: dict[str, set[str]] = {}
    for source_name, rel_path in SOURCE_FILES.items():
        full_path = recon_dir / rel_path
        if not full_path.exists():
            sources[source_name] = set()
            continue
        try:
            with open(full_path) as f:
                sources[source_name] = {
                    line.strip().lower() for line in f
                    if line.strip() and not line.strip().startswith("#")
                }
        except OSError as e:
            print(f"WARN: failed to read {full_path}: {e}", file=sys.stderr)
            sources[source_name] = set()
    return sources


def discovery_methods_for(hostname: str, sources: dict[str, set[str]]) -> list[str]:
    """Return alphabetically sorted list of source names that contain this hostname."""
    h = hostname.lower()
    return sorted(name for name, hosts in sources.items() if h in hosts)


# ─── DNS lookup (best-effort, with timeout) ───────────────────────────────
def resolve_host(hostname: str, timeout: float = 2.0) -> tuple[str | None, str | None]:
    """Best-effort A + CNAME lookup via stdlib socket. Returns (ip, cname) or (None, None)."""
    socket.setdefaulttimeout(timeout)
    ip: str | None = None
    cname: str | None = None
    try:
        canonical, _aliases, ip_list = socket.gethostbyname_ex(hostname)
        if ip_list:
            ip = ip_list[0]
        if canonical and canonical.lower().rstrip(".") != hostname.lower().rstrip("."):
            cname = canonical.rstrip(".")
    except (socket.gaierror, socket.herror, socket.timeout, OSError):
        pass
    finally:
        socket.setdefaulttimeout(None)
    return ip, cname


# ─── Main builder ─────────────────────────────────────────────────────────
def build_inventory(
    recon_dir: Path,
    target: str,
    *,
    do_dns: bool = True,
) -> dict:
    """Build the recon inventory dict by parsing files in recon_dir."""
    start = datetime.now(timezone.utc)

    sources = load_sources(recon_dir)

    # all_discovered = subdomains/all.txt ∪ each source file (defensive in case
    # all.txt was generated with different filter rules)
    all_discovered: set[str] = set()
    all_path = recon_dir / "subdomains" / "all.txt"
    if all_path.exists():
        try:
            with open(all_path) as f:
                for line in f:
                    h = line.strip().lower()
                    if h:
                        all_discovered.add(h)
        except OSError as e:
            print(f"WARN: failed to read {all_path}: {e}", file=sys.stderr)
    for hosts in sources.values():
        all_discovered |= hosts

    # Live subdomains from live/httpx_full.txt
    live_subdomains: list[dict] = []
    seen: set[str] = set()
    httpx_path = recon_dir / "live" / "httpx_full.txt"
    if httpx_path.exists():
        try:
            with open(httpx_path) as f:
                for line in f:
                    parsed = parse_httpx_line(line)
                    if not parsed:
                        continue
                    hostname = parsed["hostname"].lower()
                    if hostname in seen:
                        continue
                    seen.add(hostname)

                    ip, cname = (None, None)
                    if do_dns:
                        ip, cname = resolve_host(hostname)

                    cdn = detect_cdn(ip)

                    asset: dict = {
                        "hostname": hostname,
                        "status": parsed["status"],
                    }
                    if ip:
                        asset["ip"] = ip
                    if cname:
                        asset["cname"] = cname
                    if cdn:
                        asset["cdn"] = cdn
                    if parsed["title"]:
                        asset["title"] = parsed["title"]
                    if parsed["tech"]:
                        asset["tech"] = parsed["tech"]
                    methods = discovery_methods_for(hostname, sources)
                    if methods:
                        asset["discovery_method"] = methods

                    live_subdomains.append(asset)
        except OSError as e:
            print(f"WARN: failed to read {httpx_path}: {e}", file=sys.stderr)

    end = datetime.now(timezone.utc)
    duration = max(0, int((end - start).total_seconds()))

    inv: dict = {
        "target": target,
        "scan_date": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scan_duration_seconds": duration,
        "summary": {
            "total_discovered": len(all_discovered),
            "live_resolved": len(live_subdomains),
            "sources": [name for name, hosts in sources.items() if hosts],
        },
        "live_subdomains": live_subdomains,
        "all_discovered": sorted(all_discovered),
        "schema_version": CURRENT_SCHEMA_VERSION,
    }
    return inv


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate JSON inventory from recon_engine.sh output."
    )
    parser.add_argument("recon_dir", help="Path to recon dir (e.g., recon/example.com)")
    parser.add_argument("--target", help="Target name (default: basename of recon_dir)")
    parser.add_argument("--no-dns", action="store_true",
                        help="Skip DNS lookup (faster but no IP/CNAME/CDN)")
    parser.add_argument("--strict", action="store_true",
                        help="Abort on schema validation failure")
    parser.add_argument("--output",
                        help="Output path (default: <recon_dir>/inventory/subdomains.json)")
    args = parser.parse_args()

    recon_dir = Path(args.recon_dir).resolve()
    if not recon_dir.is_dir():
        print(f"ERROR: not a directory: {recon_dir}", file=sys.stderr)
        return 1

    target = args.target or recon_dir.name

    inv = build_inventory(recon_dir, target, do_dns=not args.no_dns)

    try:
        validate_recon_inventory(inv)
    except SchemaError as e:
        if args.strict:
            print(f"ERROR: schema validation failed: {e}", file=sys.stderr)
            return 2
        print(f"WARN: schema validation failed (writing anyway): {e}", file=sys.stderr)

    output_path = Path(args.output) if args.output else (recon_dir / "inventory" / "subdomains.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(inv, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"[+] Inventory: {output_path}")
    print(f"    Total discovered: {inv['summary']['total_discovered']}")
    print(f"    Live resolved:    {inv['summary']['live_resolved']}")
    sources_used = inv['summary']['sources']
    print(f"    Sources used:     {', '.join(sources_used) if sources_used else '(none)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
