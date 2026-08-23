#!/usr/bin/env python3
"""eol_check.py — End-of-Life / lifecycle intel tool for detected tech stacks.

Maps technology fingerprints (product=version pairs) to endoflife.date product
slugs, fetches lifecycle data, and reports EOL status. Pure stdlib — no
external dependencies beyond Python 3.10+.

Usage:
    python3 tools/eol_check.py --tech "php=7.4,ubuntu=20.04,nginx=1.18"
    python3 tools/eol_check.py --tech "python=3.8,node=16" --json
    python3 tools/eol_check.py --list-products  # show known product slugs
    python3 tools/eol_check.py --product python  # show all Python releases

API: endoflife.date (https://endoflife.date/api)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from datetime import date, datetime
from typing import Any

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
from tools.safe_http import safe_urlopen  # noqa: E402


ENDOFLIFE_API = "https://endoflife.date/api"

# Product name → endoflife.date slug mapping for common tech stacks
PRODUCT_SLUGS: dict[str, str] = {
    "alpine": "alpine",
    "amazon-linux": "amazon-linux",
    "android": "android",
    "angular": "angular",
    "ansible": "ansible",
    "apache": "apache",
    "aws-lambda": "aws-lambda",
    "centos": "centos",
    "debian": "debian",
    "django": "django",
    "dotnet": "dotnet",
    "fedora": "fedora",
    "go": "go",
    "java": "java",
    "jenkins": "jenkins",
    "jquery": "jquery",
    "kubernetes": "kubernetes",
    "laravel": "laravel",
    "mariadb": "mariadb",
    "mongodb": "mongodb",
    "mysql": "mysql",
    "nginx": "nginx",
    "node": "nodejs",
    "nodejs": "nodejs",
    "npm": "npm",
    "nvidia": "nvidia",
    "oracle-linux": "oracle-linux",
    "php": "php",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "python": "python",
    "rhel": "rhel",
    "rocky-linux": "rocky-linux",
    "ruby": "ruby",
    "rust": "rust",
    "sqlite": "sqlite",
    "suse": "suse",
    "tomcat": "tomcat",
    "ubuntu": "ubuntu",
    "vue": "vue",
    "wordpress": "wordpress",
}


def fetch_product(product: str) -> list[dict[str, Any]]:
    """Fetch lifecycle data for a product from endoflife.date."""
    url = f"{ENDOFLIFE_API}/{product}.json"
    try:
        req = urllib.request.Request(url)
        with safe_urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"  [!] Unknown product: {product}", file=sys.stderr)
            return []
        raise
    except Exception as e:
        print(f"  [!] Failed to fetch {product}: {e}", file=sys.stderr)
        return []


def find_release(cycles: list[dict[str, Any]], version: str) -> dict[str, Any] | None:
    """Find the best matching release cycle for a version string."""
    if not cycles:
        return None

    # Try exact match on cycle name
    for cycle in cycles:
        if str(cycle.get("cycle", "")) == version:
            return cycle

    # Try prefix match (e.g. "7.4" matches cycle "7")
    for cycle in cycles:
        cycle_name = str(cycle.get("cycle", ""))
        if version.startswith(cycle_name) and cycle_name:
            return cycle

    # Fallback: return latest release for the major version
    major = version.split(".")[0]
    for cycle in cycles:
        cycle_name = str(cycle.get("cycle", ""))
        if cycle_name.startswith(major):
            return cycle

    return None


def check_eol(product: str, version: str) -> dict[str, Any]:
    """Check EOL status for a product=version pair."""
    slug = PRODUCT_SLUGS.get(product.lower(), product.lower())
    cycles = fetch_product(slug)

    result: dict[str, Any] = {
        "product": product,
        "version": version,
        "slug": slug,
        "eol_status": "unknown",
        "latest": None,
        "latest_version": None,
    }

    if not cycles:
        return result

    release = find_release(cycles, version)
    if not release:
        result["eol_status"] = "not_found"
        return result

    today = date.today()
    eol_date = _parse_date(release.get("eol"))
    support_date = _parse_date(release.get("support"))
    extended_date = _parse_date(release.get("extendedSupport"))
    latest_cycle = cycles[0] if cycles else {}
    latest_version = latest_cycle.get("latest", str(latest_cycle.get("cycle", "?")))

    result["cycle"] = release.get("cycle")
    result["release_date"] = release.get("releaseDate")
    result["latest_version"] = latest_version
    result["eol_date"] = str(eol_date) if eol_date else None
    result["support_date"] = str(support_date) if support_date else None

    if eol_date and today > eol_date:
        result["eol_status"] = "eol"
    elif support_date and today > support_date:
        result["eol_status"] = "security_only"
    elif extended_date and today > extended_date:
        result["eol_status"] = "extended_support"
    else:
        result["eol_status"] = "supported"

    return result


def _parse_date(raw: Any) -> date | None:
    """Parse a date string from the API. Handles booleans (True = still supported)."""
    if raw is None or raw is True or raw is False:
        return None
    if isinstance(raw, str):
        for fmt in ("%Y-%m-%d", "%Y-%m"):
            try:
                return datetime.strptime(raw, fmt).date()
            except ValueError:
                continue
    return None


def format_result(result: dict[str, Any], color: bool = True) -> str:
    """Format a single EOL result as a human-readable line."""
    status = result["eol_status"]
    icons: dict[str, str] = {
        "eol": "🔴" if color else "EOL",
        "security_only": "🟡" if color else "SEC",
        "extended_support": "🟠" if color else "EXT",
        "supported": "🟢" if color else "OK",
        "not_found": "⚪" if color else "?",
        "unknown": "⚫" if color else "?",
    }
    icon = icons.get(status, "?")

    line = f"  {icon} {result['product']} {result['version']} → {status}"
    if result.get("latest_version"):
        line += f"  (latest: {result['latest_version']})"
    if result.get("eol_date"):
        line += f"  [EOL: {result['eol_date']}]"
    return line


def main() -> int:
    parser = argparse.ArgumentParser(
        description="eol_check.py — End-of-Life lifecycle intel from endoflife.date"
    )
    parser.add_argument(
        "--tech",
        help="Comma-separated product=version pairs (e.g. php=7.4,ubuntu=20.04)",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output as JSON"
    )
    parser.add_argument(
        "--list-products", action="store_true", help="Show known product slugs"
    )
    parser.add_argument(
        "--product", help="Show all releases for a single product"
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable emoji/color in output"
    )
    args = parser.parse_args()

    if args.list_products:
        print("Known product slugs (endoflife.date):")
        for name, slug in sorted(PRODUCT_SLUGS.items()):
            print(f"  {name:<20} → {slug}")
        return 0

    if args.product:
        cycles = fetch_product(args.product)
        if not cycles:
            print(f"No data for '{args.product}'")
            return 1
        print(f"\n{args.product} releases ({ENDOFLIFE_API}/{args.product}):")
        for c in cycles[:20]:
            eol = c.get("eol", "?")
            latest = c.get("latest", "?")
            print(f"  {str(c.get('cycle', '?')):<12} latest: {str(latest):<12} eol: {eol}")
        return 0

    if not args.tech:
        parser.print_help()
        return 1

    pairs = [p.strip().split("=", 1) for p in args.tech.split(",")]
    results = []
    for product, version in pairs:
        result = check_eol(product.strip(), version.strip())
        results.append(result)

    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        print()
        for r in results:
            print(format_result(r, color=not args.no_color))
        print()

        # Summary
        eol_count = sum(1 for r in results if r["eol_status"] == "eol")
        sec_count = sum(1 for r in results if r["eol_status"] == "security_only")
        supported = sum(1 for r in results if r["eol_status"] == "supported")
        print(
            f"Summary: {supported} supported, {sec_count} security-only, "
            f"{eol_count} end-of-life"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
