"""
Deterministic scope checker — code check, not LLM judgment.

Validates URLs against an allowlist of domain patterns before any outbound request.
Uses anchored suffix matching (not raw fnmatch) to prevent subdomain confusion:
  - "*.target.com" matches "sub.target.com" but NOT "evil-target.com"
  - "target.com" matches exactly "target.com"

Known limitation: IP addresses and CIDR ranges are NOT supported (returns False + warning).
"""
from __future__ import annotations  # PEP 604 union syntax on Python 3.9 (system /usr/bin/python3)

import sys
import argparse
import json
from urllib.parse import urlparse


class ScopeChecker:
    """Deterministic scope validator for bug bounty targets."""

    def __init__(
        self,
        domains: list[str],
        excluded_domains: list[str] | None = None,
        excluded_classes: list[str] | None = None,
    ):
        """
        Args:
            domains: Allowlist patterns like ["*.target.com", "api.target.com"]
            excluded_domains: Blocklist patterns like ["blog.target.com"]
            excluded_classes: Vuln classes excluded by program (e.g., ["dos"])
        """
        self.domains = [d.lower() for d in domains]
        self.excluded_domains = [d.lower() for d in (excluded_domains or [])]
        self.excluded_classes = [c.lower() for c in (excluded_classes or [])]

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL's hostname is in scope.

        Returns:
            True if the hostname matches an allowed pattern and is not excluded.
            False otherwise (including for malformed URLs, empty input, IP addresses).
        """
        if not url or not isinstance(url, str):
            return False

        # Ensure we have a scheme for urlparse
        normalized = url if "://" in url else f"https://{url}"

        try:
            parsed = urlparse(normalized)
        except ValueError as e:
            print(
                f"WARNING: scope checker could not parse URL {url!r}: {e}",
                file=sys.stderr,
            )
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        hostname = hostname.lower()

        # IP address check — not supported, return False with warning
        if _is_ip(hostname):
            print(
                f"WARNING: scope checker does not support IP addresses: {hostname}",
                file=sys.stderr,
            )
            return False

        # Strip port if present (urlparse handles this, but be safe)
        # hostname from urlparse should already exclude port

        # Check exclusion list first
        for excluded in self.excluded_domains:
            if _domain_matches(hostname, excluded):
                return False

        # Check allowlist
        for pattern in self.domains:
            if _domain_matches(hostname, pattern):
                return True

        return False

    def is_vuln_class_allowed(self, vuln_class: str) -> bool:
        """Check if a vulnerability class is allowed by the program."""
        return vuln_class.lower() not in self.excluded_classes

    def filter_urls(self, urls: list[str]) -> tuple[list[str], list[str]]:
        """Split a list of URLs into (in_scope, out_of_scope)."""
        in_scope = []
        out_of_scope = []
        for url in urls:
            if self.is_in_scope(url):
                in_scope.append(url)
            else:
                out_of_scope.append(url)
        return in_scope, out_of_scope

    def filter_file(self, input_path: str, output_path: str | None = None) -> tuple[int, int]:
        """Filter a file of URLs (one per line) through scope check.

        Args:
            input_path: Path to file with URLs, one per line.
            output_path: If provided, write in-scope URLs here. If None, filter in-place.

        Returns:
            (in_scope_count, out_of_scope_count)
        """
        with open(input_path, "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        in_scope, out_of_scope = self.filter_urls(lines)

        dest = output_path or input_path
        with open(dest, "w") as f:
            for url in in_scope:
                f.write(url + "\n")

        if out_of_scope:
            print(
                f"WARNING: filtered {len(out_of_scope)} out-of-scope URLs from {input_path}",
                file=sys.stderr,
            )

        return len(in_scope), len(out_of_scope)


def _domain_matches(hostname: str, pattern: str) -> bool:
    """Anchored domain matching — prevents subdomain confusion.

    *.target.com  → matches sub.target.com, a.b.target.com
                  → does NOT match target.com, evil-target.com
    target.com    → matches target.com exactly
    """
    if pattern.startswith("*."):
        # Wildcard: must be a proper subdomain
        suffix = pattern[1:]  # ".target.com"
        return hostname.endswith(suffix) and hostname != suffix[1:]
    else:
        # Exact match
        return hostname == pattern


def _is_ip(hostname: str) -> bool:
    """Check if hostname looks like an IP address (v4 or v6)."""
    # IPv6 in brackets
    if hostname.startswith("[") or ":" in hostname:
        return True
    # IPv4
    parts = hostname.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    return False


def _split_patterns(values: list[str]) -> list[str]:
    """Expand comma-separated CLI pattern args while preserving order."""
    patterns: list[str] = []
    for value in values:
        for part in value.split(","):
            part = part.strip()
            if part:
                patterns.append(part)
    return patterns


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Deterministically check assets against bug bounty scope."
    )
    parser.add_argument("asset", nargs="?", help="URL or hostname to check")
    parser.add_argument(
        "--domain",
        "-d",
        action="append",
        default=[],
        help="Allowed domain pattern. Repeat or comma-separate, e.g. target.com,*.target.com",
    )
    parser.add_argument(
        "--exclude-domain",
        "-x",
        action="append",
        default=[],
        help="Excluded domain pattern. Repeat or comma-separate.",
    )
    parser.add_argument(
        "--exclude-class",
        action="append",
        default=[],
        help="Excluded vulnerability class. Repeat or comma-separate.",
    )
    parser.add_argument("--vuln-class", help="Optional vulnerability class to check")
    parser.add_argument("--input-file", help="Filter URLs from a file, one per line")
    parser.add_argument("--output", help="Output path for filtered in-scope URLs")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = parser.parse_args(argv)

    domains = _split_patterns(args.domain)
    excluded_domains = _split_patterns(args.exclude_domain)
    excluded_classes = _split_patterns(args.exclude_class)

    if not domains:
        parser.error("at least one --domain pattern is required")
    if not args.asset and not args.input_file and not args.vuln_class:
        parser.error("provide an asset, --input-file, or --vuln-class")

    checker = ScopeChecker(domains, excluded_domains, excluded_classes)
    result: dict[str, object] = {
        "domains": domains,
        "excluded_domains": excluded_domains,
        "excluded_classes": excluded_classes,
    }
    exit_code = 0

    if args.asset:
        in_scope = checker.is_in_scope(args.asset)
        result["asset"] = args.asset
        result["in_scope"] = in_scope
        if not in_scope:
            exit_code = 2

    if args.vuln_class:
        allowed = checker.is_vuln_class_allowed(args.vuln_class)
        result["vuln_class"] = args.vuln_class
        result["vuln_class_allowed"] = allowed
        if not allowed:
            exit_code = 2

    if args.input_file:
        try:
            in_count, out_count = checker.filter_file(args.input_file, args.output)
        except OSError as exc:
            parser.error(str(exc))
        result["input_file"] = args.input_file
        result["output"] = args.output or args.input_file
        result["in_scope_count"] = in_count
        result["out_of_scope_count"] = out_count

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        if "asset" in result:
            verdict = "IN SCOPE" if result["in_scope"] else "OUT OF SCOPE"
            print(f"{verdict}: {result['asset']}")
        if "vuln_class" in result:
            verdict = "ALLOWED" if result["vuln_class_allowed"] else "EXCLUDED"
            print(f"{verdict}: vulnerability class {result['vuln_class']}")
        if "input_file" in result:
            print(
                "Filtered URLs: "
                f"{result['in_scope_count']} in scope, "
                f"{result['out_of_scope_count']} out of scope -> {result['output']}"
            )

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
