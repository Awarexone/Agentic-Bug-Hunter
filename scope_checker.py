"""
Deterministic scope checker — code check, not LLM judgment.

Validates URLs against an allowlist of domain patterns before any outbound request.
Uses anchored suffix matching (not raw fnmatch) to prevent subdomain confusion:
  - "*.target.com" matches "sub.target.com" but NOT "evil-target.com"
  - "target.com" matches exactly "target.com"

Known limitation: IP addresses and CIDR ranges are NOT supported (returns False + warning).
"""

import sys
from fnmatch import fnmatch
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
        except Exception:
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
