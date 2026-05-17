"""Deterministic scope checking for bug bounty targets.

The legacy ScopeChecker class remains for existing callers. ScopeManifest adds
target-level policy from targets/<slug>/scope.yaml: hosts, path exclusions,
CIDRs, third-party exclusions, method policy, and rate limits.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import socket
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


ACTIVE_METHODS = {"POST", "PUT", "DELETE", "PATCH"}
DEFAULT_SAFE_METHODS = ["GET", "HEAD", "OPTIONS"]


class ScopeChecker:
    """Deterministic hostname validator for bug bounty targets."""

    def __init__(
        self,
        domains: list[str],
        excluded_domains: list[str] | None = None,
        excluded_classes: list[str] | None = None,
    ):
        self.domains = [d.lower() for d in domains]
        self.excluded_domains = [d.lower() for d in (excluded_domains or [])]
        self.excluded_classes = [c.lower() for c in (excluded_classes or [])]

    def is_in_scope(self, url: str) -> bool:
        parsed = _parse_url(url)
        if parsed is None:
            return False

        hostname = (parsed.hostname or "").lower()
        if _is_ip(hostname):
            print(
                f"WARNING: scope checker does not support IP addresses: {hostname}",
                file=sys.stderr,
            )
            return False

        for excluded in self.excluded_domains:
            if _domain_matches(hostname, excluded):
                return False

        return any(_domain_matches(hostname, pattern) for pattern in self.domains)

    def is_vuln_class_allowed(self, vuln_class: str) -> bool:
        return vuln_class.lower() not in self.excluded_classes

    def filter_urls(self, urls: list[str]) -> tuple[list[str], list[str]]:
        in_scope = []
        out_of_scope = []
        for url in urls:
            if self.is_in_scope(url):
                in_scope.append(url)
            else:
                out_of_scope.append(url)
        return in_scope, out_of_scope

    def filter_file(self, input_path: str, output_path: str | None = None) -> tuple[int, int]:
        with open(input_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        in_scope, out_of_scope = self.filter_urls(lines)

        dest = output_path or input_path
        with open(dest, "w", encoding="utf-8") as f:
            for url in in_scope:
                f.write(url + "\n")

        if out_of_scope:
            print(
                f"WARNING: filtered {len(out_of_scope)} out-of-scope URLs from {input_path}",
                file=sys.stderr,
            )

        return len(in_scope), len(out_of_scope)


@dataclass
class ThirdPartyExclusion:
    name: str
    cidr: list[str] = field(default_factory=list)

    def networks(self) -> list[ipaddress._BaseNetwork]:
        return [ipaddress.ip_network(c, strict=False) for c in self.cidr]


@dataclass
class ScopeManifest:
    program_name: str = ""
    platform_url: str = ""
    safe_harbor_notes: str = ""
    asset_types: list[str] = field(default_factory=list)
    hosts_allow: list[str] = field(default_factory=list)
    hosts_deny: list[str] = field(default_factory=list)
    paths_deny: list[str] = field(default_factory=list)
    ip_cidr_allow: list[str] = field(default_factory=list)
    ip_cidr_deny: list[str] = field(default_factory=list)
    third_party_exclusions: list[ThirdPartyExclusion] = field(default_factory=list)
    methods_allow: list[str] = field(default_factory=lambda: list(DEFAULT_SAFE_METHODS))
    max_rate_per_sec: float = 1.0

    @classmethod
    def from_file(cls, path: str | Path) -> "ScopeManifest":
        if yaml is None:
            raise RuntimeError("PyYAML is required to load scope.yaml")
        p = Path(path)
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        exclusions = [
            ThirdPartyExclusion(
                name=str(item.get("name", "")),
                cidr=[str(c) for c in (item.get("cidr") or [])],
            )
            for item in data.get("third_party_exclusions", []) or []
        ]
        return cls(
            program_name=str(data.get("program_name", "")),
            platform_url=str(data.get("platform_url", "")),
            safe_harbor_notes=str(data.get("safe_harbor_notes", "")),
            asset_types=[str(x) for x in data.get("asset_types", []) or []],
            hosts_allow=[str(x).lower() for x in data.get("hosts_allow", []) or []],
            hosts_deny=[str(x).lower() for x in data.get("hosts_deny", []) or []],
            paths_deny=[str(x) for x in data.get("paths_deny", []) or []],
            ip_cidr_allow=[str(x) for x in data.get("ip_cidr_allow", []) or []],
            ip_cidr_deny=[str(x) for x in data.get("ip_cidr_deny", []) or []],
            third_party_exclusions=exclusions,
            methods_allow=[str(x).upper() for x in data.get("methods_allow", DEFAULT_SAFE_METHODS) or []],
            max_rate_per_sec=float(data.get("max_rate_per_sec", 1) or 1),
        )

    def checker(self, resolver=None) -> "ManifestScopeChecker":
        return ManifestScopeChecker(self, resolver=resolver)


class ManifestScopeChecker:
    def __init__(self, manifest: ScopeManifest, resolver=None):
        self.manifest = manifest
        self.resolver = resolver or resolve_ips
        self.host_checker = ScopeChecker(
            manifest.hosts_allow,
            excluded_domains=manifest.hosts_deny,
        )

    def check(
        self,
        url: str,
        method: str = "GET",
        approve_active: bool = False,
        rate_limit: float | None = None,
        resolve: bool = True,
    ) -> tuple[bool, str]:
        parsed = _parse_url(url)
        if parsed is None:
            return False, "malformed-url"

        hostname = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        method = method.upper()

        if method not in self.manifest.methods_allow:
            return False, f"method-not-allowed:{method}"
        if method in ACTIVE_METHODS and not approve_active:
            return False, f"active-method-requires-approval:{method}"

        if _is_ip(hostname):
            if not self._ip_allowed(hostname):
                return False, f"ip-out-of-scope:{hostname}"
        elif not self.host_checker.is_in_scope(url):
            return False, f"host-out-of-scope:{hostname}"

        for pattern in self.manifest.paths_deny:
            if re.search(pattern, path):
                return False, f"path-denied:{pattern}"

        if rate_limit is not None and float(rate_limit) > self.manifest.max_rate_per_sec:
            return False, f"rate-exceeds-scope:{rate_limit:g}>{self.manifest.max_rate_per_sec:g}"

        if resolve:
            for raw_ip in self.resolver(hostname):
                ip = ipaddress.ip_address(raw_ip)
                third_party = self._third_party_name_for_ip(ip)
                if third_party:
                    return False, f"third-party-excluded:{third_party}:{ip}"
                if not self._ip_allowed(str(ip)):
                    return False, f"resolved-ip-out-of-scope:{ip}"

        return True, f"allowed rate={self.manifest.max_rate_per_sec:g}"

    def _ip_allowed(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        deny = [ipaddress.ip_network(c, strict=False) for c in self.manifest.ip_cidr_deny]
        if any(addr in net for net in deny):
            return False
        allow = [ipaddress.ip_network(c, strict=False) for c in self.manifest.ip_cidr_allow]
        if allow:
            return any(addr in net for net in allow)
        return not _is_ip(ip)

    def _third_party_name_for_ip(self, addr: ipaddress._BaseAddress) -> str | None:
        for exclusion in self.manifest.third_party_exclusions:
            for net in exclusion.networks():
                if addr in net:
                    return exclusion.name
        return None


def resolve_ips(hostname: str) -> list[ipaddress._BaseAddress]:
    if _is_ip(hostname):
        return [ipaddress.ip_address(hostname)]
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []
    out = []
    for info in infos:
        try:
            out.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    return list(dict.fromkeys(out))


def _parse_url(url: str):
    if not url or not isinstance(url, str):
        return None
    normalized = url if "://" in url else f"https://{url}"
    try:
        parsed = urlparse(normalized)
    except Exception:
        return None
    return parsed if parsed.hostname else None


def _domain_matches(hostname: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return hostname.endswith(suffix) and hostname != suffix[1:]
    return hostname == pattern


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _main() -> int:
    parser = argparse.ArgumentParser(description="Validate a URL against scope.yaml")
    parser.add_argument("--scope", required=True, help="Path to target scope.yaml")
    parser.add_argument("--url", required=True)
    parser.add_argument("--method", default="GET")
    parser.add_argument("--rate-limit", type=float, default=None)
    parser.add_argument("--approve-active", action="store_true")
    parser.add_argument("--no-resolve", action="store_true")
    args = parser.parse_args()

    manifest = ScopeManifest.from_file(args.scope)
    ok, reason = manifest.checker().check(
        args.url,
        method=args.method,
        approve_active=args.approve_active,
        rate_limit=args.rate_limit,
        resolve=not args.no_resolve,
    )
    print(f"{'ALLOW' if ok else 'BLOCK'} {reason}")
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(_main())
