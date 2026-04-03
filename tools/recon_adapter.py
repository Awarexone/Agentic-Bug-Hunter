"""
Recon output adapter — normalizes recon data across formats.

Reads the nested directory format produced by recon_engine.sh and provides
a unified API for agent.py, brain.py, and recon-ranker to consume recon data.

Handles fallback paths (e.g. httpx_full.txt at root vs live/httpx_full.txt)
and can normalize a recon directory by creating missing stub files that
brain.py expects (priority/, api_specs/, urls/graphql.txt, etc.).

Usage:
    adapter = ReconAdapter(Path("recon/target.com"))
    subs = adapter.get_subdomains()
    adapter.normalize()  # create missing stubs for brain.py
"""

import json
import re
from pathlib import Path


class ReconAdapter:
    """Unified reader for recon output directories."""

    GRAPHQL_PATTERNS = re.compile(
        r"graphql|/gql\b|/graphiql|/altair|/playground",
        re.IGNORECASE,
    )

    def __init__(self, recon_dir: str | Path):
        self._dir = Path(recon_dir)

    def _read_lines(self, *paths: str) -> list[str]:
        """Read non-empty lines from the first existing file in paths.

        Tries each path relative to self._dir in order, returns lines
        from the first one found. Deduplicates and strips whitespace.
        """
        for p in paths:
            fp = self._dir / p
            if fp.is_file():
                seen = set()
                result = []
                for line in fp.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if line and line not in seen:
                        seen.add(line)
                        result.append(line)
                return result
        return []

    # ── Data accessors ────────────────────────────────────────────────────

    def get_subdomains(self) -> list[str]:
        """All discovered subdomains."""
        return self._read_lines("subdomains/all.txt")

    def get_resolved_subdomains(self) -> list[str]:
        """Resolved subdomains (DNS-confirmed). Falls back to all.txt."""
        return self._read_lines("subdomains/resolved.txt", "subdomains/all.txt")

    def get_live_hosts(self) -> list[str]:
        """Live HTTP hosts. Extracts URLs from httpx output if needed."""
        # Try live/urls.txt first (clean URLs)
        lines = self._read_lines("live/urls.txt")
        if lines:
            return lines
        # Fallback: parse httpx_full.txt (format: "https://host [status] [type]")
        for path in ("live/httpx_full.txt", "httpx_full.txt"):
            fp = self._dir / path
            if fp.is_file():
                seen = set()
                result = []
                for line in fp.read_text(encoding="utf-8", errors="replace").splitlines():
                    url = line.strip().split()[0] if line.strip() else ""
                    if url and url not in seen:
                        seen.add(url)
                        result.append(url)
                return result
        return []

    def get_urls(self) -> list[str]:
        """All collected URLs."""
        return self._read_lines("urls/all.txt")

    def get_parameterized_urls(self) -> list[str]:
        """URLs with query parameters."""
        return self._read_lines("urls/with_params.txt", "params/with_params.txt")

    def get_js_files(self) -> list[str]:
        """JavaScript file URLs."""
        return self._read_lines("urls/js_files.txt")

    def get_api_endpoints(self) -> list[str]:
        """API endpoint URLs."""
        return self._read_lines("urls/api_endpoints.txt")

    def get_sensitive_paths(self) -> list[str]:
        """Sensitive file paths discovered."""
        return self._read_lines("urls/sensitive_paths.txt")

    def get_js_secrets(self) -> list[str]:
        """Potential secrets found in JavaScript files."""
        return self._read_lines("js/potential_secrets.txt")

    def get_interesting_params(self) -> list[str]:
        """Parameters flagged for injection testing."""
        return self._read_lines("params/interesting_params.txt")

    def get_config_exposure(self) -> list[str]:
        """Exposed configuration files."""
        return self._read_lines("exposure/config_files.txt")

    def get_graphql_endpoints(self) -> list[str]:
        """GraphQL endpoints — from dedicated file or filtered from all URLs."""
        # Prefer dedicated file
        dedicated = self._read_lines("urls/graphql.txt")
        if dedicated:
            return dedicated
        # Filter from all URLs
        all_urls = self.get_urls()
        return [u for u in all_urls if self.GRAPHQL_PATTERNS.search(u)]

    # ── Summary ───────────────────────────────────────────────────────────

    def summary(self) -> dict:
        """Quick overview of recon data counts."""
        return {
            "subdomains": len(self.get_subdomains()),
            "live_hosts": len(self.get_live_hosts()),
            "urls": len(self.get_urls()),
            "parameterized_urls": len(self.get_parameterized_urls()),
            "js_files": len(self.get_js_files()),
            "api_endpoints": len(self.get_api_endpoints()),
            "sensitive_paths": len(self.get_sensitive_paths()),
            "graphql_endpoints": len(self.get_graphql_endpoints()),
        }

    # ── Normalize ─────────────────────────────────────────────────────────

    def normalize(self) -> None:
        """Ensure all files expected by brain.py exist.

        Creates missing directories and stub files so that brain.py's strict
        path lookups don't fail. Existing files are never overwritten.
        """
        if not self._dir.is_dir():
            return

        # Ensure directories
        for subdir in ("priority", "api_specs"):
            (self._dir / subdir).mkdir(parents=True, exist_ok=True)

        # subdomains/resolved.txt — derive from live hosts if missing
        self._ensure_file(
            "subdomains/resolved.txt",
            lambda: "\n".join(self._extract_domains_from_live()) + "\n"
            if self._extract_domains_from_live() else "",
        )

        # urls/graphql.txt — filter from all URLs
        self._ensure_file(
            "urls/graphql.txt",
            lambda: "\n".join(self.get_graphql_endpoints()) + "\n"
            if self.get_graphql_endpoints() else "",
        )

        # priority/prioritized_hosts.json
        self._ensure_file(
            "priority/prioritized_hosts.json",
            lambda: json.dumps(self._build_priority_json(), indent=2) + "\n",
        )

        # priority/critical_hosts.txt
        self._ensure_file("priority/critical_hosts.txt", lambda: "")

        # priority/high_hosts.txt
        self._ensure_file("priority/high_hosts.txt", lambda: "")

        # priority/attack_surface.md
        self._ensure_file(
            "priority/attack_surface.md",
            lambda: self._build_attack_surface_md(),
        )

        # api_specs stubs
        for stub in ("spec_urls.txt", "public_operations.txt",
                      "unauth_api_findings.txt", "summary.md"):
            self._ensure_file(f"api_specs/{stub}", lambda: "")

        # live/nuclei_takeovers.txt
        self._ensure_file("live/nuclei_takeovers.txt", lambda: "")

    def _ensure_file(self, rel_path: str, content_fn) -> None:
        """Create file if it doesn't exist. Never overwrites."""
        fp = self._dir / rel_path
        if fp.exists():
            return
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content_fn(), encoding="utf-8")

    def _extract_domains_from_live(self) -> list[str]:
        """Extract bare domains from live host URLs."""
        hosts = self.get_live_hosts()
        domains = set()
        for url in hosts:
            # Strip scheme
            if "://" in url:
                url = url.split("://", 1)[1]
            domain = url.split("/", 1)[0].split(":")[0]
            if domain:
                domains.add(domain)
        return sorted(domains)

    def _build_priority_json(self) -> dict:
        """Build a basic prioritized hosts structure."""
        live = self.get_live_hosts()
        apis = self.get_api_endpoints()
        gql = self.get_graphql_endpoints()
        sensitive = self.get_sensitive_paths()

        hosts = {}
        for url in live:
            if "://" in url:
                domain = url.split("://", 1)[1].split("/", 1)[0]
            else:
                domain = url.split("/", 1)[0]

            if domain not in hosts:
                hosts[domain] = {"host": domain, "signals": [], "priority": "medium"}

            # Boost priority based on signals
            if any(domain in a for a in apis):
                hosts[domain]["signals"].append("api_endpoints")
                hosts[domain]["priority"] = "high"
            if any(domain in g for g in gql):
                hosts[domain]["signals"].append("graphql")
                hosts[domain]["priority"] = "high"
            if any(domain in s for s in sensitive):
                hosts[domain]["signals"].append("sensitive_paths")
                hosts[domain]["priority"] = "critical"

        return {"hosts": hosts}

    def _build_attack_surface_md(self) -> str:
        """Build a markdown attack surface summary."""
        s = self.summary()
        lines = [
            "# Attack Surface Summary\n",
            f"- Subdomains: {s['subdomains']}",
            f"- Live hosts: {s['live_hosts']}",
            f"- URLs collected: {s['urls']}",
            f"- Parameterized URLs: {s['parameterized_urls']}",
            f"- API endpoints: {s['api_endpoints']}",
            f"- JS files: {s['js_files']}",
            f"- GraphQL endpoints: {s['graphql_endpoints']}",
            f"- Sensitive paths: {s['sensitive_paths']}",
            "",
        ]
        return "\n".join(lines)
