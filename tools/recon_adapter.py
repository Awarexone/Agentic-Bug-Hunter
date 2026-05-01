#!/usr/bin/env python3
"""
recon_adapter.py — Canonical recon output normalizer.

Resolves TODO-5: recon_engine.sh writes a nested directory format while
recon-agent.md expected flat files. This adapter reads either format and
returns a unified ReconData object.

Canonical format (nested — preferred):
    recon/<target>/subdomains.txt
    recon/<target>/live-hosts.txt
    recon/<target>/urls.txt
    recon/<target>/nuclei.txt
    recon/<target>/technologies.txt

Legacy flat format:
    recon/<target>-subdomains.txt
    recon/<target>-live-hosts.txt
    recon/<target>-urls.txt

Usage:
    from tools.recon_adapter import load_recon
    data = load_recon("example.com", recon_dir="recon")
    print(data.subdomains)
    print(data.live_hosts)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ReconData:
    target: str
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    nuclei_findings: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    source_format: str = "unknown"  # "nested" | "flat" | "empty"

    @property
    def is_empty(self) -> bool:
        return not any([self.subdomains, self.live_hosts, self.urls])

    def summary(self) -> str:
        return (
            f"ReconData({self.target}): "
            f"{len(self.subdomains)} subdomains, "
            f"{len(self.live_hosts)} live hosts, "
            f"{len(self.urls)} URLs, "
            f"{len(self.nuclei_findings)} nuclei findings "
            f"[format={self.source_format}]"
        )


def _read_lines(path: Path) -> list[str]:
    """Read non-empty, non-comment lines from a file. Returns [] if file missing."""
    if not path.exists():
        return []
    with path.open() as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]


def _load_nested(target: str, recon_dir: Path) -> ReconData | None:
    """Try to load from nested format: recon/<target>/subdomains.txt etc."""
    target_dir = recon_dir / target
    if not target_dir.is_dir():
        return None

    data = ReconData(
        target=target,
        subdomains=_read_lines(target_dir / "subdomains.txt"),
        live_hosts=_read_lines(target_dir / "live-hosts.txt"),
        urls=_read_lines(target_dir / "urls.txt"),
        nuclei_findings=_read_lines(target_dir / "nuclei.txt"),
        technologies=_read_lines(target_dir / "technologies.txt"),
        source_format="nested",
    )
    return data if not data.is_empty else None


def _load_flat(target: str, recon_dir: Path) -> ReconData | None:
    """Try to load from legacy flat format: recon/<target>-subdomains.txt etc."""
    safe = target.replace(".", "-")
    subdomains   = _read_lines(recon_dir / f"{safe}-subdomains.txt")
    live_hosts   = _read_lines(recon_dir / f"{safe}-live-hosts.txt")
    urls         = _read_lines(recon_dir / f"{safe}-urls.txt")
    nuclei       = _read_lines(recon_dir / f"{safe}-nuclei.txt")
    technologies = _read_lines(recon_dir / f"{safe}-technologies.txt")

    if not any([subdomains, live_hosts, urls]):
        return None

    return ReconData(
        target=target,
        subdomains=subdomains,
        live_hosts=live_hosts,
        urls=urls,
        nuclei_findings=nuclei,
        technologies=technologies,
        source_format="flat",
    )


def load_recon(target: str, recon_dir: str | Path = "recon") -> ReconData:
    """
    Load recon data for a target, auto-detecting nested vs flat format.

    Preference order:
      1. Nested: recon/<target>/ directory (canonical)
      2. Flat:   recon/<target>-*.txt files (legacy)
      3. Empty:  returns ReconData with no findings

    Args:
        target:    Target domain (e.g. "example.com")
        recon_dir: Path to the recon directory (default: "recon")

    Returns:
        ReconData with all available findings populated.
    """
    recon_path = Path(recon_dir)

    data = _load_nested(target, recon_path)
    if data:
        return data

    data = _load_flat(target, recon_path)
    if data:
        return data

    return ReconData(target=target, source_format="empty")


def normalize_to_nested(data: ReconData, recon_dir: str | Path = "recon") -> Path:
    """
    Write a ReconData object to canonical nested format.
    Used to migrate legacy flat-format recon to the canonical structure.

    Returns the path to the created target directory.
    """
    recon_path = Path(recon_dir)
    target_dir = recon_path / data.target
    target_dir.mkdir(parents=True, exist_ok=True)

    def write(filename: str, lines: list[str]) -> None:
        if lines:
            (target_dir / filename).write_text("\n".join(lines) + "\n")

    write("subdomains.txt", data.subdomains)
    write("live-hosts.txt", data.live_hosts)
    write("urls.txt", data.urls)
    write("nuclei.txt", data.nuclei_findings)
    write("technologies.txt", data.technologies)

    return target_dir


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Inspect or migrate recon output to canonical nested format."
    )
    parser.add_argument("target", help="Target domain (e.g. example.com)")
    parser.add_argument("--recon-dir", default="recon", help="Recon directory (default: recon)")
    parser.add_argument(
        "--migrate",
        action="store_true",
        help="Migrate flat-format recon to nested canonical format",
    )
    args = parser.parse_args()

    data = load_recon(args.target, args.recon_dir)
    print(data.summary())

    if data.source_format == "empty":
        print("No recon data found.")
        sys.exit(1)

    if args.migrate and data.source_format == "flat":
        dest = normalize_to_nested(data, args.recon_dir)
        print(f"Migrated to nested format: {dest}")
    elif args.migrate and data.source_format == "nested":
        print("Already in canonical nested format — nothing to migrate.")


# ─── Subdir-nested adapter (recon_engine.sh layout) ──────────────────────────
#
# recon_engine.sh writes a richer per-target tree:
#   <target>/subdomains/all.txt        live/urls.txt          live/httpx_full.txt
#   <target>/urls/all.txt              urls/with_params.txt   urls/js_files.txt
#   <target>/urls/api_endpoints.txt    urls/sensitive_paths.txt
#   <target>/js/potential_secrets.txt  params/interesting_params.txt
#   <target>/exposure/config_files.txt
#
# ReconAdapter wraps that layout with typed accessors and a normalize() step
# that creates the derived files brain.py expects (priority/, api_specs/,
# urls/graphql.txt, subdomains/resolved.txt). Distinct from load_recon() above
# which reads the simpler one-file-per-category canonical format.


class ReconAdapter:
    """Read and normalize recon output from the subdir-nested layout."""

    GRAPHQL_HINTS = ("/graphql", "/gql", "/v1/graphql", "/api/graphql")

    def __init__(self, recon_dir: str | Path):
        self.recon_dir = Path(recon_dir)

    # ── Internal ─────────────────────────────────────────────────────────

    def _read_unique(self, *paths: Path) -> list[str]:
        """Read the first existing file. Strip blanks, dedup, preserve order."""
        for p in paths:
            if p.exists():
                with p.open() as f:
                    lines = [ln.strip() for ln in f if ln.strip()]
                return list(dict.fromkeys(lines))
        return []

    @staticmethod
    def _first_token(line: str) -> str:
        """Take the first whitespace-delimited token (URL out of httpx output)."""
        return line.split()[0] if line.strip() else ""

    # ── Reads ────────────────────────────────────────────────────────────

    def get_subdomains(self) -> list[str]:
        return self._read_unique(self.recon_dir / "subdomains" / "all.txt")

    def get_resolved_subdomains(self) -> list[str]:
        return self._read_unique(
            self.recon_dir / "subdomains" / "resolved.txt",
            self.recon_dir / "subdomains" / "all.txt",
        )

    def get_live_hosts(self) -> list[str]:
        # Prefer the clean URL list; fall back to extracting URLs from the
        # full httpx output (lines like "https://x [200] [json]").
        clean = self._read_unique(self.recon_dir / "live" / "urls.txt")
        if clean:
            return clean
        for src in (self.recon_dir / "live" / "httpx_full.txt", self.recon_dir / "httpx_full.txt"):
            if src.exists():
                with src.open() as f:
                    urls = [self._first_token(ln) for ln in f if ln.strip()]
                return list(dict.fromkeys(u for u in urls if u))
        return []

    def get_urls(self) -> list[str]:
        return self._read_unique(self.recon_dir / "urls" / "all.txt")

    def get_parameterized_urls(self) -> list[str]:
        return self._read_unique(self.recon_dir / "urls" / "with_params.txt")

    def get_js_files(self) -> list[str]:
        return self._read_unique(self.recon_dir / "urls" / "js_files.txt")

    def get_api_endpoints(self) -> list[str]:
        return self._read_unique(self.recon_dir / "urls" / "api_endpoints.txt")

    def get_sensitive_paths(self) -> list[str]:
        return self._read_unique(self.recon_dir / "urls" / "sensitive_paths.txt")

    def get_js_secrets(self) -> list[str]:
        return self._read_unique(self.recon_dir / "js" / "potential_secrets.txt")

    def get_interesting_params(self) -> list[str]:
        return self._read_unique(self.recon_dir / "params" / "interesting_params.txt")

    def get_config_exposure(self) -> list[str]:
        return self._read_unique(self.recon_dir / "exposure" / "config_files.txt")

    def get_graphql_endpoints(self) -> list[str]:
        """Prefer urls/graphql.txt if present; otherwise filter all URLs."""
        dedicated = self.recon_dir / "urls" / "graphql.txt"
        if dedicated.exists():
            return self._read_unique(dedicated)
        return [u for u in self.get_urls() if any(h in u.lower() for h in self.GRAPHQL_HINTS)]

    # ── Summary ──────────────────────────────────────────────────────────

    def summary(self) -> dict[str, int]:
        return {
            "subdomains": len(self.get_subdomains()),
            "live_hosts": len(self.get_live_hosts()),
            "urls": len(self.get_urls()),
            "parameterized_urls": len(self.get_parameterized_urls()),
            "js_files": len(self.get_js_files()),
            "api_endpoints": len(self.get_api_endpoints()),
        }

    # ── Normalize ────────────────────────────────────────────────────────

    def normalize(self) -> None:
        """Create derived files brain.py / autopilot expect.

        Idempotent. Never overwrites files that already exist.
        """
        self.recon_dir.mkdir(parents=True, exist_ok=True)
        (self.recon_dir / "priority").mkdir(exist_ok=True)
        (self.recon_dir / "api_specs").mkdir(exist_ok=True)
        (self.recon_dir / "urls").mkdir(exist_ok=True)
        (self.recon_dir / "subdomains").mkdir(exist_ok=True)

        # urls/graphql.txt — populate from the URL list if not present
        gql_path = self.recon_dir / "urls" / "graphql.txt"
        if not gql_path.exists():
            gql = [u for u in self.get_urls() if any(h in u.lower() for h in self.GRAPHQL_HINTS)]
            gql_path.write_text("\n".join(gql) + ("\n" if gql else ""))

        # subdomains/resolved.txt — fall back to all.txt if not yet present
        resolved_path = self.recon_dir / "subdomains" / "resolved.txt"
        if not resolved_path.exists():
            subs = self.get_subdomains()
            resolved_path.write_text("\n".join(subs) + ("\n" if subs else ""))

        # priority/prioritized_hosts.json — minimal scaffold
        pj_path = self.recon_dir / "priority" / "prioritized_hosts.json"
        if not pj_path.exists():
            import json
            pj_path.write_text(json.dumps({
                "hosts": self.get_live_hosts(),
                "summary": self.summary(),
            }, indent=2) + "\n")

        # priority/attack_surface.md — minimal scaffold
        md_path = self.recon_dir / "priority" / "attack_surface.md"
        if not md_path.exists():
            target_label = self.recon_dir.name or "target"
            s = self.summary()
            md_path.write_text(
                f"# Attack Surface — {target_label}\n\n"
                f"- Subdomains: {s['subdomains']}\n"
                f"- Live hosts: {s['live_hosts']}\n"
                f"- URLs: {s['urls']}\n"
                f"- Parameterized URLs: {s['parameterized_urls']}\n"
                f"- JS files: {s['js_files']}\n"
                f"- API endpoints: {s['api_endpoints']}\n"
            )
