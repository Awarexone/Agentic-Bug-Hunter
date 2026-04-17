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
