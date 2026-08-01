#!/usr/bin/env python3
"""
gen_docs.py — regenerates the inventory sections of AGENTS.md and OPENCODE.md
from docs/manifest.json.

Problem this solves: CLAUDE.md, AGENTS.md, and OPENCODE.md each hand-carried
their own copy of the skills/commands/agents/tools/memory inventory. They
drifted independently (AGENTS.md was stuck at "8 agents / 9 skills / 21
commands" while the repo had grown to 13/13/27) because there was nowhere
that forced them to agree. docs/manifest.json is now that place — this
script is the only thing allowed to write the generated regions, and
tests/test_doc_sync.py fails CI if a human edits those regions by hand
instead of updating the manifest.

Each generated region is delimited by an HTML comment pair:
    <!-- GENERATED:<key>:START (see docs/manifest.json — run scripts/gen_docs.py) -->
    ...
    <!-- GENERATED:<key>:END -->
Everything outside those markers (harness-specific prose, installation
steps, troubleshooting, etc.) is left untouched.

Usage:
  python3 scripts/gen_docs.py            # rewrite AGENTS.md + OPENCODE.md in place
  python3 scripts/gen_docs.py --check    # exit 1 if either file would change (CI mode)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_PATH = os.path.join(REPO_ROOT, "docs", "manifest.json")

_START_RE = "<!-- GENERATED:{key}:START (see docs/manifest.json — run scripts/gen_docs.py) -->"
_END_RE = "<!-- GENERATED:{key}:END -->"


def load_manifest() -> dict:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ─── section renderers ─────────────────────────────────────────────────────
# Each harness gets its own renderer per section because the surrounding
# table shape (column headers, command-invocation syntax) differs, but all
# of them draw from the exact same manifest entries.

def render_skills_table(manifest: dict, *, path_column: bool) -> str:
    lines = ["| Skill | Domain |", "|---|---|"]
    for s in manifest["skills"]:
        label = f"`{s['path']}`" if path_column else f"`{s['name']}`"
        lines.append(f"| {label} | {s['description']} |")
    return "\n".join(lines)


def render_commands_table_claude_style(manifest: dict) -> str:
    """AGENTS.md/CLAUDE.md backtick both the command name and the invocation
    phrase, e.g.: | `/recon` | `/recon target.com` — full recon pipeline |
    """
    lines = ["| Command | Usage |", "|---|---|"]
    for c in manifest["commands"]:
        invocation, _, explanation = c["description"].partition(" — ")
        lines.append(f"| `/{c['name']}` | `{invocation}` — {explanation} |")
    return "\n".join(lines)


def render_commands_table_opencode_style(manifest: dict) -> str:
    """OPENCODE.md quotes just the invocation phrase and leaves the
    explanation unquoted after an em dash, e.g.:
        | `recon` | "recon target.com" — full recon pipeline |
    Manifest descriptions are "/name <args> — explanation"; strip the
    leading slash from the invocation half and keep the split.
    """
    lines = ["| Command | Usage |", "|---|---|"]
    for c in manifest["commands"]:
        invocation, _, explanation = c["description"].partition(" — ")
        invocation = invocation.lstrip("/")
        lines.append(f"| `{c['name']}` | \"{invocation}\" — {explanation} |")
    return "\n".join(lines)


def render_agents_list(manifest: dict) -> str:
    return "\n".join(f"- `{a['name']}` — {a['description']}" for a in manifest["agents"])


def render_tools_list(manifest: dict) -> str:
    return "\n".join(f"- `{t['path']}` — {t['description']}" for t in manifest["tools"])


def render_memory_list(manifest: dict) -> str:
    return "\n".join(f"- `{m['path']}` — {m['description']}" for m in manifest["memory"])


# ─── generic marker-region substitution ────────────────────────────────────

def apply_regions(text: str, regions: dict[str, str]) -> str:
    """Replace the content between each GENERATED:<key>:START/END marker pair.

    Raises ValueError if a requested key's markers aren't found in `text` —
    that's a hard failure, not a silent no-op, so a missing marker can't
    quietly leave stale content in place.
    """
    for key, body in regions.items():
        start_marker = _START_RE.format(key=key)
        end_marker = _END_RE.format(key=key)
        pattern = re.compile(
            re.escape(start_marker) + r".*?" + re.escape(end_marker),
            re.DOTALL,
        )
        replacement = f"{start_marker}\n{body}\n{end_marker}"
        new_text, count = pattern.subn(replacement, text, count=1)
        if count == 0:
            raise ValueError(
                f"marker pair for '{key}' not found — expected:\n{start_marker}\n...\n{end_marker}"
            )
        text = new_text
    return text


def render_agents_md(manifest: dict) -> dict:
    return {
        "skills": render_skills_table(manifest, path_column=False),
        "commands": render_commands_table_claude_style(manifest),
        "agents": render_agents_list(manifest),
        "tools": render_tools_list(manifest),
        "memory": render_memory_list(manifest),
    }


def render_opencode_md(manifest: dict) -> dict:
    return {
        "skills": render_skills_table(manifest, path_column=False),
        "commands": render_commands_table_opencode_style(manifest),
    }


TARGETS = {
    "AGENTS.md": render_agents_md,
    "OPENCODE.md": render_opencode_md,
}


def generate(check: bool = False) -> bool:
    """Returns True if all target files are already up to date."""
    manifest = load_manifest()
    all_clean = True
    for filename, render_fn in TARGETS.items():
        path = os.path.join(REPO_ROOT, filename)
        with open(path, "r", encoding="utf-8") as fh:
            original = fh.read()
        regions = render_fn(manifest)
        updated = apply_regions(original, regions)
        if updated != original:
            all_clean = False
            if check:
                print(f"STALE: {filename} does not match docs/manifest.json")
            else:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(updated)
                print(f"updated {filename}")
        elif not check:
            print(f"{filename} already up to date")
    return all_clean


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true",
        help="Don't write anything — exit 1 if AGENTS.md/OPENCODE.md would change.",
    )
    args = parser.parse_args()
    up_to_date = generate(check=args.check)
    if args.check and not up_to_date:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
