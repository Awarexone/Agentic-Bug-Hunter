"""Shared CLI banner — ASCII "BUGHUNTER" logo with a red→yellow gradient.

Import and call:

    from tools.banner import print_banner
    print_banner(
        "Bug Bounty Automation Pipeline",
        target="example.com",
        steps=[
            ("Recon", "subdomain enum, URL crawl, tech fingerprint"),
            ("Hunt",  "XSS · SQLi · SSRF · IDOR · LLM probes"),
        ],
    )

Respects NO_COLOR and falls back to plain text on non-TTY stdout.
"""

from __future__ import annotations

import os
import sys
from typing import Iterable, Optional, Sequence, Tuple, Union

_LOGO = [
    "██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ",
    "██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗",
    "██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝",
    "██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗",
    "██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║",
    "╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝",
]
_LOGO_WIDTH = max(len(line) for line in _LOGO)

# Red → orange → gold gradient for 256-color terminals.
_GRADIENT_256 = [
    "\033[38;5;196m", "\033[38;5;202m", "\033[38;5;208m",
    "\033[38;5;214m", "\033[38;5;220m", "\033[38;5;226m",
]
# 8-color fallback for terminals without 256-color support.
_GRADIENT_8 = [
    "\033[1;31m", "\033[0;31m", "\033[1;33m",
    "\033[0;33m", "\033[1;33m", "\033[0;33m",
]

_CYAN = "\033[1;36m"
_MAGENTA = "\033[1;35m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_NC = "\033[0m"

_TAG = "bughunter.fun  ·  github.com/shuvonsec/claude-bug-bounty"


def _use_color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _should_skip(stream) -> bool:
    # Don't print the banner more than once per process tree (parent → child).
    if os.environ.get("BBHUNT_BANNER_SHOWN"):
        return True
    # Don't print into a pipe / file — keeps logs and parser-fed output clean.
    if not getattr(stream, "isatty", lambda: False)():
        return True
    if os.environ.get("BBHUNT_NO_BANNER"):
        return True
    return False


def _palette(stream):
    if not _use_color(stream):
        return [""] * 6, "", "", "", "", ""
    term = os.environ.get("TERM", "")
    colorterm = os.environ.get("COLORTERM", "")
    use_256 = "256" in term or colorterm in ("truecolor", "24bit") or term.startswith("xterm")
    grad = _GRADIENT_256 if use_256 else _GRADIENT_8
    return grad, _CYAN, _MAGENTA, _BOLD, _DIM, _NC


def _center(text: str, width: int) -> str:
    pad = max(0, (width - len(text)) // 2)
    return " " * pad + text


Step = Union[str, Tuple[str, str]]


def print_banner(subtitle: Optional[str] = None, target: Optional[str] = None,
                 steps: Optional[Sequence[Step]] = None, stream=None) -> None:
    """Print the BUGHUNTER banner.

    Args:
        subtitle: one-line caption shown in cyan beneath the logo.
        target:   the host/domain being hunted (printed in magenta).
        steps:    iterable of either "Label" strings or (label, description) tuples.
                  Rendered as a numbered "Workflow" block beneath the byline.
    """
    if stream is None:
        stream = sys.stdout
    if _should_skip(stream):
        return
    grad, cyan, magenta, bold, dim, nc = _palette(stream)

    print(file=stream)
    for color, row in zip(grad, _LOGO):
        print(f"  {color}{row}{nc}", file=stream)

    if subtitle:
        bar = "─" * _LOGO_WIDTH
        print(f"  {cyan}{bar}{nc}", file=stream)
        print(f"  {cyan}{_center(subtitle, _LOGO_WIDTH)}{nc}", file=stream)

    print(f"  {dim}{_center(_TAG, _LOGO_WIDTH)}{nc}", file=stream)
    if target:
        line = f"▸ target: {target}"
        print(f"  {magenta}{_center(line, _LOGO_WIDTH)}{nc}", file=stream)

    if steps:
        normalized: list = []
        for s in steps:
            if isinstance(s, tuple):
                normalized.append((str(s[0]), str(s[1]) if len(s) > 1 else ""))
            else:
                normalized.append((str(s), ""))
        label_width = max(len(label) for label, _ in normalized)
        print(file=stream)
        print(f"  {dim}{_center('── Workflow ──', _LOGO_WIDTH)}{nc}", file=stream)
        for idx, (label, desc) in enumerate(normalized, 1):
            num = f"{cyan}{idx}.{nc}"
            label_col = f"{bold}{label:<{label_width}}{nc}"
            desc_col = f"{dim}{desc}{nc}" if desc else ""
            print(f"   {num}  {label_col}  {desc_col}", file=stream)

    print(file=stream)
    # Mark printed so child processes (subprocess.run / os.execvp) skip.
    os.environ["BBHUNT_BANNER_SHOWN"] = "1"


if __name__ == "__main__":
    # Preview: `python3 -m tools.banner [subtitle] [target]`
    sub = sys.argv[1] if len(sys.argv) > 1 else "Bug Bounty Automation Pipeline"
    tgt = sys.argv[2] if len(sys.argv) > 2 else None
    demo_steps = [
        ("Recon",    "subdomain enum, URL crawl, tech fingerprint, CVE sweep"),
        ("Hunt",     "XSS · SQLi · SSRF · IDOR · auth bypass · LLM probes"),
        ("Validate", "7-Question Gate · 4-gate checklist · kill weak findings"),
        ("Report",   "H1/Bugcrowd/Intigriti template · CVSS 3.1 · PoC + repro"),
    ]
    print_banner(sub, target=tgt, steps=demo_steps)
