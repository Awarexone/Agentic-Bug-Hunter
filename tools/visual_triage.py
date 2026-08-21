#!/usr/bin/env python3
"""
Visual triage — screenshot a list of live hosts for fast surface review AND
reusable PoC evidence.

Staring at 400 URLs in a text file is slow; a screenshot gallery surfaces login
panels, default installs, error pages, and dev/staging boxes in seconds. The
same captures double as report evidence, closing the "no automatic PoC capture"
gap.

Prefers whichever screenshotter is installed, in order:
  1. eyewitness  (registered `eyewitness|probe`) — richest report
  2. aquatone    (registered `aquatone|probe`)   — fast, clustered gallery
  3. httpx -screenshot                            — already a core dependency

Command construction + gallery indexing are pure and unit-tested; only
`capture()` shells out.

Usage:
  tools/visual_triage.py -l recon/target.com/live/urls.txt -o shots/
  tools/visual_triage.py -u https://admin.target.com -o shots/
  tools/visual_triage.py -l urls.txt -o shots/ --tool aquatone --json
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

TOOLS = ("eyewitness", "aquatone", "httpx")
IMAGE_EXTS = {".png", ".jpg", ".jpeg"}


@dataclass
class Shot:
    url: str
    image: str


def pick_tool(preferred: str | None, available: set[str]) -> str | None:
    """Pure: choose a screenshotter. Explicit preference wins if present,
    otherwise fall back through the priority order."""
    if preferred:
        return preferred if preferred in available else None
    for t in TOOLS:
        if t in available:
            return t
    return None


def build_cmd(tool: str, input_file: str, outdir: str) -> list[str]:
    """Pure: the shell command for each supported screenshotter."""
    if tool == "eyewitness":
        return ["eyewitness", "--web", "-f", input_file, "-d", outdir, "--no-prompt"]
    if tool == "aquatone":
        # aquatone reads targets on stdin; caller pipes input_file in.
        return ["aquatone", "-out", outdir]
    if tool == "httpx":
        return ["httpx", "-silent", "-list", input_file, "-screenshot", "-srd", outdir]
    raise ValueError(f"unknown screenshot tool: {tool}")


def index_gallery(outdir: str) -> list[Shot]:
    """Pure-ish: walk an output dir for captured images and pair each with the
    URL its filename encodes (host + port, the convention all three tools use)."""
    root = Path(outdir)
    shots: list[Shot] = []
    if not root.exists():
        return shots
    for img in sorted(root.rglob("*")):
        if img.suffix.lower() not in IMAGE_EXTS:
            continue
        shots.append(Shot(url=_url_from_name(img.stem), image=str(img)))
    return shots


def _url_from_name(stem: str) -> str:
    """Best-effort reverse of the `https__host_port` filename convention."""
    name = stem
    for scheme in ("https", "http"):
        if name.startswith(scheme + "__") or name.startswith(scheme + "_"):
            rest = name.split("_", 2)[-1] if "__" not in name else name.split("__", 1)[1]
            host = rest.replace("_", ".").rstrip(".")
            return f"{scheme}://{host}"
    return name.replace("_", ".")


def render_html(shots: list[Shot], title: str = "Visual Triage") -> str:
    """Pure: a self-contained gallery page (no external assets)."""
    cells = "\n".join(
        f'<figure><a href="{s.image}"><img src="{s.image}" loading="lazy"/></a>'
        f"<figcaption>{s.url}</figcaption></figure>"
        for s in shots
    )
    return (
        f"<!doctype html><meta charset=utf-8><title>{title}</title>"
        "<style>body{background:#0b0e14;color:#c8d3f5;font:14px system-ui;margin:24px}"
        "h1{font-size:18px}main{display:grid;gap:16px;"
        "grid-template-columns:repeat(auto-fill,minmax(320px,1fr))}"
        "figure{margin:0;background:#141a24;border:1px solid #232a36;border-radius:8px;overflow:hidden}"
        "img{width:100%;display:block}figcaption{padding:8px 10px;font-size:12px;"
        "word-break:break-all;color:#7f8ba3}</style>"
        f"<h1>{title} — {len(shots)} host(s)</h1><main>{cells}</main>"
    )


def capture(tool: str, input_file: str, outdir: str) -> subprocess.CompletedProcess:
    Path(outdir).mkdir(parents=True, exist_ok=True)
    cmd = build_cmd(tool, input_file, outdir)
    if tool == "aquatone":
        with open(input_file, "r", encoding="utf-8", errors="replace") as fh:
            return subprocess.run(cmd, stdin=fh, capture_output=True, text=True, timeout=3600)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=3600)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Screenshot live hosts for triage + PoC evidence.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("-l", "--list", dest="list_file", help="file of URLs, one per line")
    src.add_argument("-u", "--url", help="a single URL")
    ap.add_argument("-o", "--out", required=True, help="output directory for screenshots")
    ap.add_argument("--tool", choices=TOOLS, help="force a specific screenshotter")
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args(argv)

    available = {t for t in TOOLS if shutil.which(t)}
    tool = pick_tool(args.tool, available)
    if tool is None:
        want = args.tool or " / ".join(TOOLS)
        print(
            f"[-] no screenshot tool available ({want}).\n"
            "    eyewitness: brew install eyewitness  (or pipx)\n"
            "    aquatone  : go install github.com/michenriksen/aquatone@latest\n"
            "    httpx     : go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
            file=sys.stderr,
        )
        return 127

    # Normalize a single-URL run into a temp list beside the output dir.
    input_file = args.list_file
    if args.url:
        Path(args.out).mkdir(parents=True, exist_ok=True)
        input_file = str(Path(args.out) / "_targets.txt")
        Path(input_file).write_text(args.url + "\n", encoding="utf-8")
    elif not Path(input_file).is_file():
        print(f"[-] URL list not found: {input_file}", file=sys.stderr)
        return 2

    try:
        capture(tool, input_file, args.out)
    except subprocess.TimeoutExpired:
        print("[-] screenshot capture timed out (60m).", file=sys.stderr)
        return 124

    shots = index_gallery(args.out)
    gallery = Path(args.out) / "gallery.html"
    gallery.write_text(render_html(shots), encoding="utf-8")

    if args.json:
        print(json.dumps({"tool": tool, "count": len(shots), "gallery": str(gallery),
                          "shots": [asdict(s) for s in shots]}, indent=2))
    else:
        print(f"[+] {tool}: captured {len(shots)} screenshot(s)")
        print(f"[+] gallery: {gallery}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
