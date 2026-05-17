#!/usr/bin/env python3
"""
Live TUI dashboard for /recon and /hunt.

Renders an ANSI box that updates in place. Each phase ticks
[ ] pending → [⠹] running (spinner) → [✓] done with count + elapsed.
A "Latest:" line shows the most recent log message from the underlying script.

Two usage modes:

1) Python API:
       from tools.dashboard import Dashboard
       db = Dashboard(title="HUNT", target="target.com",
                      phases=[("subdomain_enum", "Subdomain enum"),
                              ("live_probe",     "Live host probe"), ...])
       db.start()
       db.phase_start("subdomain_enum")
       db.phase_update("subdomain_enum", note="1,247 subs")
       db.phase_done("subdomain_enum", note="1,247 subs", elapsed="12s")
       db.latest("katana   https://api.target.com/v2/orders/...")
       db.stop()

2) CLI tail mode — pipe a bash script through it:
       BBHUNT_DASHBOARD=1 bash tools/recon_engine.sh target.com \
           | python3 tools/dashboard.py --tail --kind recon --target target.com

   The tail parser recognizes the existing log_info / log_done / log_ok
   markers in recon_engine.sh and vuln_scanner.sh — no script changes
   required.

Falls back to plain pass-through output when stdout is not a TTY (piped,
redirected, captured by Claude Code, CI). The dashboard is decoration;
the actual log lines always reach stdout when not in TTY mode.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

# ── ANSI ─────────────────────────────────────────────────────────────────────

ESC = "\033"
CSI = ESC + "["
HIDE_CURSOR = CSI + "?25l"
SHOW_CURSOR = CSI + "?25h"
CLEAR_LINE = CSI + "2K"
CURSOR_UP = lambda n: f"{CSI}{n}A"
CURSOR_COL1 = "\r"

# Colours — match the bash scripts' palette so the dashboard feels native.
GREEN = CSI + "0;32m"
RED = CSI + "0;31m"
YELLOW = CSI + "1;33m"
CYAN = CSI + "0;36m"
DIM = CSI + "2m"
BOLD = CSI + "1m"
RESET = CSI + "0m"

SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


# ── ANSI-aware width helpers (used by both the banner and the dashboard) ─────

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def _visible_len(s: str) -> int:
    return len(_ANSI_RE.sub("", s))


def _pad_to(s: str, width: int) -> str:
    vis = _visible_len(s)
    if vis >= width:
        plain = _ANSI_RE.sub("", s)
        return plain[:width]
    return s + " " * (width - vis)


# ── Startup banner ───────────────────────────────────────────────────────────
#
# Tall green block letters for "BBHUNT" — drawn by hand so we have zero deps
# (no figlet, no pyfiglet). Each row is exactly 7 columns per letter + 1 gap.
# If you want different text, swap the LETTERS map. Width-clamps gracefully.

_LETTERS = {
    "B": [
        "██████ ",
        "██   ██",
        "██████ ",
        "██████ ",
        "██   ██",
        "██████ ",
    ],
    "H": [
        "██   ██",
        "██   ██",
        "███████",
        "███████",
        "██   ██",
        "██   ██",
    ],
    "U": [
        "██   ██",
        "██   ██",
        "██   ██",
        "██   ██",
        "██   ██",
        "███████",
    ],
    "N": [
        "███   █",
        "████  █",
        "██ ██ █",
        "██  ███",
        "██   ██",
        "██   ██",
    ],
    "T": [
        "███████",
        "  ███  ",
        "  ███  ",
        "  ███  ",
        "  ███  ",
        "  ███  ",
    ],
    " ": [
        "       ",
        "       ",
        "       ",
        "       ",
        "       ",
        "       ",
    ],
}


def _render_bigtext(text: str) -> list:
    """Render text as 6-line ASCII block letters. Unknown chars become blanks."""
    rows = ["", "", "", "", "", ""]
    for ch in text.upper():
        glyph = _LETTERS.get(ch, _LETTERS[" "])
        for i in range(6):
            rows[i] += glyph[i] + " "
    return rows


def print_banner(
    target: str = "",
    mode: str = "full",
    output_dir: str = "",
    auth: bool = False,
    extra_lines: Optional[list] = None,
    title: str = "BBHUNT",
    tagline: str = "+ Recon. Hunt. Validate. Report. +",
    version: str = "v4.3",
):
    """Print the OpenClaude-style startup banner.

    Big green block letters, tagline, an info panel (target/mode/output/auth),
    a status pill, and a version line. Renders to whatever stdout is — colour
    codes are emitted but degrade to plain text in non-colour terminals.
    """
    out = []

    # Big title.
    for row in _render_bigtext(title):
        out.append(f"{GREEN}{BOLD}{row}{RESET}")

    # Tagline.
    out.append("")
    out.append(f"{DIM}{tagline}{RESET}")
    out.append("")

    # Info panel — like OpenClaude's Provider/Model/Endpoint block.
    panel = []
    if target:
        panel.append(("Target",  f"{CYAN}{target}{RESET}"))
    panel.append(("Mode",    f"{YELLOW}{mode}{RESET}"))
    if output_dir:
        panel.append(("Output", f"{CYAN}{output_dir}{RESET}"))
    panel.append(("Auth",    f"{GREEN}session loaded{RESET}" if auth else f"{DIM}none{RESET}"))
    if extra_lines:
        for k, v in extra_lines:
            panel.append((k, v))

    label_width = max(len(k) for k, _ in panel) + 2
    panel_width = 56
    out.append(f"{GREEN}┌{'─' * (panel_width - 2)}┐{RESET}")
    for k, v in panel:
        label = f"{DIM}{k:<{label_width}}{RESET}"
        line = f" {label}{v}"
        pad = panel_width - 2 - _visible_len(line)
        out.append(f"{GREEN}│{RESET}{line}{' ' * max(0, pad)}{GREEN}│{RESET}")
    out.append(f"{GREEN}└{'─' * (panel_width - 2)}┘{RESET}")

    # Status pill — green dot + Ready + hint.
    out.append("")
    status = f" {GREEN}●{RESET} local   {GREEN}Ready{RESET}   {DIM}type /hunt to begin{RESET}"
    out.append(status)
    out.append("")
    out.append(f"{DIM}bbhunt {version}{RESET}")
    out.append("")

    sys.stdout.write("\n".join(out) + "\n")
    sys.stdout.flush()


# ── Data ─────────────────────────────────────────────────────────────────────

@dataclass
class Phase:
    key: str
    label: str
    state: str = "pending"  # pending | running | done | failed | skipped
    note: str = ""
    elapsed: str = ""
    started_at: float = 0.0


@dataclass
class Dashboard:
    title: str
    target: str
    phases: list  # list[tuple[str, str]] of (key, label) — preserves order
    width: int = 64
    refresh_hz: float = 10.0

    # internal
    _phases: dict = field(default_factory=dict, init=False)
    _phase_order: list = field(default_factory=list, init=False)
    _latest: str = field(default="", init=False)
    _start_ts: float = field(default=0.0, init=False)
    _spinner_idx: int = field(default=0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _thread: Optional[threading.Thread] = field(default=None, init=False)
    _stop: threading.Event = field(default_factory=threading.Event, init=False)
    _rendered_lines: int = field(default=0, init=False)
    _is_tty: bool = field(default=False, init=False)
    _failed: bool = field(default=False, init=False)

    def __post_init__(self):
        self._is_tty = sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb"
        for key, label in self.phases:
            self._phases[key] = Phase(key=key, label=label)
            self._phase_order.append(key)

        cols = shutil.get_terminal_size((self.width, 24)).columns
        # Box looks bad below 50 cols. Clamp to terminal width with sane min/max.
        self.width = max(50, min(self.width, cols))

    # ── lifecycle ────────────────────────────────────────────────────────────

    def start(self):
        self._start_ts = time.time()
        if not self._is_tty:
            # Non-TTY: print a one-time banner and return. Phase transitions
            # will print as plain lines via _emit_plain().
            print(f"{BOLD}{self.title}{RESET}  {self.target}", flush=True)
            return
        sys.stdout.write(HIDE_CURSOR)
        sys.stdout.flush()
        self._thread = threading.Thread(target=self._render_loop, daemon=True)
        self._thread.start()

    def stop(self, ok: bool = True):
        if self._is_tty:
            self._stop.set()
            if self._thread:
                self._thread.join(timeout=1.0)
            with self._lock:
                self._render(final=True)
            sys.stdout.write(SHOW_CURSOR)
            sys.stdout.flush()
        else:
            elapsed = self._fmt_elapsed(time.time() - self._start_ts)
            status = "DONE" if ok else "FAILED"
            print(f"{BOLD}{self.title} {status}{RESET}  {self.target}  elapsed {elapsed}", flush=True)

    # ── phase events ─────────────────────────────────────────────────────────

    def phase_start(self, key: str, note: str = ""):
        with self._lock:
            p = self._phases.get(key)
            if not p:
                return
            p.state = "running"
            p.note = note
            p.started_at = time.time()
        self._emit_plain(f"{CYAN}[*]{RESET} {p.label}")

    def phase_update(self, key: str, note: str):
        with self._lock:
            p = self._phases.get(key)
            if not p:
                return
            p.note = note
            if p.state == "pending":
                p.state = "running"
                p.started_at = time.time()

    def phase_done(self, key: str, note: str = "", elapsed: Optional[str] = None):
        with self._lock:
            p = self._phases.get(key)
            if not p:
                return
            if elapsed is None and p.started_at:
                elapsed = self._fmt_elapsed(time.time() - p.started_at)
            p.state = "done"
            p.note = note or p.note
            p.elapsed = elapsed or ""
        self._emit_plain(f"  {GREEN}[✓]{RESET} {p.label}  {p.note}  {p.elapsed}")

    def phase_skip(self, key: str, reason: str = ""):
        with self._lock:
            p = self._phases.get(key)
            if not p:
                return
            p.state = "skipped"
            p.note = reason
        self._emit_plain(f"  {DIM}[—] {p.label}  {reason}{RESET}")

    def phase_fail(self, key: str, reason: str = ""):
        with self._lock:
            p = self._phases.get(key)
            if p:
                p.state = "failed"
                p.note = reason
                if p.started_at:
                    p.elapsed = self._fmt_elapsed(time.time() - p.started_at)
            self._failed = True
        self._emit_plain(f"  {RED}[✗]{RESET} {p.label}  {reason}")

    def latest(self, line: str):
        with self._lock:
            self._latest = line.strip()

    # ── rendering ────────────────────────────────────────────────────────────

    def _render_loop(self):
        interval = 1.0 / max(1.0, self.refresh_hz)
        while not self._stop.is_set():
            with self._lock:
                self._spinner_idx = (self._spinner_idx + 1) % len(SPINNER_FRAMES)
                self._render()
            time.sleep(interval)

    def _render(self, final: bool = False):
        # Move cursor back up to overwrite the previous frame.
        out = []
        if self._rendered_lines:
            out.append(CURSOR_UP(self._rendered_lines))
            out.append(CURSOR_COL1)

        w = self.width
        inner = w - 2  # account for two corner chars

        elapsed = self._fmt_elapsed(time.time() - self._start_ts)
        header = f"  {BOLD}{self.title}{RESET}  {self.target}"
        right = f"elapsed {elapsed}  "
        header_padded = self._pad_to(header, inner - self._visible_len(right)) + right

        spinner = SPINNER_FRAMES[self._spinner_idx]
        lines = []
        lines.append("╔" + "═" * (w - 2) + "╗")
        lines.append("║" + header_padded + "║")
        lines.append("╠" + "═" * (w - 2) + "╣")

        for key in self._phase_order:
            p = self._phases[key]
            if p.state == "done":
                mark = f"{GREEN}[✓]{RESET}"
            elif p.state == "running":
                mark = f"{CYAN}[{spinner}]{RESET}"
            elif p.state == "failed":
                mark = f"{RED}[✗]{RESET}"
            elif p.state == "skipped":
                mark = f"{DIM}[—]{RESET}"
            else:
                mark = f"{DIM}[ ]{RESET}"

            label = p.label
            note = p.note if p.state != "pending" else ""
            elapsed_col = p.elapsed if p.state == "done" else ("running" if p.state == "running" else "")
            row = f" {mark} {label:<22} {note:<22}{elapsed_col}"
            lines.append("║" + self._pad_to(row, inner) + "║")

        lines.append("╠" + "═" * (w - 2) + "╣")
        latest = self._latest or ""
        latest_disp = f" {DIM}Latest:{RESET} {latest}"
        lines.append("║" + self._pad_to(latest_disp, inner) + "║")
        lines.append("╚" + "═" * (w - 2) + "╝")

        # Clear each line before writing to avoid leftover glyphs when the new
        # content is shorter than the previous frame's content.
        for ln in lines:
            out.append(CLEAR_LINE + ln + "\n")

        sys.stdout.write("".join(out))
        sys.stdout.flush()
        self._rendered_lines = len(lines)

    # ── helpers ──────────────────────────────────────────────────────────────

    def _emit_plain(self, line: str):
        """In non-TTY mode, print a phase transition as a plain line so logs
        still tell the story when piped to a file or captured by Claude Code."""
        if not self._is_tty:
            print(line, flush=True)

    @staticmethod
    def _fmt_elapsed(seconds: float) -> str:
        if seconds < 60:
            return f"{int(seconds)}s"
        m, s = divmod(int(seconds), 60)
        if m < 60:
            return f"{m:02d}:{s:02d}"
        h, m = divmod(m, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    # Width helpers live at module level (used by both banner + dashboard).
    _visible_len = staticmethod(_visible_len)
    _pad_to = staticmethod(_pad_to)


# ── Bash log parser (tail mode) ───────────────────────────────────────────────

# Recon phases — keyed to recon_engine.sh's "Phase N: Name" log_info lines.
# Order matches the script's pipeline.
RECON_PHASES = [
    ("subdomain_enum", "Subdomain enum"),
    ("live_probe",     "Live host probe"),
    ("port_scan",      "Port scan"),
    ("url_collect",    "URL collection"),
    ("js_analysis",    "JS analysis"),
    ("dir_fuzz",       "Directory fuzz"),
    ("config_expose",  "Config exposure"),
    ("param_discover", "Parameter discovery"),
    ("cicd_scan",      "CI/CD scan"),
    ("nuclei",         "Nuclei sweep"),
    ("takeover",       "Takeover check"),
]

# Map "Phase N" → phase key. Phase 6.5 collapses into config_expose.
RECON_PHASE_BY_NUM = {
    "1":   "subdomain_enum",
    "2":   "live_probe",
    "3":   "port_scan",
    "4":   "url_collect",
    "5":   "js_analysis",
    "6":   "dir_fuzz",
    "6.5": "config_expose",
    "7":   "param_discover",
    "8":   "cicd_scan",
    "9":   "nuclei",
    "10":  "takeover",
}

# Vuln scanner phases.
SCAN_PHASES = [
    ("upload",  "Upload surface"),
    ("xss",     "XSS"),
    ("sqli",    "SQL injection"),
    ("ssti",    "SSTI"),
    ("cms",     "CMS / MSF"),
    ("mfa",     "MFA bypass"),
    ("saml",    "SAML / SSO"),
]

SCAN_CHECK_BY_NUM = {
    "0": "upload",
    "1": "xss",
    "2": "sqli",
    "3": "xss",  # "Check 3: XSS" header — same phase
    "4": "ssti",
    "7": "cms",
    "8": "mfa",
    "9": "saml",
}

PHASE_RE = re.compile(r"\bPhase\s+([0-9]+(?:\.[0-9]+)?)\s*:\s*(.+)$")
CHECK_RE = re.compile(r"\bCheck\s+([0-9]+)\s*:\s*(.+)$")
DONE_RE = re.compile(r"\[✓\]\s+(.+)$")
INFO_RE = re.compile(r"\[\*\]\s+(.+)$")
OK_RE = re.compile(r"\[\+\]\s+(.+)$")


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


def _summarize_done(text: str) -> str:
    """Heuristic: pull a count/short note from a 'log_done' line like
    'subfinder: 1019 subdomains' or 'Live hosts: 318'."""
    # Trim trailing ANSI and whitespace.
    text = text.strip()
    return text[:30]


class TailParser:
    """Reads bash script output line-by-line and drives a Dashboard."""

    def __init__(self, dashboard: Dashboard, phase_map: dict):
        self.db = dashboard
        self.phase_map = phase_map  # phase_num_str → phase_key
        self._current: Optional[str] = None

    def feed(self, raw: str):
        line = _strip_ansi(raw).rstrip("\n")
        if not line:
            return

        # Always pass the line through so the user sees the full script output
        # underneath the dashboard when not in TTY mode. When in TTY mode the
        # dashboard owns stdout; we just keep the latest line for the "Latest:"
        # display.
        if self.db._is_tty:
            self.db.latest(line.strip())
        else:
            print(raw, end="" if raw.endswith("\n") else "\n", flush=True)

        m = PHASE_RE.search(line) or CHECK_RE.search(line)
        if m:
            num = m.group(1)
            key = self.phase_map.get(num)
            if key:
                # If we were already in a phase, mark it done (best-effort —
                # bash scripts don't emit explicit phase-end markers).
                if self._current and self._current != key:
                    self.db.phase_done(self._current)
                self._current = key
                self.db.phase_start(key)
            return

        d = DONE_RE.search(line)
        if d and self._current:
            self.db.phase_update(self._current, note=_summarize_done(d.group(1)))
            return


# ── CLI: --tail mode ─────────────────────────────────────────────────────────

def _cli_tail(kind: str, target: str):
    if kind == "recon":
        phases = RECON_PHASES
        phase_map = RECON_PHASE_BY_NUM
        title = "RECON"
    elif kind == "scan":
        phases = SCAN_PHASES
        phase_map = SCAN_CHECK_BY_NUM
        title = "HUNT (scan)"
    else:
        print(f"Unknown --kind: {kind}", file=sys.stderr)
        sys.exit(2)

    db = Dashboard(title=title, target=target, phases=phases)
    db.start()
    parser = TailParser(db, phase_map)
    try:
        for raw in sys.stdin:
            parser.feed(raw)
        # End-of-stream: close out the last phase if still running.
        if parser._current:
            db.phase_done(parser._current)
        db.stop(ok=True)
    except KeyboardInterrupt:
        db.stop(ok=False)
        sys.exit(130)


def main():
    p = argparse.ArgumentParser(description="Live TUI dashboard for /recon and /hunt")
    p.add_argument("--tail", action="store_true",
                   help="Read bash script output from stdin and render a dashboard")
    p.add_argument("--kind", choices=["recon", "scan"], default="recon",
                   help="Which phase map to use (default: recon)")
    p.add_argument("--target", default="(unknown)",
                   help="Target label to display in the dashboard header")
    args = p.parse_args()

    if args.tail:
        _cli_tail(args.kind, args.target)
        return

    # No --tail: print usage and exit.
    p.print_help()


if __name__ == "__main__":
    main()
