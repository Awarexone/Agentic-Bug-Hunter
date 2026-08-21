#!/usr/bin/env python3
"""
SAST source audit — run Semgrep over fetched JS/source instead of manual grep.

Recon pulls down JS bundles and (sometimes) leaked source, but nothing runs a
real static analyzer against it — the skills' grep patterns are eyeballed by
hand. This wraps `semgrep` (registered `semgrep|sast`) with security-focused
rulesets and maps its output into this toolkit's severity vocabulary so findings
drop straight into the validation gate.

Command construction + result parsing/normalization are pure and unit-tested;
only `run()` shells out to semgrep.

Usage:
  tools/sast_scan.py recon/target.com/js/            # security-audit ruleset
  tools/sast_scan.py app/ --config p/xss,p/jwt
  tools/sast_scan.py app.js --json
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

# Default rulesets — Semgrep Registry packs that map cleanly to bounty classes.
DEFAULT_CONFIGS = ["p/security-audit", "p/secrets", "p/xss", "p/sql-injection", "p/command-injection"]

# Semgrep severity -> this toolkit's states (see triage-validation SKILL.md).
SEVERITY_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "INFORMATIONAL"}
# Rule-id fragments that warrant bumping a WARNING up to HIGH.
HIGH_SIGNAL = ("sql-injection", "command-injection", "ssrf", "rce", "deserial",
               "path-traversal", "hardcoded", "secret", "xxe")


@dataclass
class SastFinding:
    rule_id: str
    severity: str
    path: str
    line: int
    message: str

    @property
    def confidence(self) -> str:
        """POSSIBLE by default — SAST is signal, not proof. The validation gate
        still requires a runtime PoC before anything is reported."""
        return "POSSIBLE"


def build_cmd(path: str, configs: list[str]) -> list[str]:
    cmd = ["semgrep", "--json", "--quiet", "--disable-version-check", "--timeout", "60"]
    for c in configs:
        cmd += ["--config", c]
    cmd.append(path)
    return cmd


def _normalize_severity(rule_id: str, raw: str) -> str:
    sev = SEVERITY_MAP.get((raw or "").upper(), "MEDIUM")
    if sev == "MEDIUM" and any(sig in rule_id.lower() for sig in HIGH_SIGNAL):
        return "HIGH"
    return sev


def parse_semgrep(obj: dict) -> list[SastFinding]:
    """Pure: turn semgrep --json into normalized findings, de-duped by
    (rule, path, line) so the same rule firing repeatedly isn't noise."""
    out: list[SastFinding] = []
    seen: set[tuple[str, str, int]] = set()
    for r in obj.get("results", []):
        rule_id = r.get("check_id", "unknown")
        path = r.get("path", "")
        start = (r.get("start") or {}).get("line", 0) or 0
        key = (rule_id, path, int(start))
        if key in seen:
            continue
        seen.add(key)
        extra = r.get("extra") or {}
        msg_lines = (extra.get("message") or "").strip().splitlines()
        out.append(
            SastFinding(
                rule_id=rule_id,
                severity=_normalize_severity(rule_id, extra.get("severity", "")),
                path=path,
                line=int(start),
                message=msg_lines[0][:200] if msg_lines else "",
            )
        )
    return out


_ORDER = {"HIGH": 0, "MEDIUM": 1, "INFORMATIONAL": 2}


def summarize(findings: list[SastFinding]) -> dict:
    """Pure: counts by normalized severity, most-severe first."""
    by_sev = {"HIGH": 0, "MEDIUM": 0, "INFORMATIONAL": 0}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return {"total": len(findings), **{k.lower(): v for k, v in by_sev.items()}}


def run(path: str, configs: list[str]) -> list[SastFinding]:
    if shutil.which("semgrep") is None:
        raise FileNotFoundError("semgrep")
    proc = subprocess.run(build_cmd(path, configs), capture_output=True, text=True, timeout=3600)
    try:
        obj = json.loads(proc.stdout or "{}")
    except ValueError:
        # semgrep printed a hard error to stderr instead of JSON
        raise RuntimeError(proc.stderr.strip() or "semgrep produced no JSON output")
    return parse_semgrep(obj)


def _render(findings: list[SastFinding], as_json: bool) -> str:
    summary = summarize(findings)
    if as_json:
        return json.dumps(
            {"summary": summary,
             "findings": [{**asdict(f), "confidence": f.confidence} for f in findings]},
            indent=2,
        )
    lines = [
        f"[*] semgrep: {summary['total']} finding(s) — "
        f"{summary['high']} HIGH, {summary['medium']} MEDIUM, {summary['informational']} INFO",
    ]
    for f in sorted(findings, key=lambda x: (_ORDER.get(x.severity, 9), x.path, x.line)):
        lines.append(f"    [{f.severity}] {f.path}:{f.line}  {f.rule_id}")
        if f.message:
            lines.append(f"            {f.message}")
    if summary["total"]:
        lines.append("")
        lines.append("[!] All flagged POSSIBLE — confirm with a runtime PoC before reporting.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="SAST source audit via semgrep.")
    ap.add_argument("path", help="file or directory of source/JS to scan")
    ap.add_argument("--config", help="comma-separated semgrep configs (default: security packs)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args(argv)

    if not Path(args.path).exists():
        print(f"[-] path not found: {args.path}", file=sys.stderr)
        return 2

    configs = [c.strip() for c in args.config.split(",")] if args.config else DEFAULT_CONFIGS
    try:
        findings = run(args.path, configs)
    except FileNotFoundError:
        print("[-] semgrep is not installed.  brew install semgrep  (or pipx install semgrep)",
              file=sys.stderr)
        return 127
    except subprocess.TimeoutExpired:
        print("[-] semgrep timed out (60m).", file=sys.stderr)
        return 124
    except RuntimeError as e:
        print(f"[-] semgrep error: {e}", file=sys.stderr)
        return 1

    print(_render(findings, args.json))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
