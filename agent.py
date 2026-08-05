#!/usr/bin/env python3
"""
agent.py — LangGraph-style ReAct hunting agent for bug bounty automation.

Architecture
────────────
Primary:  Real LangGraph + langchain-ollama  (pip install langgraph langchain-ollama)
Fallback: Built-in ReAct loop using Ollama native tool calling  (works out of the box)

Both paths expose identical tools and persistent memory — the difference is
that the real LangGraph backend handles interrupts, checkpoints, and parallel
subgraphs correctly.

ReAct loop:
    Observe (state) → Think (LLM) → Act (tool) → Observe (result) → loop
    ↳ LLM picks next tool based on ALL prior findings, not a priority table
    ↳ Working memory is compressed every 5 steps to stay within context window
    ↳ Full finding history persists to JSON session — survives crashes/restarts

Memory layers
─────────────
  working_memory  : LLM-maintained running notes (updated after each step)
  findings_log    : [{tool, severity, summary, timestamp}, ...]
  observation_buf : last 5 raw tool outputs (sliding window, avoids bloat)
  session_file    : everything above persisted to disk (JSON)

Usage
─────
  python3 agent.py --target example.com
  python3 agent.py --target example.com --cookie "JSESSIONID=abc" --time 4
  python3 agent.py --target example.com --scope-lock --no-brain
  python3 agent.py --target example.com --langgraph          # force LangGraph

Session state lives at recon/<domain>/agent_session.json — one persistent
session per domain (matches the rest of the repo's domain-keyed layout, e.g.
recon/<domain>/, findings/<domain>/, hunt-memory/targets/<domain>.json).
Re-running against the same domain automatically picks up where it left off.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any

# ── LangGraph optional import ──────────────────────────────────────────────────
try:
    from langgraph.graph import StateGraph, END
    from langgraph.graph.message import add_messages
    from langgraph.prebuilt import ToolNode, tools_condition
    from langchain_core.messages import HumanMessage, SystemMessage, AIMessage, ToolMessage
    from langchain_core.tools import tool as lc_tool
    try:
        from langchain_ollama import ChatOllama
        _LANGGRAPH_OK = True
    except ImportError:
        from langchain_community.chat_models import ChatOllama
        _LANGGRAPH_OK = True
except ImportError:
    _LANGGRAPH_OK = False
    StateGraph = END = None
    add_messages = None

# ── Ollama native tool calling (fallback / always available) ───────────────────
try:
    import ollama as _ollama_lib
    _OLLAMA_OK = True
except ImportError:
    _ollama_lib = None
    _OLLAMA_OK = False

# ── hunt.py lazy imports (avoids running main()) ───────────────────────────────
_hunt = None
def _h():
    """Lazy-load tools/hunt.py once. Needs the repo root on sys.path first (see
    brain.py import below) so hunt.py's own `from tools.auth_session import ...`
    resolves."""
    global _hunt
    if _hunt is None:
        import importlib.util, sys as _sys
        _here = os.path.dirname(os.path.abspath(__file__))
        spec = importlib.util.spec_from_file_location("hunt", os.path.join(_here, "tools", "hunt.py"))
        _hunt = importlib.util.module_from_spec(spec)
        _sys.modules.setdefault("hunt", _hunt)
        spec.loader.exec_module(_hunt)
    return _hunt


def _recon_dir_for(domain: str) -> str:
    """recon/<domain>/ — tools/hunt.py's flat, domain-keyed layout (no session concept)."""
    return os.path.join(_h().RECON_DIR, domain)


def _findings_dir_for(domain: str) -> str:
    """findings/<domain>/ — same flat layout."""
    return os.path.join(_h().FINDINGS_DIR, domain)


def _append_journal_entry(memory_dir: str, entry: dict) -> None:
    """Append a pre-validated journal entry to hunt-memory/journal.jsonl.

    Same locked-append primitive FailedPatternDB/ChainDB/ReportOutcomeDB use in
    memory/vuln_intelligence.py, inlined here since no JournalDB class exists —
    journal.jsonl writes have always lived at the Claude-Code-agent layer
    (via /remember); this is the first Python-side writer.
    """
    import fcntl

    from memory.rotation import DEFAULT_KEEP, DEFAULT_MAX_BYTES, rotate_if_needed

    path = Path(memory_dir) / "journal.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, separators=(",", ":")) + "\n"
    encoded = line.encode("utf-8")

    rotate_if_needed(path, max_bytes=DEFAULT_MAX_BYTES, keep=DEFAULT_KEEP)

    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            os.write(fd, encoded)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)

# ── brain.py import ───────────────────────────────────────────────────────────
try:
    _here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, _here)
    from brain import Brain, BRAIN_SYSTEM, MODEL_PRIORITY, OLLAMA_HOST, _pick_model
    _BRAIN_OK = True
except Exception as _brain_err:
    _BRAIN_OK = False
    BRAIN_SYSTEM = ""
    MODEL_PRIORITY = ["qwen3:8b"]
    OLLAMA_HOST = "http://localhost:11434"

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN   = "\033[0;32m"
CYAN    = "\033[0;36m"
YELLOW  = "\033[1;33m"
RED     = "\033[0;31m"
MAGENTA = "\033[0;35m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
NC      = "\033[0m"

MAX_OBS_CHARS    = 3000    # truncate tool output kept in observation buffer
MAX_CTX_CHARS    = 18000   # max chars sent to LLM per step
MAX_FINDINGS_LOG = 200     # cap stored findings
MEMORY_REFRESH_N = 5       # compress working_memory every N steps


# ──────────────────────────────────────────────────────────────────────────────
#  Tool definitions  (JSON Schema — compatible with Ollama native tool calling)
# ──────────────────────────────────────────────────────────────────────────────

TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "run_recon",
            "description": (
                "Run full subdomain enumeration + live host discovery on the target domain. "
                "This MUST be the first step if recon data does not exist. "
                "Returns: number of live hosts found, key tech stacks detected."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "scope_lock": {
                        "type": "boolean",
                        "description": "If true, skip subdomain enum and only probe the exact target given.",
                        "default": False,
                    },
                    "quick": {
                        "type": "boolean",
                        "description": "If true, skip amass + reduce ffuf coverage for a faster pass.",
                        "default": False,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_vuln_scan",
            "description": (
                "Run the full vulnerability scanner pipeline in one pass: nuclei CVE/misconfig "
                "templates, XSS (dalfox), linear-scaling SQLi PoC verification, SSTI canary probes, "
                "race conditions, RCE upload-execution PoC, CMS detection (WordPress/Drupal) with "
                "Metasploit resource generation, CORS misconfig checks, JWT checks, and MFA/SAML "
                "checks. This is a single consolidated scan — do not look for separate "
                "CMS/RCE/SQLi/CORS/JWT tools, they don't exist as separate steps anymore."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "quick": {
                        "type": "boolean",
                        "description": "If true, run fast subset of templates only.",
                        "default": False,
                    },
                    "full": {
                        "type": "boolean",
                        "description": "If true, run all templates including slow ones.",
                        "default": False,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_secret_hunt",
            "description": (
                "Scan JS bundles collected during recon for leaked secrets — trufflehog "
                "(verifies live keys against issuer APIs), noseyparker, gitleaks, whichever is "
                "installed. Hardcoded AWS/GCP/Azure keys, API tokens, private keys. "
                "Always worth running — secrets bypass all other controls."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_param_discovery",
            "description": (
                "Brute-force hidden HTTP parameters on recon's discovered URLs using Arjun "
                "(falls back to x8). Use when parameterized URLs are sparse or the site returns "
                "data conditionally. Returns: new parameterized URLs added to the attack surface."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_recon_summary",
            "description": (
                "Read and summarize current recon data: live hosts, tech stack, "
                "discovered paths, parameterized URLs, CMS detections. "
                "Use to refresh your understanding before deciding next action."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_findings_summary",
            "description": (
                "Read and summarize all vulnerability findings discovered so far. "
                "Returns severity breakdown, top findings, and suggested exploit chains. "
                "Use before deciding to run additional tools or write the final report."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_working_memory",
            "description": (
                "Update your working notes about this target. Call this after making "
                "a significant discovery or after each tool run to keep your notes current. "
                "These notes persist across all steps and are always visible to you."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "notes": {
                        "type": "string",
                        "description": "Your updated notes about the target, findings, and next priorities.",
                    }
                },
                "required": ["notes"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": (
                "Signal that the hunt is complete. Call this when: all high-priority tools "
                "have run, time budget is close to exhausted, or no further tools would "
                "add new findings. Provide a brief verdict."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "verdict": {
                        "type": "string",
                        "description": "Brief summary: what was found, what's worth reporting.",
                    }
                },
                "required": ["verdict"],
            },
        },
    },
]

TOOL_NAMES = {t["function"]["name"] for t in TOOLS}


# ──────────────────────────────────────────────────────────────────────────────
#  Memory
# ──────────────────────────────────────────────────────────────────────────────

class HuntMemory:
    """
    Three-layer memory:
      1. working_memory   — LLM's rolling notes (updated by update_working_memory tool)
      2. findings_log     — structured list of all discoveries [{tool, severity, text, ts}]
      3. observation_buf  — last N raw tool outputs, used to build LLM context
    All layers are persisted to a JSON session file.
    """

    def __init__(self, session_file: str):
        self.session_file    = session_file
        self.working_memory  = ""
        self.findings_log:   list[dict] = []
        self.observation_buf: list[dict] = []   # {tool, ts, text}
        self.completed_steps: list[str]  = []
        self.step_count      = 0
        self._load()

    def _load(self) -> None:
        if os.path.isfile(self.session_file):
            try:
                data = json.loads(Path(self.session_file).read_text())
                self.working_memory   = data.get("working_memory", "")
                self.findings_log     = data.get("findings_log", [])
                self.observation_buf  = data.get("observation_buf", [])[-10:]
                self.completed_steps  = data.get("completed_steps", [])
                self.step_count       = data.get("step_count", 0)
            except Exception:
                pass

    def save(self) -> None:
        Path(self.session_file).parent.mkdir(parents=True, exist_ok=True)
        data = {
            "working_memory":  self.working_memory,
            "findings_log":    self.findings_log[-MAX_FINDINGS_LOG:],
            "observation_buf": self.observation_buf[-10:],
            "completed_steps": self.completed_steps,
            "step_count":      self.step_count,
            "saved_at":        datetime.now().isoformat(),
        }
        Path(self.session_file).write_text(json.dumps(data, indent=2))

    def add_observation(self, tool: str, text: str) -> None:
        """Record a tool output to the sliding observation window."""
        entry = {
            "tool": tool,
            "ts":   datetime.now().isoformat(),
            "text": text[:MAX_OBS_CHARS],
        }
        self.observation_buf.append(entry)
        if len(self.observation_buf) > 15:
            self.observation_buf = self.observation_buf[-10:]

    def add_finding(self, tool: str, severity: str, text: str, confirmed: bool = False) -> None:
        self.findings_log.append({
            "tool":      tool,
            "severity":  severity,
            "text":      text[:500],
            "confirmed": confirmed,  # PoC-verified via vuln_scanner.sh's own [CONFIRMED] tag
            "ts":        datetime.now().isoformat(),
        })

    def findings_summary(self) -> str:
        """Compact summary of all findings for LLM context."""
        if not self.findings_log:
            return "No findings yet."
        by_sev: dict[str, list[str]] = {}
        for f in self.findings_log[-50:]:
            by_sev.setdefault(f["severity"].upper(), []).append(f"{f['tool']}: {f['text'][:120]}")
        lines = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if sev in by_sev:
                lines.append(f"[{sev}] ({len(by_sev[sev])} items)")
                lines.extend(f"  • {x}" for x in by_sev[sev][:5])
        return "\n".join(lines) or "No classified findings."

    def recent_observations(self, n: int = 3) -> str:
        """Last n tool outputs formatted for LLM context."""
        recents = self.observation_buf[-n:]
        if not recents:
            return "No tool outputs yet."
        parts = []
        for obs in recents:
            parts.append(f"[{obs['tool']}]\n{obs['text']}")
        return "\n\n".join(parts)


# ──────────────────────────────────────────────────────────────────────────────
#  Tool dispatcher  (maps tool names → hunt.py functions)
# ──────────────────────────────────────────────────────────────────────────────

class ToolDispatcher:
    """Execute tool calls and return plain-text observations."""

    def __init__(self, domain: str, memory: HuntMemory,
                 scope_lock: bool = False,
                 default_cookies: str = ""):
        self.domain          = domain
        self.memory          = memory
        self.scope_lock      = scope_lock
        self.default_cookies = default_cookies
        self.session_start   = time.time()  # for should_stop()'s elapsed_minutes

    def _run_shell_tool(self, script_name: str, args: list[str],
                         timeout: int = 900, extra_env: dict | None = None) -> bool:
        """Run a tools/*.sh script directly — for tools that don't have a Python
        wrapper in tools/hunt.py (secrets_hunter.sh, param_discovery.sh). Mirrors
        tools/hunt.py's own subprocess pattern (used for recon_engine.sh/vuln_scanner.sh).

        args is a list of argv elements (e.g. domain-derived paths under
        recon/<domain>/ or findings/<domain>/) — never a pre-formatted shell
        string. self.domain is attacker/user-influenced, and recon_dir/out_dir
        are built from it via os.path.join with no shell-metacharacter
        screening, so this must never reach a shell that re-parses them."""
        h = _h()
        script = os.path.join(h.BASE_DIR, "tools", script_name)
        if not os.path.isfile(script):
            return False
        child_env = os.environ.copy()
        if extra_env:
            child_env.update(extra_env)
        proc = None
        try:
            proc = subprocess.Popen(
                ["bash", script, *args],
                cwd=h.BASE_DIR, env=child_env,
            )
            proc.wait(timeout=timeout)
            return proc.returncode == 0
        except subprocess.TimeoutExpired:
            if proc:
                proc.kill()
            return False

    # ── Memory-informed priority (Phase B: replaces the old static prose) ──

    _TECH_TOKEN_RE = re.compile(r"\[([a-zA-Z][a-zA-Z0-9_.\-]{1,30})\]")

    def _detect_tech_stack(self) -> list[str]:
        """Best-effort tech extraction from recon's httpx tech-detect output.

        Heuristic, same spirit as _summarize_recon's own tech-detection guess —
        an empty/partial result degrades priority_briefing() to its documented
        'no memory data yet' state rather than crashing, so precision here
        matters less than not blocking on it.
        """
        recon_dir = _recon_dir_for(self.domain)
        techs: set[str] = set()
        for fn in ("live/httpx_full.txt", "httpx_full.txt", "tech_priority.txt", "tech.txt"):
            fp = os.path.join(recon_dir, fn)
            if not os.path.isfile(fp):
                continue
            try:
                with open(fp, errors="replace") as f:
                    for line in f:
                        for token in self._TECH_TOKEN_RE.findall(line):
                            if not token.isdigit():
                                techs.add(token.lower())
            except OSError:
                pass
            if techs:
                break
        return sorted(techs)

    # Maps vuln_scanner.sh's own FINDINGS_DIR subcategories (it always
    # mkdir -p's all of them, so "empty vs has content" is a real success/fail
    # signal) to the vuln_class names used elsewhere in this codebase.
    _VULN_SCAN_SUBDIRS = {
        "upload": "file-upload", "xss": "xss", "sqli": "sqli", "takeover": "misconfig",
        "misconfig": "misconfig", "exposure": "info-disclosure", "ssrf": "ssrf",
        "cves": "misconfig", "redirects": "open-redirect", "idor": "idor",
        "auth_bypass": "auth-bypass", "lfi": "lfi", "ssti": "ssti", "graphql": "graphql",
        "cors": "cors", "jwt": "auth-bypass", "smuggling": "misconfig", "cloud": "misconfig",
    }
    # secrets_hunter.sh writes to its own --out dir (see run_secret_hunt dispatch),
    # not one of vuln_scanner.sh's subdirs, so it gets its own small map.
    _SECRET_HUNT_SUBDIRS = {"secrets": "info-disclosure"}

    def _log_experiments_from_findings(self, tool_name: str, subdir_map: dict[str, str]) -> None:
        """After a real test tool completes, log one experiments.jsonl entry per
        relevant findings subcategory (content = success, still-empty = fail) —
        the granular per-attempt signal should_stop()/payload_category_affinity()
        need, which this loop never wrote before (findings_log only ever had
        whole-tool-run text summaries, nothing structured). Best-effort."""
        try:
            from memory.experiment_memory import ExperimentDB
            from memory.schemas import make_experiment_entry
        except ImportError:
            return

        findings_dir = _findings_dir_for(self.domain)
        if not os.path.isdir(findings_dir):
            return

        tech_stack = self._detect_tech_stack()
        h = _h()
        db = ExperimentDB(os.path.join(h.BASE_DIR, "hunt-memory", "experiments.jsonl"))
        endpoint = f"https://{self.domain}/"

        for subdir, vuln_class in subdir_map.items():
            d = os.path.join(findings_dir, subdir)
            if not os.path.isdir(d):
                continue
            has_content = any(
                os.path.isfile(os.path.join(d, fn)) and os.path.getsize(os.path.join(d, fn)) > 0
                for fn in os.listdir(d)
            )
            try:
                entry = make_experiment_entry(
                    target=self.domain, endpoint=endpoint, vuln_class=vuln_class,
                    payload_category=f"vuln_scan_{subdir}",
                    result="success" if has_content else "fail",
                    technique=tool_name, tech_stack=tech_stack or None,
                )
                db.save(entry)
            except Exception:
                pass

    def _experiment_signal(self, tech_stack: list[str]) -> str:
        """should_stop() + payload_category_affinity() folded into one line for
        priority_briefing() — grounds the loop's stop/pivot instinct in an actual
        count instead of only the time/step budget."""
        try:
            from memory.experiment_memory import ExperimentDB, payload_category_affinity, should_stop
        except ImportError:
            return ""

        h = _h()
        db = ExperimentDB(os.path.join(h.BASE_DIR, "hunt-memory", "experiments.jsonl"))
        endpoint = f"https://{self.domain}/"
        experiments = db.for_endpoint(self.domain, endpoint)
        if not experiments:
            return ""

        elapsed_min = round((time.time() - self.session_start) / 60, 1)
        stop = should_stop(experiments, elapsed_min)
        lines = [f"Experiment memory: {stop['reason']}"]

        if tech_stack:
            top = payload_category_affinity(tech_stack, experiments, top=3)
            for p in top:
                if p["successes"]:
                    lines.append(
                        f"  {p['payload_category']} ({p['vuln_class']}): "
                        f"{p['successes']}W/{p['failures']}L on this stack before"
                    )
        return "\n".join(lines)

    def priority_briefing(self) -> str:
        """Live tech->vuln affinity + EV/hour ranking from hunt-memory/, the
        same memory-driven signal recon-ranker/priority_score give the
        Claude-Code-native agents — this loop gets it too instead of a
        hardcoded 'CMS > RCE > SQLi' guess that never learns anything."""
        try:
            from memory.pattern_db import PatternDB
            from memory.vuln_intelligence import (
                ChainDB, FailedPatternDB, ReportOutcomeDB,
                expected_value_per_hour, format_decision, tech_vuln_affinity,
            )
        except ImportError as e:
            return f"(memory.vuln_intelligence not importable — {e})"

        tech_stack = self._detect_tech_stack()
        if not tech_stack:
            return "(no tech stack detected yet — run run_recon first for a memory-informed ranking)"

        h = _h()
        memory_dir = os.path.join(h.BASE_DIR, "hunt-memory")
        patterns = PatternDB(os.path.join(memory_dir, "patterns.jsonl")).read_all()
        failed   = FailedPatternDB(os.path.join(memory_dir, "failed_patterns.jsonl")).read_all()
        chains   = ChainDB(os.path.join(memory_dir, "chains.jsonl")).read_all()
        outcomes = ReportOutcomeDB(os.path.join(memory_dir, "report_outcomes.jsonl")).read_all()

        affinity = tech_vuln_affinity(tech_stack, patterns, failed, top=6)
        if not affinity:
            base = f"(tech stack {tech_stack} — no prior hunt-memory data for this combination yet)"
            signal = self._experiment_signal(tech_stack)
            return f"{base}\n{signal}" if signal else base

        lines = [f"Tech stack detected: {', '.join(tech_stack)}"]
        top_ev = None
        top_affinity = None
        for a in affinity:
            ev = expected_value_per_hour(
                a["vuln_class"], tech_stack, self.domain,
                patterns=patterns, failed_patterns=failed, chains=chains, report_outcomes=outcomes,
            )
            if top_ev is None:
                top_ev, top_affinity = ev, a  # affinity is net_score-sorted -- first is the top candidate
            recal = ev["impact_recalibration"]
            recal_note = (
                f", impact recalibrated {recal['static_prior']}->{recal['impact']} "
                f"(n={recal['sample_size']} report outcomes)"
                if recal["recalibrated"] else ""
            )
            lines.append(
                f"  {a['vuln_class']}: {a['wins']}W/{a['losses']}L (confidence {a['confidence']}) "
                f"— EV/hr {ev['ev_per_hour']} [{ev['ev_label']}]{recal_note}"
            )
        signal = self._experiment_signal(tech_stack)
        if signal:
            lines.append("")
            lines.append(signal)

        if top_ev and not top_ev["hard_kill"]:
            lines.append("")
            lines.append("--- Top Recommendation ---")
            lines.append(format_decision(
                top_ev, f"https://{self.domain}/",
                f"Run run_vuln_scan and check the {top_affinity['vuln_class']} findings subdirectory",
                affinity=top_affinity,
            ))
        return "\n".join(lines)

    # ── Duplicate/noise gate on finish (Phase B2) ───────────────────────────

    _VULN_CLASS_KEYWORDS: list[tuple[str, str]] = [
        ("sql injection", "sqli"), ("sqli", "sqli"), ("injectable", "sqli"),
        ("rce", "rce"), ("code execution", "rce"),
        ("ssti", "ssti"), ("open redirect", "open-redirect"),
        ("cors", "cors"), ("cross-origin", "cors"),
        ("jwt", "auth-bypass"), ("default cred", "auth-bypass"),
        ("idor", "idor"),
        ("secret", "info-disclosure"), ("exposed", "info-disclosure"), ("api key", "info-disclosure"),
        ("takeover", "misconfig"), ("misconfig", "misconfig"), ("wordpress", "misconfig"), ("drupal", "misconfig"),
    ]

    @classmethod
    def _guess_vuln_class(cls, text: str) -> str | None:
        """Keyword-based vuln_class guess from a findings_log entry's free text —
        same style as _classify_obs's own keyword-based severity guess. This loop's
        findings aren't structured with an explicit vuln_class, so this is the only
        honest way to query duplicate_or_noise_check with what's actually available."""
        t = text.lower()
        for kw, vuln_class in cls._VULN_CLASS_KEYWORDS:
            if kw in t:
                return vuln_class
        return None

    def check_finish_for_duplicates(self) -> dict:
        """Before accepting `finish`, check whether every HIGH/CRITICAL finding this
        session already has a report_outcomes.jsonl entry for this target+vuln_class —
        i.e. the LLM may be about to declare victory on findings that were already
        submitted in a prior session, not anything new.

        Endpoint-level matching isn't possible here (findings_log has no endpoint,
        only tool/severity/text) so this checks at (target, vuln_class) granularity —
        duplicate_or_noise_check's report_outcomes match doesn't require an endpoint,
        only its journal/failed_pattern matches do, so this is still a real signal,
        just coarser than the per-endpoint check validation-engine does.
        """
        notable = [f for f in self.memory.findings_log if f.get("severity") in ("HIGH", "CRITICAL")]
        if not notable:
            return {"blocked": False, "reason": "no HIGH/CRITICAL findings to check"}

        try:
            from memory.vuln_intelligence import (
                ReportOutcomeDB, FailedPatternDB, duplicate_or_noise_check, _read_jsonl_best_effort,
            )
        except ImportError:
            return {"blocked": False, "reason": "memory.vuln_intelligence not importable"}

        h = _h()
        memory_dir = os.path.join(h.BASE_DIR, "hunt-memory")
        outcomes = ReportOutcomeDB(os.path.join(memory_dir, "report_outcomes.jsonl")).read_all()
        failed   = FailedPatternDB(os.path.join(memory_dir, "failed_patterns.jsonl")).read_all()
        journal  = _read_jsonl_best_effort(Path(os.path.join(memory_dir, "journal.jsonl")))

        checked, all_duplicate = 0, True
        for f in notable:
            vuln_class = self._guess_vuln_class(f.get("text", ""))
            if not vuln_class:
                continue
            checked += 1
            result = duplicate_or_noise_check(
                self.domain, vuln_class, "",
                journal_entries=journal, report_outcomes=outcomes, failed_patterns=failed,
            )
            if not result["is_duplicate"]:
                all_duplicate = False

        if checked == 0:
            return {"blocked": False, "reason": "no findings text matched a known vuln-class keyword"}
        if all_duplicate:
            return {
                "blocked": True,
                "reason": (
                    f"All {checked} HIGH/CRITICAL finding(s) this session match a vuln_class already "
                    f"in report_outcomes.jsonl for {self.domain} — likely re-confirming a prior "
                    f"submission, not a new finding. Verify before finishing."
                ),
            }
        return {"blocked": False, "reason": f"{checked} finding(s) checked, at least one is new"}

    def check_finish_for_unconfirmed(self) -> dict:
        """Before accepting `finish`, check whether every HIGH/CRITICAL finding this
        session is still unverified — only keyword-guessed, or tagged [POSSIBLE]/
        [INFORMATIONAL] rather than vuln_scanner.sh's own [CONFIRMED] PoC tag.

        This is this loop's version of validation-engine's "impact proven?" check:
        don't let it declare victory on a claim nothing actually verified. It's a
        soft gate (warn once, then allow) — a real HIGH finding without a
        [CONFIRMED] tag can still be real, it just hasn't been proven yet, and the
        loop may be out of budget to re-verify it.
        """
        notable = [f for f in self.memory.findings_log if f.get("severity") in ("HIGH", "CRITICAL")]
        if not notable:
            return {"blocked": False, "reason": "no HIGH/CRITICAL findings to check"}
        if any(f.get("confirmed") for f in notable):
            return {"blocked": False, "reason": "at least one finding carries a scanner-verified [CONFIRMED] tag"}
        return {
            "blocked": True,
            "reason": (
                f"{len(notable)} HIGH/CRITICAL finding(s) this session, none carry vuln_scanner.sh's "
                f"own [CONFIRMED] PoC-verification tag — only keyword-guessed severity or "
                f"[POSSIBLE]/manual-review signal. Re-run the relevant check or manually verify "
                f"before finishing, if time allows."
            ),
        }

    # ── Memory write-back on finish (Phase B3) ──────────────────────────────

    def _log_session_summary(self) -> None:
        """Auto-log a session-summary journal entry on finish — previously every
        standalone hunt through this loop vanished the moment the process exited,
        since HuntMemory is 100% session-scoped JSON. Reuses schemas.py's existing
        make_session_summary_entry (built for exactly this — the Claude-Code
        autopilot flow already auto-logs the same way via /remember at session end).
        Best-effort: a memory-write failure must never break the actual finish.
        """
        try:
            from memory.schemas import make_session_summary_entry
        except ImportError:
            return

        completed = list(dict.fromkeys(self.memory.completed_steps))
        vuln_classes: set[str] = set()
        for f in self.memory.findings_log:
            vc = self._guess_vuln_class(f.get("text", ""))
            if vc:
                vuln_classes.add(vc)

        try:
            entry = make_session_summary_entry(
                target=self.domain,
                action="hunt",
                endpoints_tested=completed,
                vuln_classes_tried=sorted(vuln_classes),
                findings_count=len(self.memory.findings_log),
            )
            h = _h()
            _append_journal_entry(os.path.join(h.BASE_DIR, "hunt-memory"), entry)
        except Exception as exc:
            print(f"{YELLOW}[Agent] Session-summary journal write skipped: {exc}{NC}", flush=True)

    def dispatch(self, name: str, args: dict) -> str:
        """Execute named tool and return text observation."""
        h = _h()
        domain = self.domain
        t0 = time.time()

        try:
            if name == "run_recon":
                ok = h.run_recon(
                    domain,
                    quick=bool(args.get("quick", False)),
                    scope_lock=args.get("scope_lock", self.scope_lock),
                )
                obs = self._summarize_recon(domain, ok)

            elif name == "run_vuln_scan":
                ok = h.run_vuln_scan(
                    domain,
                    quick=bool(args.get("quick", False)),
                    full=bool(args.get("full", False)),
                )
                obs = self._summarize_findings(domain, "scan", ok)
                self._log_experiments_from_findings(name, self._VULN_SCAN_SUBDIRS)

            elif name == "run_secret_hunt":
                recon_dir = _recon_dir_for(domain)
                if not os.path.isdir(recon_dir):
                    return "ERROR: no recon data yet. Run run_recon first."
                out_dir = os.path.join(_findings_dir_for(domain), "secrets")
                ok = self._run_shell_tool(
                    "secrets_hunter.sh", ["--js-bundle", recon_dir, "--out", out_dir]
                )
                obs = self._summarize_findings(domain, "secrets", ok)
                self._log_experiments_from_findings(name, self._SECRET_HUNT_SUBDIRS)

            elif name == "run_param_discovery":
                recon_dir = _recon_dir_for(domain)
                urls_file = os.path.join(recon_dir, "urls", "all.txt")
                if not os.path.isfile(urls_file):
                    return "ERROR: no crawled URLs yet (recon/<domain>/urls/all.txt missing). Run run_recon first."
                out_dir = os.path.join(_findings_dir_for(domain), "params")
                ok = self._run_shell_tool(
                    "param_discovery.sh", ["-l", urls_file],
                    extra_env={"PARAM_OUT_DIR": out_dir},
                )
                obs = self._summarize_params(domain, ok, out_dir)

            elif name == "read_recon_summary":
                obs = self._read_recon_files(domain)

            elif name == "read_findings_summary":
                obs = self._read_findings_files(domain)

            elif name == "update_working_memory":
                notes = args.get("notes", "")
                self.memory.working_memory = notes
                self.memory.save()
                return f"Working memory updated ({len(notes)} chars)."

            elif name == "finish":
                self._log_session_summary()
                return f"FINISH: {args.get('verdict', 'Hunt complete.')}"

            else:
                return f"Unknown tool: {name}"

        except Exception as exc:
            tb = traceback.format_exc()
            return f"Tool {name} raised exception: {exc}\n{tb[:500]}"

        elapsed = round(time.time() - t0, 1)
        obs_full = f"{obs}\n\n[{name} completed in {elapsed}s]"

        # Update memory
        self.memory.add_observation(name, obs_full)
        self.memory.completed_steps.append(name)
        self.memory.step_count += 1

        # Classify any critical/high findings into findings_log
        self._classify_obs(name, obs_full)
        self.memory.save()

        return obs_full

    # ── Observation formatters ──────────────────────────────────────────────

    def _summarize_recon(self, domain: str, ok: bool) -> str:
        recon_dir = _recon_dir_for(domain)
        lines = [f"run_recon: {'OK' if ok else 'PARTIAL'}"]

        # Count live hosts
        for fn in ("live/httpx_full.txt", "httpx_full.txt"):
            fp = os.path.join(recon_dir, fn)
            if os.path.isfile(fp):
                count = sum(1 for _ in open(fp) if _.strip())
                lines.append(f"Live hosts: {count}")
                break

        # Count resolved subdomains
        for fn in ("resolved.txt", "all.txt"):
            fp = os.path.join(recon_dir, fn)
            if os.path.isfile(fp):
                count = sum(1 for _ in open(fp) if _.strip())
                lines.append(f"Subdomains: {count}")
                break

        # Tech detections
        for fn in ("tech_priority.txt", "tech.txt"):
            fp = os.path.join(recon_dir, fn)
            if os.path.isfile(fp):
                techs = [l.strip() for l in open(fp) if l.strip()][:10]
                lines.append(f"Tech detected: {', '.join(techs)}")
                break

        # Parameterized URLs
        for fn in ("urls/with_params.txt", "params/with_params.txt"):
            fp = os.path.join(recon_dir, fn)
            if os.path.isfile(fp):
                count = sum(1 for _ in open(fp) if _.strip())
                lines.append(f"Parameterized URLs: {count}")
                break

        return "\n".join(lines)

    def _summarize_findings(self, domain: str, label: str, ok: bool) -> str:
        findings_dir = _findings_dir_for(domain)
        lines = [f"{label}: {'OK' if ok else 'ran (check manually)'}"]

        # Walk findings dir for any .txt with content
        if findings_dir and os.path.isdir(findings_dir):
            for root, _, files in os.walk(findings_dir):
                for fn in files:
                    if not fn.endswith(".txt"):
                        continue
                    fp = os.path.join(root, fn)
                    try:
                        content = Path(fp).read_text(errors="replace")
                        if any(kw in content.lower() for kw in
                               ("critical", "high", "vulnerable", "injectable",
                                "rce", "sqli", "open redirect", "exposed", "default cred")):
                            head = content[:400].replace("\n", " ")
                            lines.append(f"  [{fn}] {head}")
                    except Exception:
                        pass

        if len(lines) == 1:
            lines.append("  No HIGH/CRITICAL findings in artifacts (check logs above for details).")
        return "\n".join(lines[:20])

    def _summarize_params(self, domain: str, ok: bool, out_dir: str) -> str:
        lines = [f"run_param_discovery: {'OK' if ok else 'partial'}"]
        for fn in ("arjun_summary.txt", "arjun.json", "x8.txt"):
            fp = os.path.join(out_dir, fn)
            if os.path.isfile(fp):
                count = sum(1 for _ in open(fp) if _.strip())
                lines.append(f"  {fn}: {count} lines")
        if len(lines) == 1:
            lines.append(f"  No output files found under {out_dir} — check arjun/x8 are installed (tools/arsenal.md).")
        return "\n".join(lines)

    def _read_recon_files(self, domain: str) -> str:
        recon_dir = _recon_dir_for(domain)
        parts = []

        for label, fn in [
            ("Live hosts (sample)",    "httpx_full.txt"),
            ("Tech priority",          "tech_priority.txt"),
            ("Parameterized URLs",     "urls/with_params.txt"),
            ("All URLs (sample)",      "urls/all.txt"),
        ]:
            fp = os.path.join(recon_dir, fn)
            if os.path.isfile(fp):
                lines = [l.strip() for l in open(fp) if l.strip()]
                count = len(lines)
                sample = lines[:20]
                parts.append(f"=== {label} ({count} total) ===\n" + "\n".join(sample))

        return "\n\n".join(parts) if parts else "No recon data found. Run run_recon first."

    def _read_findings_files(self, domain: str) -> str:
        findings_dir = _findings_dir_for(domain)
        if not findings_dir or not os.path.isdir(findings_dir):
            return "No findings directory. Run vulnerability scans first."

        parts = []
        for root, _, files in os.walk(findings_dir):
            for fn in sorted(files):
                if not fn.endswith((".txt", ".json")):
                    continue
                fp = os.path.join(root, fn)
                try:
                    content = Path(fp).read_text(errors="replace")
                    if content.strip():
                        rel = os.path.relpath(fp, findings_dir)
                        parts.append(f"=== {rel} ===\n{content[:800]}")
                except Exception:
                    pass

        if not parts:
            return "Findings directory exists but is empty."
        combined = "\n\n".join(parts)
        # Truncate to avoid blowing context
        if len(combined) > MAX_CTX_CHARS:
            combined = combined[:MAX_CTX_CHARS] + "\n...[truncated]"
        return combined

    @staticmethod
    def _keyword_severity(text_lower: str) -> str | None:
        """Weak-signal severity guess from free text — the only option when no
        scanner tag is present. Severity (how bad, if real) is deliberately kept
        separate from `confirmed` (do we have proof) — see _classify_obs."""
        if any(kw in text_lower for kw in ("rce_confirmed", "injectable", "critical")):
            return "CRITICAL"
        if any(kw in text_lower for kw in ("high", "sql injection", "sqli", "rce", "default cred")):
            return "HIGH"
        if any(kw in text_lower for kw in ("medium", "exposed", "open redirect", "cors")):
            return "MEDIUM"
        if any(kw in text_lower for kw in ("low", "info")):
            return "LOW"
        return None

    def _classify_obs(self, tool: str, obs: str) -> None:
        """Extract a severity label from observation text and add to findings_log.

        Prefers vuln_scanner.sh's own [CONFIRMED]/[POSSIBLE] tags (see
        verify_sqli_poc/verify_rce_poc/SSTI-CONFIRMED/SAML-SIG-STRIP in
        tools/vuln_scanner.sh — real PoC verification, not a guess) over keyword
        matching, which this loop used to rely on for everything, discarding the
        verification work the scanner already did every time.

        [CONFIRMED] is ground truth: severity=CRITICAL, confirmed=True, no
        further judgment needed. [POSSIBLE] means "real signal, not yet proven" —
        severity still comes from that line's own content (a SQLI-CANDIDATE is
        still potentially HIGH, just unconfirmed), only `confirmed` stays False.
        Untagged output (or [INFORMATIONAL], which reads as LOW via the normal
        keyword pass since the tag text itself contains "info") falls back to
        the old whole-observation keyword guess — the weakest signal, never
        confirmed.
        """
        lines = obs.splitlines()

        for ln in lines:
            if "[CONFIRMED]" in ln:
                text = ln.strip()[:300]
                hint = self._chain_signal_for_finding(text)
                if hint:
                    text = f"{text} | {hint}"
                self.memory.add_finding(tool, "CRITICAL", text, confirmed=True)
                return

        for ln in lines:
            if "[POSSIBLE]" in ln:
                sev = self._keyword_severity(ln.lower()) or "MEDIUM"
                text = ln.strip()[:300]
                if sev in ("HIGH", "CRITICAL"):
                    hint = self._chain_signal_for_finding(text)
                    if hint:
                        text = f"{text} | {hint}"
                self.memory.add_finding(tool, sev, text, confirmed=False)
                return

        sev = self._keyword_severity(obs.lower())
        if not sev:
            return  # not a finding, skip

        for ln in lines:
            if any(kw in ln.lower() for kw in
                   ("critical", "high", "injectable", "rce", "exposed", "found", "medium", "sql")):
                text = ln.strip()[:300]
                if sev in ("HIGH", "CRITICAL"):
                    hint = self._chain_signal_for_finding(text)
                    if hint:
                        text = f"{text} | {hint}"
                self.memory.add_finding(tool, sev, text, confirmed=False)
                break

    def _chain_signal_for_finding(self, finding_text: str) -> str | None:
        """When a HIGH/CRITICAL finding lands, check chains.jsonl for a confirmed
        A->B(->C) shape already proven on this tech stack — the 'found A, now
        check for B' step chain-builder.md does for Claude-Code sessions, ported
        here since this loop has no way to invoke that agent directly. This is
        context, not an assertion the current finding IS part of the chain —
        worded that way in the output."""
        try:
            from memory.vuln_intelligence import ChainDB
        except ImportError:
            return None

        vuln_class = self._guess_vuln_class(finding_text)
        tech_stack = self._detect_tech_stack()
        if not tech_stack:
            return None

        h = _h()
        chains = ChainDB(os.path.join(h.BASE_DIR, "hunt-memory", "chains.jsonl")).match(tech_stack)
        if not chains:
            return None

        # Prefer a chain whose steps actually mention this vuln class; fall back
        # to the highest-payout chain for this tech stack as general context.
        relevant = chains
        if vuln_class:
            keyword_matches = [c for c in chains if vuln_class in " ".join(c.get("steps", [])).lower()]
            if keyword_matches:
                relevant = keyword_matches

        top = relevant[0]
        steps = " -> ".join(top.get("steps", []))
        payout = f", ${top['payout']} elsewhere" if top.get("payout") else ""
        return (f"CHAIN CONTEXT: confirmed chain '{top.get('chain_name')}' exists for this tech "
                f"stack ({steps}{payout}) — worth checking whether this finding extends into it")


# ──────────────────────────────────────────────────────────────────────────────
#  Core ReAct agent  (Ollama native tool calling)
# ──────────────────────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────────────────────
#  Loop Detector  (ctf-agent technique: signature hashing, sliding window 12)
# ──────────────────────────────────────────────────────────────────────────────

class LoopDetector:
    """
    Detects when the agent is repeating the same tool call in a loop.
    Sliding window of last 12 tool signatures.
    Warn at 3 repetitions, force direction change at 5.
    Signature = tool_name + first 300 chars of serialised args.
    """
    WINDOW = 12
    WARN_AT  = 3
    BREAK_AT = 5

    def __init__(self):
        self._history: list[str] = []
        self._counts:  dict[str, int] = {}

    def record(self, tool: str, args: dict) -> tuple[bool, bool]:
        """
        Record a tool call. Returns (warn, must_break).
        warn=True at WARN_AT repeats; must_break=True at BREAK_AT.
        """
        sig = tool + ":" + json.dumps(args, sort_keys=True)[:300]
        self._history.append(sig)
        if len(self._history) > self.WINDOW:
            evicted = self._history.pop(0)
            self._counts[evicted] = max(0, self._counts.get(evicted, 0) - 1)
        self._counts[sig] = self._counts.get(sig, 0) + 1
        n = self._counts[sig]
        return n >= self.WARN_AT, n >= self.BREAK_AT

    def reset(self) -> None:
        self._history.clear()
        self._counts.clear()


# ──────────────────────────────────────────────────────────────────────────────
#  JSONL Tracer  (ctf-agent technique: append-only, immediate flush, tail -f)
# ──────────────────────────────────────────────────────────────────────────────

class AgentTracer:
    """
    Append-only JSONL event log — one JSON object per line, flushed immediately.
    `tail -f session.jsonl` gives live stream of what the agent is doing.
    """

    def __init__(self, log_path: str):
        self.log_path = log_path
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        self._f = open(log_path, "a", buffering=1)  # line-buffered

    def _write(self, event: dict) -> None:
        event.setdefault("ts", datetime.now().isoformat())
        self._f.write(json.dumps(event) + "\n")
        self._f.flush()

    def tool_call(self, tool: str, args: dict, step: int) -> None:
        self._write({"event": "tool_call", "step": step, "tool": tool, "args": args})

    def tool_result(self, tool: str, result: str, elapsed: float, step: int) -> None:
        self._write({"event": "tool_result", "step": step, "tool": tool,
                     "elapsed_s": elapsed, "result_preview": result[:400]})

    def loop_warn(self, tool: str, count: int, step: int) -> None:
        self._write({"event": "loop_warn", "step": step, "tool": tool, "count": count})

    def loop_break(self, tool: str, step: int) -> None:
        self._write({"event": "loop_break", "step": step, "tool": tool})

    def bump(self, message: str, step: int) -> None:
        self._write({"event": "bump", "step": step, "message": message})

    def finding(self, severity: str, tool: str, text: str) -> None:
        self._write({"event": "finding", "severity": severity, "tool": tool, "text": text[:300]})

    def finish(self, verdict: str, step: int, elapsed_mins: float) -> None:
        self._write({"event": "finish", "step": step,
                     "elapsed_mins": elapsed_mins, "verdict": verdict})

    def close(self) -> None:
        self._f.close()


# ──────────────────────────────────────────────────────────────────────────────
#  Multi-model racer  (ctf-agent: asyncio FIRST_COMPLETED pattern)
# ──────────────────────────────────────────────────────────────────────────────

def race_analysis(prompt: str, models: list[str], client,
                  system: str = "", timeout: int = 120) -> str:
    """
    Ask multiple Ollama models the same analysis question.
    Return whichever completes first with a non-empty answer.
    Used for: triage decisions, next-action advice, finding classification.
    Falls back to sequential if only one model available.
    """
    import threading

    result_holder: dict[str, str] = {}
    done_event = threading.Event()

    def _call(model: str) -> None:
        try:
            resp = client.chat(
                model=model,
                messages=[
                    {"role": "system", "content": system or AGENT_SYSTEM},
                    {"role": "user",   "content": prompt},
                ],
                options={"num_predict": 800, "temperature": 0.1, "num_ctx": 8192},
            )
            text = (resp.get("message", {}).get("content") or "").strip()
            if text and not done_event.is_set():
                result_holder["winner"] = model
                result_holder["text"]   = text
                done_event.set()
        except Exception:
            pass

    threads = [threading.Thread(target=_call, args=(m,), daemon=True) for m in models]
    for t in threads:
        t.start()
    done_event.wait(timeout=timeout)

    if "text" in result_holder:
        winner = result_holder["winner"]
        print(f"{DIM}[Race] Winner: {winner}{NC}", flush=True)
        return result_holder["text"]

    # Sequential fallback
    for m in models:
        try:
            resp = client.chat(
                model=m,
                messages=[
                    {"role": "system", "content": system or AGENT_SYSTEM},
                    {"role": "user",   "content": prompt},
                ],
                options={"num_predict": 800, "temperature": 0.1, "num_ctx": 8192},
            )
            text = (resp.get("message", {}).get("content") or "").strip()
            if text:
                return text
        except Exception:
            continue
    return ""


AGENT_SYSTEM = """\
You are an elite autonomous bug bounty hunter operating within an authorized bug bounty program or VAPT engagement.
You have a set of tools that execute real security scans. Use them strategically.

CORE RULES:
1. Always start with run_recon if no recon data exists yet.
2. After recon, read_recon_summary to understand the attack surface before choosing next tool.
3. run_vuln_scan is a single consolidated pass — it already covers CMS detection, RCE PoC,
   SQLi verification, XSS, SSTI, CORS, JWT, and MFA/SAML checks in one call. There is no
   separate tool per vuln class; don't look for one.
4. run_secret_hunt and run_param_discovery are the only other testing tools — both need
   run_recon's output first (JS bundles / crawled URLs respectively).
5. Check the "Memory-informed priority" section in your context every step — it's real
   win/loss history and expected-value-per-hour for this exact tech stack, pulled from every
   prior hunt across all targets. It's a signal about which vuln classes are worth chasing on
   THIS target's stack, not an instruction to run a specific tool — you still decide the next
   tool call, but weight it by EV/hr and confidence, not by a fixed rule-of-thumb.
6. Maintain your notes via update_working_memory after each significant discovery.
7. Call finish when: all applicable tools have run, time is running low, or no new attack
   surface remains.
8. DO NOT repeat a tool that already completed in this session unless explicitly justified.

Think step by step. Pick the highest-impact next action given what you know."""


class ReActAgent:
    """
    Built-in ReAct loop using Ollama native tool calling.
    Works without LangGraph installed — just needs `pip install ollama`.
    """

    MIN_STEPS_BEFORE_FINISH = 6  # persistence: must run at least N tools before finish allowed

    def __init__(self, domain: str, memory: HuntMemory,
                 dispatcher: ToolDispatcher,
                 max_steps: int = 20,
                 time_budget_hours: float = 2.0,
                 model: str | None = None,
                 tracer: AgentTracer | None = None):
        self.domain     = domain
        self.memory     = memory
        self.dispatcher = dispatcher
        self.max_steps  = max_steps
        self.time_start = time.time()
        self.time_budget_secs = time_budget_hours * 3600
        self.done       = False
        self.verdict    = ""
        self._finish_duplicate_warned = False    # warn once, then let finish through
        self._finish_unconfirmed_warned = False  # same, for the confirmed-PoC gate

        # ctf-agent techniques
        self.loop_detector = LoopDetector()
        self.tracer        = tracer  # set externally after session_file is known
        self.bump_file     = ""      # set by run_agent_hunt — path to bump file

        # racing models (analysis + triage) — baron-llm races qwen3 on quick decisions
        self._race_models: list[str] = []

        if not _OLLAMA_OK:
            raise RuntimeError("Ollama Python package not installed: pip install ollama")

        self.client = _ollama_lib.Client(host=OLLAMA_HOST)
        self.model  = model or self._pick_tool_capable_model()
        if not self.model:
            raise RuntimeError("No Ollama model available. Pull one: ollama pull qwen2.5:32b")

        # Build race roster: primary model + baron-llm if available and different
        try:
            available = [m.model for m in self.client.list().models]
            if "baron-llm:latest" in available and "baron-llm:latest" != self.model:
                self._race_models = [self.model, "baron-llm:latest"]
            else:
                self._race_models = [self.model]
        except Exception:
            self._race_models = [self.model]

        print(f"{GREEN}[Agent] ReAct loop online — model: {BOLD}{self.model}{NC}", flush=True)
        race_note = f"  race_models={self._race_models}" if len(self._race_models) > 1 else ""
        print(f"{DIM}[Agent] max_steps={max_steps}  budget={time_budget_hours}h  "
              f"tool_calling=native{race_note}{NC}", flush=True)

    def _pick_tool_capable_model(self) -> str | None:
        """Prefer models with confirmed Ollama tool-calling support."""
        tool_capable_first = [
            "qwen3-coder-64k:latest",
            "qwen3-coder:30b",
            "qwen2.5:32b",
            "qwen2.5-coder:32b",
            "qwen3:30b-a3b",
            "qwen3:14b",
            "qwen3:8b",
            "mistral:7b-instruct-v0.3-q8_0",
        ]
        try:
            available = [m.model for m in self.client.list().models]
        except Exception:
            return None

        for pref in tool_capable_first:
            if pref in available:
                return pref
        # Fall back to first available
        return available[0] if available else None

    def _build_context(self) -> str:
        """Build the current state block that prefixes every LLM message."""
        elapsed_mins = round((time.time() - self.time_start) / 60, 1)
        budget_mins  = round(self.time_budget_secs / 60, 1)
        remaining    = round((self.time_budget_secs - (time.time() - self.time_start)) / 60, 1)

        completed = list(dict.fromkeys(self.memory.completed_steps))
        ctx_parts = [
            f"## Autonomous Hunt — {self.domain}",
            f"Step {self.memory.step_count + 1}/{self.max_steps}  "
            f"| Elapsed {elapsed_mins}m / {budget_mins}m budget  "
            f"| {remaining}m remaining",
            "",
            f"## Completed steps ({len(completed)})",
            ", ".join(completed) if completed else "(none yet)",
            "",
            "## Working memory (your notes)",
            self.memory.working_memory or "(empty — use update_working_memory to take notes)",
            "",
            "## Findings so far",
            self.memory.findings_summary(),
            "",
            "## Memory-informed priority (hunt-memory/ — real win/loss + EV/hour, not a guess)",
            self.dispatcher.priority_briefing(),
            "",
            "## Recent tool outputs (last 3)",
            self.memory.recent_observations(3),
        ]
        return "\n".join(ctx_parts)

    def _check_bump(self) -> str | None:
        """Check if operator has injected guidance via bump file."""
        if not self.bump_file or not os.path.isfile(self.bump_file):
            return None
        try:
            msg = Path(self.bump_file).read_text().strip()
            if msg:
                Path(self.bump_file).write_text("")  # consume
                return msg
        except Exception:
            pass
        return None

    def step(self) -> str | None:
        """Execute one ReAct step. Returns observation string or None if finished."""
        if self.done:
            return None

        time_left = self.time_budget_secs - (time.time() - self.time_start)
        if time_left < 60:
            print(f"{YELLOW}[Agent] Time budget exhausted — stopping.{NC}", flush=True)
            self.done = True
            return None

        # ── Check operator bump (guidance injection mid-run) ─────────────
        bump_msg = self._check_bump()
        if bump_msg:
            print(f"{YELLOW}[Agent] BUMP received: {bump_msg}{NC}", flush=True)
            if self.tracer:
                self.tracer.bump(bump_msg, self.memory.step_count)
            self.loop_detector.reset()  # fresh start after guidance
            self.memory.working_memory += f"\n\n[OPERATOR GUIDANCE] {bump_msg}"
            self.memory.save()

        context  = self._build_context()
        user_msg = f"{context}\n\nWhat is the best next action? Call the appropriate tool."

        print(f"\n{CYAN}{'─'*60}{NC}", flush=True)
        print(f"{BOLD}[Agent] Step {self.memory.step_count + 1} — calling LLM...{NC}", flush=True)

        try:
            response = self.client.chat(
                model=self.model,
                messages=[
                    {"role": "system",    "content": AGENT_SYSTEM},
                    {"role": "user",      "content": user_msg},
                ],
                tools=TOOLS,
                options={
                    "num_ctx":     16384,
                    "num_predict": 1024,
                    "temperature": 0.1,
                },
            )
        except Exception as e:
            print(f"{RED}[Agent] LLM call failed: {e}{NC}", flush=True)
            return f"LLM error: {e}"

        msg = response.get("message", {})

        # ── Native tool calling path ─────────────────────────────────────
        tool_calls = msg.get("tool_calls", [])
        if tool_calls:
            results = []
            for tc in tool_calls:
                fn   = tc.get("function", {})
                name = fn.get("name", "")
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {}

                # ── Persistence enforcement: block early finish ──────────
                if name == "finish" and self.memory.step_count < self.MIN_STEPS_BEFORE_FINISH:
                    remaining_needed = self.MIN_STEPS_BEFORE_FINISH - self.memory.step_count
                    print(f"{YELLOW}[Agent] Finish blocked — only {self.memory.step_count} steps done, "
                          f"need {remaining_needed} more. Continuing...{NC}", flush=True)
                    results.append(
                        f"[SYSTEM] Too early to finish. You have only run "
                        f"{self.memory.step_count} tools. Run at least "
                        f"{remaining_needed} more high-impact tools before concluding."
                    )
                    continue

                # ── Duplicate/noise gate: don't finish on already-known findings ──
                if name == "finish" and not self._finish_duplicate_warned:
                    gate = self.dispatcher.check_finish_for_duplicates()
                    if gate["blocked"]:
                        self._finish_duplicate_warned = True
                        print(f"{YELLOW}[Agent] Finish gate: {gate['reason']}{NC}", flush=True)
                        results.append(f"[SYSTEM] {gate['reason']} If you've confirmed this is "
                                        f"genuinely new (different endpoint, changed since last time), "
                                        f"call finish again to proceed.")
                        continue

                # ── Exploit-validation gate: don't finish on unverified claims ──
                if name == "finish" and not self._finish_unconfirmed_warned:
                    gate = self.dispatcher.check_finish_for_unconfirmed()
                    if gate["blocked"]:
                        self._finish_unconfirmed_warned = True
                        print(f"{YELLOW}[Agent] Finish gate: {gate['reason']}{NC}", flush=True)
                        results.append(f"[SYSTEM] {gate['reason']} Call finish again once you've "
                                        f"done what you can, or to proceed anyway.")
                        continue

                # ── Loop detection ───────────────────────────────────────
                warn, must_break = self.loop_detector.record(name, args)
                if must_break:
                    print(f"{RED}[Agent] Loop detected on '{name}' — forcing direction change{NC}",
                          flush=True)
                    if self.tracer:
                        self.tracer.loop_break(name, self.memory.step_count)
                    self.loop_detector.reset()
                    results.append(
                        f"[SYSTEM] Loop detected: '{name}' called 5+ times with identical args. "
                        f"You MUST switch strategy. Try a completely different tool or angle. "
                        f"What have you NOT tried yet?"
                    )
                    continue
                if warn:
                    print(f"{YELLOW}[Agent] Loop warning: '{name}' repeated — consider switching{NC}",
                          flush=True)
                    if self.tracer:
                        self.tracer.loop_warn(name, LoopDetector.WARN_AT, self.memory.step_count)

                print(f"{MAGENTA}[Agent] Tool: {BOLD}{name}{NC}{MAGENTA}  args={json.dumps(args)}{NC}",
                      flush=True)
                if self.tracer:
                    self.tracer.tool_call(name, args, self.memory.step_count)

                t0  = time.time()
                obs = self.dispatcher.dispatch(name, args)
                elapsed = round(time.time() - t0, 1)

                if self.tracer:
                    self.tracer.tool_result(name, obs, elapsed, self.memory.step_count)

                results.append(obs)

                if name == "finish":
                    self.done    = True
                    self.verdict = args.get("verdict", "")
                    if self.tracer:
                        self.tracer.finish(self.verdict, self.memory.step_count,
                                           round((time.time() - self.time_start) / 60, 1))

            return "\n\n---\n\n".join(results)

        # ── Text-based fallback (model didn't use tool calling) ──────────
        content = msg.get("content", "")
        if content:
            print(f"{DIM}[Agent] LLM text response (no tool call):\n{content[:300]}{NC}",
                  flush=True)
            # Try to parse ReAct-format: Action: tool_name / Action Input: {...}
            parsed = self._parse_react_text(content)
            if parsed:
                name, args = parsed
                print(f"{MAGENTA}[Agent] Parsed from text: {name}{NC}", flush=True)
                obs = self.dispatcher.dispatch(name, args)
                if name == "finish":
                    self.done    = True
                    self.verdict = args.get("verdict", "")
                return obs

        # LLM produced nothing useful — nudge it
        self.memory.step_count += 1
        return "(LLM produced no tool call — will retry next step)"

    def _parse_react_text(self, text: str) -> tuple[str, dict] | None:
        """Parse old-style ReAct text format as fallback for non-tool-calling models."""
        import re
        # Match: Action: tool_name\nAction Input: {...}
        m = re.search(
            r"Action:\s*(\w+)\s*\nAction\s+Input:\s*(\{.*?\})",
            text, re.DOTALL
        )
        if m:
            name = m.group(1)
            try:
                args = json.loads(m.group(2))
            except Exception:
                args = {}
            if name in TOOL_NAMES:
                return name, args

        # Simpler: just "Action: tool_name" with no args
        m2 = re.search(r"Action:\s*(\w+)", text)
        if m2:
            name = m2.group(1)
            if name in TOOL_NAMES:
                return name, {}

        return None

    def run(self) -> dict:
        """Run the full ReAct loop until done or max_steps reached."""
        from tools.banner import print_banner
        print_banner(
            "ReAct Hunt Agent",
            target=self.domain,
            steps=[
                ("Observe", "read working memory + last 5 tool observations"),
                ("Think",   "LLM picks the next best tool from finding history"),
                ("Act",     "run tool, parse output, persist findings to session"),
                ("Loop",    "repeat until max-steps or LLM signals done"),
            ],
        )

        for i in range(self.max_steps):
            if self.done:
                break

            obs = self.step()
            if obs:
                # Print first 500 chars of observation
                preview = obs[:500] + ("..." if len(obs) > 500 else "")
                print(f"{DIM}[Observation]\n{preview}{NC}\n", flush=True)

        if not self.done:
            print(f"{YELLOW}[Agent] Max steps ({self.max_steps}) reached.{NC}", flush=True)

        elapsed = round((time.time() - self.time_start) / 60, 1)
        print(f"\n{GREEN}[Agent] Hunt complete. ({elapsed} min){NC}")
        print(f"  Steps executed:  {self.memory.step_count}")
        print(f"  Completed tools: {', '.join(dict.fromkeys(self.memory.completed_steps))}")
        print(f"  Findings:        {len(self.memory.findings_log)}")
        if self.tracer:
            print(f"  Trace log:       {self.tracer.log_path}")
        if self.bump_file:
            print(f"  Bump file:       {self.bump_file}")
        if self.verdict:
            print(f"  Verdict:         {self.verdict}")

        return {
            "domain":           self.domain,
            "success":          True,
            "model":            self.model,
            "steps":            self.memory.step_count,
            "completed_steps":  list(dict.fromkeys(self.memory.completed_steps)),
            "reports":          len(self.memory.findings_log),
            "findings":         len(self.memory.findings_log),
            "findings_log":     self.memory.findings_log,
            "working_memory":   self.memory.working_memory,
            "verdict":          self.verdict,
            "session_file":     self.memory.session_file,
            **{step: (step in self.memory.completed_steps)
               for step in ("run_recon", "run_vuln_scan", "run_secret_hunt", "run_param_discovery")},
        }


# ──────────────────────────────────────────────────────────────────────────────
#  LangGraph agent  (optional — requires: pip install langgraph langchain-ollama)
# ──────────────────────────────────────────────────────────────────────────────

def build_langgraph_agent(domain: str, dispatcher: ToolDispatcher,
                           memory: HuntMemory, model: str,
                           max_steps: int = 20):
    """
    Build a real LangGraph ReAct agent.
    State: MessagesState (list of messages)
    Nodes: agent (LLM) → tools (ToolNode) → back to agent
    Edges: tools_condition → tool node or END
    """
    if not _LANGGRAPH_OK:
        raise ImportError(
            "LangGraph not installed. Run:\n"
            "  pip install langgraph langchain-ollama\n"
            "Or use the built-in ReAct loop (default, no extra deps)."
        )

    from typing import TypedDict, Annotated
    from langgraph.graph import StateGraph, END
    from langgraph.graph.message import add_messages
    from langgraph.prebuilt import ToolNode, tools_condition
    from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
    from langchain_core.tools import tool as lc_tool, StructuredTool
    import inspect

    # ── Wrap dispatcher calls as LangChain tools ──────────────────────────
    lc_tools = []
    for tool_spec in TOOLS:
        fn_spec = tool_spec["function"]
        tool_name = fn_spec["name"]
        tool_desc = fn_spec["description"]
        props     = fn_spec["parameters"].get("properties", {})

        # Create a closure that captures tool_name
        def _make_tool(tname):
            def _tool_fn(**kwargs):
                return dispatcher.dispatch(tname, kwargs)
            _tool_fn.__name__ = tname
            _tool_fn.__doc__  = tool_desc
            return lc_tool(_tool_fn)

        lc_tools.append(_make_tool(tool_name))

    # ── LLM with tools bound ──────────────────────────────────────────────
    llm = ChatOllama(
        model=model,
        base_url=OLLAMA_HOST,
        temperature=0.1,
        num_ctx=16384,
    )
    llm_with_tools = llm.bind_tools(lc_tools)

    # ── State ──────────────────────────────────────────────────────────────
    class HuntState(TypedDict):
        messages: Annotated[list, add_messages]

    # ── Graph nodes ────────────────────────────────────────────────────────
    def agent_node(state: HuntState) -> HuntState:
        context = f"Target: {domain}\n\n" + _build_context_for_langgraph(domain, memory, dispatcher)
        # Prepend system + context to messages if first call
        msgs = state["messages"]
        if not any(isinstance(m, SystemMessage) for m in msgs):
            msgs = [SystemMessage(content=AGENT_SYSTEM),
                    HumanMessage(content=context)] + list(msgs)
        response = llm_with_tools.invoke(msgs)
        # Check finish signal
        if hasattr(response, "tool_calls"):
            for tc in (response.tool_calls or []):
                if tc.get("name") == "finish":
                    memory.working_memory += f"\n\nFINISHED: {tc.get('args', {}).get('verdict', '')}"
        return {"messages": [response]}

    tool_node = ToolNode(lc_tools)

    def should_continue(state: HuntState):
        last = state["messages"][-1]
        if not hasattr(last, "tool_calls") or not last.tool_calls:
            return END
        if any(tc.get("name") == "finish" for tc in last.tool_calls):
            return END
        if memory.step_count >= max_steps:
            return END
        return "tools"

    # ── Build graph ────────────────────────────────────────────────────────
    graph = StateGraph(HuntState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.set_entry_point("agent")
    graph.add_conditional_edges("agent", should_continue, {"tools": "tools", END: END})
    graph.add_edge("tools", "agent")

    return graph.compile()


def _build_context_for_langgraph(domain: str, memory: HuntMemory, dispatcher: ToolDispatcher) -> str:
    """Same context builder used by LangGraph agent node."""
    completed = list(dict.fromkeys(memory.completed_steps))
    return (
        f"Completed steps: {', '.join(completed) or 'none'}\n"
        f"Working memory:\n{memory.working_memory or '(empty)'}\n\n"
        f"Findings so far:\n{memory.findings_summary()}\n\n"
        f"Memory-informed priority (hunt-memory/):\n{dispatcher.priority_briefing()}\n\n"
        f"Recent observations:\n{memory.recent_observations(2)}"
    )


# ──────────────────────────────────────────────────────────────────────────────
#  Public entry point  (called directly: python3 agent.py --target x)
# ──────────────────────────────────────────────────────────────────────────────

def run_agent_hunt(
    domain: str,
    *,
    scope_lock: bool = False,
    max_steps: int = 20,
    time_budget_hours: float = 2.0,
    cookies: str = "",
    model: str | None = None,
    resume_session_id: str | None = None,
    use_langgraph: bool = False,
) -> dict:
    """
    Main entry point for agent-driven autonomous hunting.

    One persistent session per domain (recon/<domain>/agent_session.json) — matches
    tools/hunt.py's flat, domain-keyed layout. Re-running against the same domain
    automatically resumes; there's no separate session-ID concept to select between.
    """
    h = _h()
    if resume_session_id and resume_session_id != "latest":
        print(f"{YELLOW}[Agent] --resume is informational only now — session state is "
              f"per-domain (recon/{domain}/agent_session.json), not per-ID.{NC}", flush=True)

    # ── Resolve session (flat, domain-keyed — no session-ID concept) ──────
    session_dir  = _recon_dir_for(domain)
    session_file = os.path.join(session_dir, "agent_session.json")

    print(f"{GREEN}[Agent] Session: {domain} → {session_dir}{NC}", flush=True)

    # ── Init memory + dispatcher ──────────────────────────────────────────
    memory     = HuntMemory(session_file)
    dispatcher = ToolDispatcher(
        domain, memory,
        scope_lock=scope_lock,
        default_cookies=cookies,
    )

    # ── Run ───────────────────────────────────────────────────────────────
    if use_langgraph and _LANGGRAPH_OK:
        print(f"{GREEN}[Agent] Using real LangGraph backend.{NC}", flush=True)
        picked_model = model or (_pick_model() if _BRAIN_OK else None) or "qwen2.5:32b"
        try:
            graph   = build_langgraph_agent(domain, dispatcher, memory, picked_model, max_steps)
            initial = {"messages": [HumanMessage(content=f"Hunt {domain}. Begin.")]}
            result_state = graph.invoke(initial, config={"recursion_limit": max_steps * 2})
            return {
                "domain":          domain,
                "success":         True,
                "model":           picked_model,
                "backend":         "langgraph",
                "steps":           memory.step_count,
                "completed_steps": list(dict.fromkeys(memory.completed_steps)),
                "reports":         len(memory.findings_log),
                "findings":        len(memory.findings_log),
                "session_file":    session_file,
                "working_memory":  memory.working_memory,
                **{step: (step in memory.completed_steps)
                   for step in ("run_recon", "run_vuln_scan", "run_secret_hunt", "run_param_discovery")},
            }
        except Exception as e:
            print(f"{YELLOW}[Agent] LangGraph error: {e} — falling back to built-in{NC}",
                  flush=True)

    # Built-in ReAct loop
    log_path  = os.path.join(session_dir, "agent_trace.jsonl")
    bump_path = os.path.join(session_dir, "agent_bump.txt")
    tracer    = AgentTracer(log_path)

    print(f"{GREEN}[Agent] Trace: tail -f {log_path}{NC}", flush=True)
    print(f"{GREEN}[Agent] Bump:  echo 'guidance here' > {bump_path}{NC}", flush=True)

    agent = ReActAgent(
        domain      = domain,
        memory      = memory,
        dispatcher  = dispatcher,
        max_steps   = max_steps,
        time_budget_hours = time_budget_hours,
        model       = model,
        tracer      = tracer,
    )
    agent.bump_file = bump_path

    result = agent.run()
    tracer.close()
    result["backend"]    = "builtin-react"
    result["trace_path"] = log_path
    result["bump_path"]  = bump_path
    return result


# ──────────────────────────────────────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ReAct hunting agent — autonomous bug bounty with Ollama tool calling",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 agent.py --target example.com
  python3 agent.py --target example.com --time 4 --max-steps 30
  python3 agent.py --target example.com --cookie "JSESSIONID=abc123"
  python3 agent.py --target example.com --scope-lock
  python3 agent.py --target example.com --langgraph
  python3 agent.py --target example.com --list-models
"""
    )
    parser.add_argument("--target",      required=False, help="Domain to hunt")
    parser.add_argument("--time",        type=float, default=2.0, help="Time budget in hours (default 2)")
    parser.add_argument("--max-steps",   type=int,   default=20,  help="Max ReAct iterations (default 20)")
    parser.add_argument("--cookie",      type=str,   default="",  help="Session cookie for POST discovery")
    parser.add_argument("--scope-lock",  action="store_true",     help="Stick to exact target only")
    parser.add_argument("--model",       type=str,   default=None, help="Ollama model override")
    parser.add_argument("--langgraph",   action="store_true",     help="Use real LangGraph backend")
    parser.add_argument("--resume",      type=str,   default=None,
                        help="Deprecated — session state is per-domain now, resume is automatic")
    parser.add_argument("--list-models", action="store_true",     help="List available Ollama models")
    parser.add_argument("--bump",        type=str,   default=None,
                        help="Inject operator guidance mid-run: --bump SESSION_DIR 'message'",
                        nargs=2, metavar=("SESSION_DIR", "MESSAGE"))
    args = parser.parse_args()

    if args.list_models:
        if not _OLLAMA_OK:
            print("Ollama not installed: pip install ollama")
            return
        client = _ollama_lib.Client(host=OLLAMA_HOST)
        try:
            models = [m.model for m in client.list().models]
            print(f"\nAvailable Ollama models ({len(models)}):")
            for m in models:
                marker = " ← recommended" if any(m.startswith(p.split(":")[0]) for p in
                         ["qwen3-coder", "qwen2.5", "qwen3"]) else ""
                print(f"  {m}{marker}")
        except Exception as e:
            print(f"Cannot reach Ollama: {e}")
        print(f"\nLangGraph available: {_LANGGRAPH_OK}")
        print(f"Ollama available:    {_OLLAMA_OK}")
        return

    if args.bump:
        session_dir, message = args.bump
        bump_file = os.path.join(session_dir, "agent_bump.txt")
        Path(bump_file).write_text(message.strip())
        print(f"[Bump] Wrote guidance to {bump_file}")
        print(f"[Bump] Agent will pick it up on next step.")
        return

    if not args.target:
        parser.print_help()
        sys.exit(1)

    # Trust boundary — same check hunt.py's CLI enforces. args.target flows
    # into recon_dir/findings_dir (os.path.join) which _run_shell_tool passes
    # to secrets_hunter.sh/param_discovery.sh; validating once here means
    # every downstream use can assume a safe domain/IP/CIDR/path.
    try:
        _h().validate_target(args.target)
    except ValueError as exc:
        print(f"Refusing target {args.target!r}: {exc}")
        sys.exit(2)

    result = run_agent_hunt(
        args.target,
        scope_lock=args.scope_lock,
        max_steps=args.max_steps,
        time_budget_hours=args.time,
        cookies=args.cookie,
        model=args.model,
        resume_session_id=args.resume,
        use_langgraph=args.langgraph,
    )

    print(f"\n{BOLD}{'═'*60}{NC}")
    print(f"{BOLD}Hunt Result: {result['domain']}{NC}")
    print(f"  Backend:   {result.get('backend', 'unknown')}")
    print(f"  Model:     {result.get('model', 'unknown')}")
    print(f"  Steps:     {result.get('steps', 0)}")
    print(f"  Findings:  {result.get('findings', 0)}")
    print(f"  Session:   {result.get('session_file', '')}")
    if result.get("trace_path"):
        print(f"  Trace:     {result['trace_path']}")
    if result.get("bump_path"):
        print(f"  Bump:      echo 'guidance' > {result['bump_path']}")
    if result.get("verdict"):
        print(f"\nVerdict:\n{result['verdict']}")
    print(f"{BOLD}{'═'*60}{NC}\n")


if __name__ == "__main__":
    main()
