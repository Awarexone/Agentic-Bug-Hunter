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
  python3 agent.py --target example.com --resume SESSION_ID

From hunt.py:
  hunt.py --target x --agent              # drops into agent mode
  hunt.py --target x --agent --langgraph  # with real LangGraph
"""

from __future__ import annotations

import argparse
import json
import os
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
    """Lazy-load hunt module once."""
    global _hunt
    if _hunt is None:
        import importlib.util, sys as _sys
        _here = os.path.dirname(os.path.abspath(__file__))
        spec = importlib.util.spec_from_file_location("hunt", os.path.join(_here, "hunt.py"))
        _hunt = importlib.util.module_from_spec(spec)
        _sys.modules.setdefault("hunt", _hunt)
        spec.loader.exec_module(_hunt)
    return _hunt

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
                    "max_urls": {
                        "type": "integer",
                        "description": "Max URLs to collect (default 100, use 200+ for thorough recon).",
                        "default": 100,
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
                "Run the core vulnerability scanner (nuclei templates + custom checks). "
                "Tests for CVEs, misconfigs, exposed panels, default creds, takeover candidates. "
                "Returns: finding count by severity."
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
            "name": "run_js_analysis",
            "description": (
                "Download and analyse all JavaScript files found during recon. "
                "Extracts: API keys, secrets, hardcoded tokens, internal endpoints, "
                "GraphQL schemas, and auth-bypass hints. Use when JS files were discovered."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_secret_hunt",
            "description": (
                "Scan for leaked secrets: TruffleHog on JS/git repos, GitHound on GitHub, "
                "hardcoded AWS/GCP/Azure keys, API tokens, private keys. "
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
                "Brute-force GET URL parameters using arjun + paramspider on all live hosts. "
                "Use when parameterized URLs are sparse or the site returns data conditionally. "
                "Returns: new parameterized URLs added to the attack surface."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_post_param_discovery",
            "description": (
                "Discover POST form endpoints and their parameter names using lightpanda "
                "(JS-rendered HTML) + arjun POST brute-force. "
                "Mandatory for JSP/Java/Spring apps, ASP.NET WebForms, any app with login forms. "
                "Then runs sqlmap on discovered POST endpoints automatically. "
                "Pass cookies if the forms are behind authentication."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cookies": {
                        "type": "string",
                        "description": "Session cookie string e.g. 'JSESSIONID=abc; token=xyz'",
                        "default": "",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_api_fuzz",
            "description": (
                "Fuzz API endpoints for IDOR, auth bypass, privilege escalation, "
                "and unauthenticated access. Tests REST + GraphQL + gRPC. "
                "Use when API endpoints or numeric IDs were found in recon."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_cors_check",
            "description": (
                "Test all live hosts for CORS misconfigurations: null origin, "
                "wildcard with credentials, trusted subdomain bypass. "
                "High-priority when authenticated API endpoints are present."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_cms_exploit",
            "description": (
                "Run CMS-specific exploit checks: Drupalgeddon (CVE-2014-3704, CVE-2018-7600), "
                "WordPress plugin vulns + user enum, Joomla RCE, Magento SQLi. "
                "Use immediately when a CMS is detected — especially Drupal < 8 or WordPress."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_rce_scan",
            "description": (
                "Scan for Remote Code Execution vectors: Log4Shell (JNDI), Tomcat PUT upload, "
                "JBoss admin consoles, SSTI (Jinja2/Twig/Freemarker), shellshock, "
                "interactsh OOB callbacks. Use when Java/Tomcat/JBoss/Struts is detected."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_sqlmap_targeted",
            "description": (
                "Run sqlmap against parameterized GET URLs found in recon. "
                "Tests error-based, boolean-blind, time-blind, UNION injection. "
                "Use when parameterized URLs exist OR nuclei flagged SQL-related findings."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_sqlmap_on_file",
            "description": (
                "Run sqlmap against a specific raw HTTP request file (Burp-style). "
                "Use when you know a specific endpoint with POST params that needs SQLi testing. "
                "Provide the full path to the saved request file."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "request_file": {
                        "type": "string",
                        "description": "Absolute path to raw HTTP request file.",
                    },
                    "level": {
                        "type": "integer",
                        "description": "sqlmap level 1-5 (default 5).",
                        "default": 5,
                    },
                    "risk": {
                        "type": "integer",
                        "description": "sqlmap risk 1-3 (default 3).",
                        "default": 3,
                    },
                },
                "required": ["request_file"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_jwt_audit",
            "description": (
                "Audit JWT tokens found in recon artifacts: algorithm confusion (alg=none, "
                "RS256→HS256), weak HMAC secret cracking, forged claims. "
                "Use when JWT tokens appear in URLs, cookies, or response headers."
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

    def add_finding(self, tool: str, severity: str, text: str) -> None:
        self.findings_log.append({
            "tool":     tool,
            "severity": severity,
            "text":     text[:500],
            "ts":       datetime.now().isoformat(),
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
                 scope_lock: bool = False, max_urls: int = 100,
                 default_cookies: str = ""):
        self.domain          = domain
        self.memory          = memory
        self.scope_lock      = scope_lock
        self.max_urls        = max_urls
        self.default_cookies = default_cookies

    def dispatch(self, name: str, args: dict) -> str:
        """Execute named tool and return text observation."""
        h = _h()
        domain = self.domain
        t0 = time.time()

        try:
            if name == "run_recon":
                ok = h.run_recon(
                    domain,
                    scope_lock=args.get("scope_lock", self.scope_lock),
                    max_urls=int(args.get("max_urls", self.max_urls)),
                )
                obs = self._summarize_recon(domain, ok)

            elif name == "run_vuln_scan":
                ok = h.run_vuln_scan(
                    domain,
                    quick=bool(args.get("quick", False)),
                    full=bool(args.get("full", False)),
                )
                obs = self._summarize_findings(domain, "scan", ok)

            elif name == "run_js_analysis":
                ok = h.run_js_analysis(domain)
                obs = self._summarize_findings(domain, "js", ok)

            elif name == "run_secret_hunt":
                ok = h.run_secret_hunt(domain)
                obs = self._summarize_findings(domain, "secrets", ok)

            elif name == "run_param_discovery":
                ok = h.run_param_discovery(domain)
                obs = self._summarize_params(domain, ok)

            elif name == "run_post_param_discovery":
                cookies = args.get("cookies", self.default_cookies)
                ok = h.run_post_param_discovery(domain, cookies=cookies)
                obs = self._summarize_post_params(domain, ok)

            elif name == "run_api_fuzz":
                ok = h.run_api_fuzz(domain)
                obs = self._summarize_findings(domain, "api", ok)

            elif name == "run_cors_check":
                ok = h.run_cors_check(domain)
                obs = self._summarize_findings(domain, "cors", ok)

            elif name == "run_cms_exploit":
                ok = h.run_cms_exploit(domain)
                obs = self._summarize_findings(domain, "cms", ok)

            elif name == "run_rce_scan":
                ok = h.run_rce_scan(domain)
                obs = self._summarize_findings(domain, "rce", ok)

            elif name == "run_sqlmap_targeted":
                ok = h.run_sqlmap_targeted(domain)
                obs = self._summarize_findings(domain, "sqlmap", ok)

            elif name == "run_sqlmap_on_file":
                req_file = args.get("request_file", "")
                if not req_file or not os.path.isfile(req_file):
                    return f"ERROR: request_file not found: {req_file}"
                ok = h.run_sqlmap_request_file(
                    req_file, domain=domain,
                    level=int(args.get("level", 5)),
                    risk=int(args.get("risk", 3)),
                )
                obs = f"sqlmap (request-file) completed. Injectable: {ok}"

            elif name == "run_jwt_audit":
                ok = h.run_jwt_audit(domain)
                obs = self._summarize_findings(domain, "jwt", ok)

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
        h = _h()
        recon_dir = h._resolve_recon_dir(domain)
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
        h = _h()
        findings_dir = h._resolve_findings_dir(domain, create=False)
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

    def _summarize_params(self, domain: str, ok: bool) -> str:
        h = _h()
        recon_dir  = h._resolve_recon_dir(domain)
        params_dir = os.path.join(recon_dir, "params")
        lines = [f"run_param_discovery: {'OK' if ok else 'partial'}"]
        for fn in ("paramspider.txt", "arjun.json"):
            fp = os.path.join(params_dir, fn)
            if os.path.isfile(fp):
                count = sum(1 for _ in open(fp) if _.strip())
                lines.append(f"  {fn}: {count} lines")
        return "\n".join(lines)

    def _summarize_post_params(self, domain: str, ok: bool) -> str:
        h = _h()
        recon_dir  = h._resolve_recon_dir(domain)
        params_dir = os.path.join(recon_dir, "params")
        lines = [f"run_post_param_discovery: {'found POST params' if ok else 'no POST params found'}"]
        fp = os.path.join(params_dir, "post_params.json")
        if os.path.isfile(fp):
            try:
                data = json.loads(Path(fp).read_text())
                for url, info in list(data.items())[:8]:
                    params = ", ".join(info.get("params", [])[:6])
                    lines.append(f"  POST {url}  →  [{params}]")
            except Exception:
                pass
        return "\n".join(lines)

    def _read_recon_files(self, domain: str) -> str:
        h = _h()
        recon_dir = h._resolve_recon_dir(domain)
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
        h = _h()
        findings_dir = h._resolve_findings_dir(domain, create=False)
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

    def _classify_obs(self, tool: str, obs: str) -> None:
        """Extract severity labels from observation text and add to findings_log."""
        obs_l = obs.lower()
        if any(kw in obs_l for kw in ("rce_confirmed", "injectable", "critical")):
            sev = "CRITICAL"
        elif any(kw in obs_l for kw in ("high", "sql injection", "rce", "default cred")):
            sev = "HIGH"
        elif any(kw in obs_l for kw in ("medium", "exposed", "open redirect", "cors")):
            sev = "MEDIUM"
        elif any(kw in obs_l for kw in ("low", "info")):
            sev = "LOW"
        else:
            return  # not a finding, skip

        # Take first relevant line as summary
        for ln in obs.splitlines():
            if any(kw in ln.lower() for kw in
                   ("critical", "high", "injectable", "rce", "exposed", "found", "medium", "sql")):
                self.memory.add_finding(tool, sev, ln.strip()[:300])
                break


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
3. Prioritize by impact: CMS exploits > RCE > SQLi > IDOR > secrets > info.
4. If Drupal or WordPress is detected → run_cms_exploit immediately.
5. If Java/Tomcat/JBoss/Spring is detected → run_rce_scan + run_post_param_discovery.
6. If parameterized URLs found → run_sqlmap_targeted.
7. If JWT tokens appear in any recon data → run_jwt_audit.
8. Maintain your notes via update_working_memory after each significant discovery.
9. Call finish when: all high-priority tools done, time running low, or no new attack surface.
10. DO NOT repeat a tool that already completed in this session unless explicitly justified.

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
        print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════╗{NC}")
        print(f"{BOLD}{CYAN}║  ReAct Hunt Agent — {self.domain:<20}  ║{NC}")
        print(f"{BOLD}{CYAN}╚══════════════════════════════════════════╝{NC}\n")

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
            # Map completed_steps to phase flags print_dashboard checks
            **{step: (step in self.memory.completed_steps)
               for step in ("recon", "scan", "js_analysis", "secret_hunt",
                            "param_discovery", "api_fuzz", "cors", "cms_exploit",
                            "rce_scan", "sqlmap", "jwt_audit")},
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
        context = f"Target: {domain}\n\n" + _build_context_for_langgraph(domain, memory)
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


def _build_context_for_langgraph(domain: str, memory: HuntMemory) -> str:
    """Same context builder used by LangGraph agent node."""
    completed = list(dict.fromkeys(memory.completed_steps))
    return (
        f"Completed steps: {', '.join(completed) or 'none'}\n"
        f"Working memory:\n{memory.working_memory or '(empty)'}\n\n"
        f"Findings so far:\n{memory.findings_summary()}\n\n"
        f"Recent observations:\n{memory.recent_observations(2)}"
    )


# ──────────────────────────────────────────────────────────────────────────────
#  Public entry point  (called by hunt.py --agent)
# ──────────────────────────────────────────────────────────────────────────────

def run_agent_hunt(
    domain: str,
    *,
    scope_lock: bool = False,
    max_urls: int = 100,
    max_steps: int = 20,
    time_budget_hours: float = 2.0,
    cookies: str = "",
    model: str | None = None,
    resume_session_id: str | None = None,
    use_langgraph: bool = False,
) -> dict:
    """
    Main entry point for agent-driven autonomous hunting.
    Called by hunt.py when --agent flag is passed.
    """
    h = _h()

    # ── Resolve session ───────────────────────────────────────────────────
    session_id, recon_dir = h._activate_recon_session(
        domain,
        requested_session_id=resume_session_id or "latest",
        create=True,
    )
    session_dir  = os.path.dirname(recon_dir)
    session_file = os.path.join(session_dir, "agent_session.json")

    print(f"{GREEN}[Agent] Session: {session_id} → {recon_dir}{NC}", flush=True)

    # ── Init memory + dispatcher ──────────────────────────────────────────
    memory     = HuntMemory(session_file)
    dispatcher = ToolDispatcher(
        domain, memory,
        scope_lock=scope_lock,
        max_urls=max_urls,
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
                   for step in ("recon", "scan", "js_analysis", "secret_hunt",
                                "param_discovery", "api_fuzz", "cors", "cms_exploit",
                                "rce_scan", "sqlmap", "jwt_audit")},
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
  python3 agent.py --target example.com --scope-lock --max-urls 50
  python3 agent.py --target example.com --langgraph
  python3 agent.py --target example.com --resume SESSION_ID
  python3 agent.py --list-models
"""
    )
    parser.add_argument("--target",      required=False, help="Domain to hunt")
    parser.add_argument("--time",        type=float, default=2.0, help="Time budget in hours (default 2)")
    parser.add_argument("--max-steps",   type=int,   default=20,  help="Max ReAct iterations (default 20)")
    parser.add_argument("--cookie",      type=str,   default="",  help="Session cookie for POST discovery")
    parser.add_argument("--scope-lock",  action="store_true",     help="Stick to exact target only")
    parser.add_argument("--max-urls",    type=int,   default=100, help="Max URLs in recon (default 100)")
    parser.add_argument("--model",       type=str,   default=None, help="Ollama model override")
    parser.add_argument("--langgraph",   action="store_true",     help="Use real LangGraph backend")
    parser.add_argument("--resume",      type=str,   default=None, help="Resume session ID")
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

    result = run_agent_hunt(
        args.target,
        scope_lock=args.scope_lock,
        max_urls=args.max_urls,
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
