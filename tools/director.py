#!/usr/bin/env python3
"""
Research Director — Phase 2 orchestration layer.

Problem this solves: recon-ranker.md scores classes/endpoints, and
hypothesis-engine.md generates named hypotheses, but nothing turns that
into an *executable, time-boxed plan* with explicit negative space (what
we are NOT doing and why), dependency-aware scheduling, and a mandatory
falsifier on every attack. That's this module's whole job. It generates
zero new hypotheses and computes zero new scores — it converts leads that
already exist (lead board + Phase 1 browser intelligence) into ordered,
falsifiable, time-budgeted attacks.

ONE FORMULA: every priority/EV number in this file is the unmodified
return of memory.vuln_intelligence.priority_score() / expected_value_per_hour().
This module never recomputes those; it only reads, orders, and explains.

detection_risk: deliberately NOT a field anywhere in this module. There is
no measured or persisted detection-risk signal anywhere in this codebase
(checked tools/waf_response_analyzer.py — an active-fingerprinting tool
with no persisted per-target output to read at planning time; and
memory/audit_log.py's RateLimiter/CircuitBreaker — runtime execution
guards, not a pre-computed score). Rather than fabricate a 0-1 float,
only `risk_level` (LOW/MEDIUM/HIGH) exists, computed from a small,
explicitly-labeled static heuristic (see risk_level_for()) — not a
measured value, same treatment as cold-start confidence in confidence().

Pure library + thin CLI: no input(), no prompts, JSON in/out — same
convention as memory/vuln_intelligence.py and memory/finding_score.py.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools import lead_board  # noqa: E402
from tools import fingerprint  # noqa: E402
from memory.finding_score import normalize_vuln_class  # noqa: E402
from memory.pattern_db import PatternDB  # noqa: E402
from memory.vuln_intelligence import (  # noqa: E402
    ChainDB,
    FailedPatternDB,
    HypothesisDB,
    ReportOutcomeDB,
    TESTING_TIME_ESTIMATES,
    DEFAULT_TESTING_TIME_MINUTES,
    _memory_paths,  # reused, not reimplemented — same path map the CLI commands use
    _read_jsonl_best_effort,  # reused for journal.jsonl (no dedicated JournalDB exists)
    duplicate_or_noise_check,
    expected_value_per_hour,
    hypothesis_calibration,
    priority_score,
    tech_vuln_affinity,
)
from memory.experiment_memory import should_stop  # noqa: E402

# ─── State machine ──────────────────────────────────────────────────────────

STATES = (
    "PENDING", "READY", "IN_PROGRESS", "WAITING", "BLOCKED",
    "COMPLETED", "ABANDONED", "FAILED", "SKIPPED",
)
TERMINAL_STATES = {"COMPLETED", "ABANDONED", "FAILED", "SKIPPED"}

# ─── Skip taxonomy ──────────────────────────────────────────────────────────
# Every reason the automatic classifier can actually detect from data it has.
# ALWAYS_REJECTED and POLICY_EXCLUDED stay in the vocabulary (schema
# completeness, and a future validation-time caller can set them) but the
# classifier below never emits them itself — see module docstring in
# _skip_reason() for why: recon-time leads are unconfirmed candidates, and
# both of those reasons require proof this Director doesn't have yet.
SKIP_REASONS = (
    "BELOW_EV_FLOOR",
    "MATCHES_FAILED_PATTERN",
    "POLICY_EXCLUDED",
    "ALWAYS_REJECTED",
    "DUPLICATE",
    "TIME_CONSTRAINT",
    "DEPENDENCY_UNMET",
    "INSUFFICIENT_EVIDENCE",
)
AUTO_DETECTABLE_SKIP_REASONS = (
    "BELOW_EV_FLOOR", "MATCHES_FAILED_PATTERN", "DUPLICATE",
    "TIME_CONSTRAINT", "DEPENDENCY_UNMET", "INSUFFICIENT_EVIDENCE",
)

RISK_LEVELS = ("LOW", "MEDIUM", "HIGH")

# should_stop()'s own default minute_limit (memory/experiment_memory.py) —
# reused as the minimum time every attack gets before a stop/pivot judgment
# is even meaningful. Not a new number: it's the exact constant rules/hunting.md's
# 5-minute rule and should_stop()'s default already use.
MINIMUM_TIME_MINUTES = 5.0

# ─── Skill (hunt-*) -> vuln_class ───────────────────────────────────────────


def skill_to_vuln_class(skill: str) -> str:
    """lead_board.py leads carry a `skill` field ("hunt-idor"), not the
    `vuln_class` string priority_score() needs ("idor"). No such mapping
    exists anywhere in the codebase today (recon-ranker.md does this by LLM
    judgment, not code). Strip the "hunt-" prefix and hand the rest to
    memory.finding_score.normalize_vuln_class() — reusing the exact alias
    table finding_score.py already maintains for the equivalent scanner-
    category problem, instead of building a second one. Skills with no
    entry in that alias table pass through lowercased unchanged, and
    priority_score() degrades gracefully to DEFAULT_IMPACT_POTENTIAL for
    anything unrecognized — the same graceful-unknown behavior
    finding_score.py's own tests already prove.
    """
    category = re.sub(r"^hunt-", "", skill or "")
    return normalize_vuln_class(category)


# ─── tech_stack loader ──────────────────────────────────────────────────────


def load_tech_stack(target: str, memory_dir: str) -> list[str]:
    """<memory_dir>/targets/<target>.json's "tech_stack" field, if the
    profile exists (memory/schemas.py::validate_target_profile() defines
    the shape; nothing before this read it back into a plain list). Best
    effort: missing file, malformed JSON, or a non-list value all resolve
    to [] rather than raising — an empty tech stack is a legitimate
    heuristic-only state the scoring formula already handles."""
    path = Path(memory_dir) / "targets" / f"{target}.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return []
    stack = data.get("tech_stack", [])
    return stack if isinstance(stack, list) else []


def load_fingerprint_tech_attack_matrix(target: str, recon_dir: str,
                                         matrix_path: str | None = None) -> dict | None:
    """tools/tech_attack_matrix.json, gated on recon/<target>/fingerprint.json
    (tools/fingerprint.py's Phase 3 output) actually existing for THIS
    target. fingerprint.json's presence is the gate, not the matrix file's
    — a target that never ran Phase 3 fingerprinting gets None back here,
    which priority_score()/expected_value_per_hour() treat identically to
    the parameter never existing (their `if tech_attack_matrix else 20`
    branch), so behavior for a not-yet-fingerprinted target is byte-
    identical to before this wiring existed. A present-but-malformed
    fingerprint.json is treated the same as absent — best-effort, no
    crash, same convention _read_browser_json()/load_tech_stack() already
    use in this module."""
    fp_path = Path(recon_dir) / "fingerprint.json"
    if not fp_path.exists():
        return None
    try:
        json.loads(fp_path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None
    return fingerprint.load_tech_attack_matrix(matrix_path or fingerprint.DEFAULT_MATRIX_PATH)


# ─── Memory loading (mirrors memory/finding_score.py's _memory_lists()) ────


def load_memory(memory_dir: str) -> dict:
    """All memory-backed inputs priority_score()/expected_value_per_hour()/
    hypothesis_calibration()/duplicate_or_noise_check() take, loaded once
    per build_plan()/replan() call. Uses the exact same path map
    (_memory_paths) and best-effort JSONL reader (_read_jsonl_best_effort)
    memory/vuln_intelligence.py's own CLI commands use — not a second
    loader convention."""
    paths = _memory_paths(memory_dir)
    return {
        "patterns": PatternDB(paths["patterns"]).read_all(),
        "failed_patterns": FailedPatternDB(paths["failed_patterns"]).read_all(),
        "chains": ChainDB(paths["chains"]).read_all(),
        "report_outcomes": ReportOutcomeDB(paths["report_outcomes"]).read_all(),
        "hypotheses": HypothesisDB(paths["hypotheses"]).read_all(),
        "journal": _read_jsonl_best_effort(paths["journal"]),
    }


# ─── Browser intelligence -> concrete leads ────────────────────────────────
#
# Phase 1's four artifacts (recon/<target>/browser/*.json) sit there as
# passive data until something turns them into attack candidates. Every
# URL-shaped signal is run through lead_board.route_observation() — the
# SAME classifier ingest() already uses for ordinary recon URLs — instead
# of hand-rolling new routing rules. Bare paths (framework routes, browser
# recon's own privileged-route candidates) are joined against a synthetic
# https://<target> base first since route_observation()'s patterns expect
# a scheme. Role/permission constants have no URL shape and no existing
# classifier, so those get one minimal, explicitly-labeled lead each.
#
# These are transient: they're candidate pools for THIS build_plan() call,
# never written to memory/leads/<target>.jsonl. Only browser_recon.py's own
# discover_hidden_endpoints() (never-called.json) already has a deliberate,
# separate persistence path into urls/api_endpoints.txt, feeding the
# ordinary lead_board.py ingest() the next time a hunter runs it — this
# function does not duplicate or bypass that; it just also scores these
# signals for THIS plan without mutating shared lead-board state.
#
# NOTE (documented gap, not silently dropped): the Phase 2 spec's example
# list for browser-intelligence leads includes "feature flags". Verified:
# tools/browser_recon.py has no feature-flag extractor of any kind today —
# no lead type is synthesized for it here. Source-map discoveries are
# already covered transitively: recovered sources under browser/sources/
# already feed discover_hidden_endpoints() and extract_framework_routes(),
# both of which this function already reads via never-called.json/routes.json.

_URL_SCHEME_RE = re.compile(r"^https?://", re.I)


def _as_url(target: str, path_or_url: str) -> str:
    if _URL_SCHEME_RE.match(path_or_url or ""):
        return path_or_url
    suffix = path_or_url if (path_or_url or "").startswith("/") else f"/{path_or_url}"
    return f"https://{target}{suffix}"


def _read_browser_json(recon_dir: str, name: str) -> dict | None:
    p = Path(recon_dir) / "browser" / name
    if not p.exists():
        return None
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None
    return payload if isinstance(payload, dict) else None


def _new_browser_lead(target: str, skill: str, priority: str, signal: str, why: str,
                       evidence: str, artifact: str) -> dict:
    now = lead_board.now_iso()
    return {
        "id": "bi-" + secrets.token_hex(3),
        "target": target,
        "skill": skill,
        "priority": priority,
        "signal": signal,
        "why": why,
        "evidence": lead_board.norm_evidence(evidence),
        "source": "browser-intel",
        "browser_artifact": artifact,
        "status": "new",
        "note": "",
        "created": now,
        "last_seen": now,
        "seen_count": 1,
    }


def browser_intel_leads(target: str, recon_dir: str) -> list[dict]:
    """Convert recon/<target>/browser/*.json (Phase 1 output) into
    lead-board-shaped candidate dicts. Never raises, never sends a
    request — pure file read + existing-classifier reuse. Returns []
    if Phase 1 never ran (no browser/ dir) or produced nothing."""
    leads: list[dict] = []

    def _route_url(raw: str, artifact: str) -> None:
        url = _as_url(target, raw)
        for skill, prio, label, why in lead_board.route_observation(url, "url"):
            leads.append(_new_browser_lead(target, skill, prio, label, why, raw, artifact))

    never_called = _read_browser_json(recon_dir, "never-called.json")
    if never_called:
        for ep in never_called.get("never_called", []) or []:
            _route_url(ep, "never-called.json")

    routes = _read_browser_json(recon_dir, "routes.json")
    if routes:
        for route in routes.get("routes", []) or []:
            _route_url(route, "routes.json")

    auth_model = _read_browser_json(recon_dir, "auth-model.json")
    if auth_model:
        for route in auth_model.get("candidate_privileged_client_routes", []) or []:
            _route_url(route, "auth-model.json")
        for url in auth_model.get("auth_lifecycle_endpoints", []) or []:
            _route_url(url, "auth-model.json")
        for const in auth_model.get("role_permission_constants", []) or []:
            leads.append(_new_browser_lead(
                target, "hunt-auth-bypass", lead_board.P_MED,
                "role/permission constant (browser auth-model)",
                "client-side role/permission constant discovered — test privilege "
                "escalation using this exact role/scope value",
                const, "auth-model.json",
            ))

    api_calls = _read_browser_json(recon_dir, "api-calls.json")
    if api_calls:
        for call in api_calls.get("calls", []) or []:
            if not isinstance(call, dict) or not call.get("url"):
                continue
            if call.get("request_headers_auth"):
                _route_url(call["url"], "api-calls.json")

    return leads


# ─── Attack graph -> concrete leads (Phase 4 batch 2) ──────────────────────
#
# memory/attack_graph.py builds a typed capability graph from lead-board
# leads + browser intelligence + Phase 3 tech modifiers, path-searches it,
# and scores each path — but a graph is not itself an executable plan
# candidate. attack_graph_leads() is the SAME wrapper pattern as
# browser_intel_leads() just above: pure, best-effort, never raises on
# missing/malformed recon data, no new candidate type or scoring path.
# build_plan() concatenates its output alongside board_leads/bi_leads and
# scores every lead identically via _score_lead() — see build_plan() below.
#
# Imported lazily (function-local, not module-level) because
# memory/attack_graph.py itself imports `from tools import director` (it
# reuses skill_to_vuln_class()/_read_browser_json() from this module) — a
# module-level import here would be circular.


def attack_graph_leads(target: str, recon_dir: str, memory_dir: str | None = None) -> list[dict]:
    """Wraps memory.attack_graph.build_capability_graph() + top_paths()
    into lead-board-shaped candidates. Never raises on missing/malformed
    recon data (build_capability_graph()'s own file reads already are
    best-effort — see its docstring); a target with no recon/leads/browser
    intelligence yet just yields [], same as browser_intel_leads()."""
    from memory import attack_graph as ag  # local import: avoid the circular import noted above

    tech_stack = load_tech_stack(target, memory_dir) if memory_dir is not None else []
    tech_attack_matrix = load_fingerprint_tech_attack_matrix(target, recon_dir)
    graph = ag.build_capability_graph(
        target, recon_dir=recon_dir, tech_stack=tech_stack, tech_attack_matrix=tech_attack_matrix,
    )
    return ag.top_paths(target, graph)


# ─── Risk level (static heuristic tier — NOT a measured value) ─────────────

# Skills whose test plan implies an authenticated session is needed at all.
_AUTH_REQUIRED_SKILLS = {
    "hunt-ato", "hunt-auth-bypass", "hunt-oauth", "hunt-saml", "hunt-mfa-bypass",
    "hunt-idor", "hunt-api-misconfig", "hunt-business-logic",
}
# Skills whose test plan implies many requests (enumeration) rather than one probe.
_ENUMERATION_SKILLS = {"hunt-idor", "hunt-auth-bypass", "hunt-ato"}
# Sources that are already-observed signals — at most a single confirmatory
# check, never active probing of the target.
_PASSIVE_SOURCES = {"tech", "nuclei", "ai"}
_MUTATING_HINT_RE = re.compile(r"upload|delete|reset|change|invalidate|revoke|spray", re.I)


def risk_level_for(skill: str, source: str, evidence: str) -> str:
    """LOW/MEDIUM/HIGH heuristic tier. NOT a measured or predicted value —
    see module docstring for why no numeric detection_risk field exists.
    Buckets on three attributes Director already has: passive observation
    vs. active requests, whether the skill implies an authenticated
    session, and whether it implies enumeration or a mutating action
    rather than a single read-only probe."""
    if source in _PASSIVE_SOURCES:
        return "LOW"
    needs_auth = skill in _AUTH_REQUIRED_SKILLS
    high_volume = skill in _ENUMERATION_SKILLS or bool(_MUTATING_HINT_RE.search(evidence or ""))
    if needs_auth and high_volume:
        return "HIGH"
    if needs_auth or high_volume:
        return "MEDIUM"
    return "LOW"


# ─── Falsifiers / success conditions ───────────────────────────────────────
# New authored content — this is the Director's actual job (the spec gives
# the IDOR example verbatim; no falsifier library exists anywhere else to
# reuse). Generic fallback covers any vuln_class not listed.

FALSIFIER_TEMPLATES: dict[str, str] = {
    "idor": "Dead if: no authorization difference after testing 15 representative "
            "objects/IDs across at least 2 privilege levels within 20 minutes.",
    "ssrf": "Dead if: no out-of-band callback and no internal-only response body "
            "difference after 10 payload variants (DNS, internal IP, cloud metadata) within 15 minutes.",
    "xss": "Dead if: payload is not reflected unescaped in a script-executable "
           "sink after 10 context variants (attribute, tag, JS string) within 15 minutes.",
    "sqli": "Dead if: no boolean/time-based/error-based differential after 10 "
            "payload variants across every parameter within 20 minutes.",
    "graphql": "Dead if: introspection is disabled or reveals nothing exploitable, "
               "AND no auth-bypass on a sensitive mutation/query within 20 minutes.",
    "ssti": "Dead if: no template-expression evaluation (e.g. 7*7 -> 49) after 8 "
            "engine-specific payload variants within 15 minutes.",
    "oauth": "Dead if: redirect_uri validation, state, and PKCE all enforce correctly "
             "on 5 bypass attempts within 25 minutes.",
    "saml": "Dead if: signature validation holds against XSW/wrapping/comment-injection "
            "variants after 5 attempts within 30 minutes.",
    "ato": "Dead if: no account-recovery/reset/OTP weakness reproduces after 5 "
           "attempts within 25 minutes.",
    "auth-bypass": "Dead if: every sibling endpoint in the same controller enforces "
                   "authorization correctly after 10 checks within 20 minutes.",
    "file-upload": "Dead if: no bypass (extension/MIME/magic-byte/path) lands an "
                   "executable or stored-XSS-capable file after 8 attempts within 20 minutes.",
    "xxe": "Dead if: no external entity resolves (OOB or in-band) after 5 payload "
           "variants within 15 minutes.",
    "cors": "Dead if: ACAO does not reflect an arbitrary origin with credentials "
            "allowed after 3 checks within 10 minutes.",
    "open-redirect": "Dead if: redirect target cannot be fully attacker-controlled "
                      "(scheme+host) after 5 encoding variants within 10 minutes.",
    "misconfig": "Dead if: no exploitable misconfiguration confirmed (not just "
                 "present-but-hardened) after 15 minutes.",
    "info-disclosure": "Dead if: disclosed data has no exploitable sensitivity "
                        "(secrets, PII, internal topology) after 10 minutes.",
    "race-condition": "Dead if: no state inconsistency across 20 concurrent requests "
                       "within 15 minutes.",
}
_DEFAULT_FALSIFIER = ("Dead if: no working proof-of-concept after the maximum time "
                       "budget below, with at least 3 independent technique variants tried.")


def falsifier_for(vuln_class: str) -> str:
    return FALSIFIER_TEMPLATES.get(vuln_class, _DEFAULT_FALSIFIER)


_SUCCESS_TEMPLATES: dict[str, str] = {
    "idor": "Authenticated-as-user-A request returns/mutates user-B's object with no ownership check.",
    "ssrf": "Server-side request reaches an attacker-controlled or internal-only endpoint from a user-supplied URL.",
    "xss": "Attacker-controlled script executes in another user's session/origin.",
    "sqli": "Injected input changes query logic (boolean/time/error/UNION) provably.",
    "graphql": "Introspection or a mutation returns/mutates data outside the caller's authorization.",
    "ssti": "Server evaluates an injected template expression.",
    "oauth": "Authorization code or token is obtained for a victim account without their consent.",
    "saml": "A forged/altered assertion is accepted as valid by the service provider.",
    "ato": "Full control of another account obtained via the recovery/reset/OTP flow.",
    "auth-bypass": "A privileged action/endpoint succeeds without the required role/session.",
    "file-upload": "An uploaded file executes server-side or renders as stored XSS.",
    "xxe": "An external entity resolves and discloses local/internal data.",
    "cors": "A cross-origin credentialed request exfiltrates authenticated data.",
    "open-redirect": "Redirect target is fully attacker-controlled and chains to a real impact (OAuth/session theft).",
    "misconfig": "The misconfiguration is shown to grant access/data beyond intended scope.",
    "info-disclosure": "Disclosed data is sensitive enough to enable a further attack.",
    "race-condition": "Concurrent requests produce a state outcome impossible under correct locking.",
}
_DEFAULT_SUCCESS = "A working, reproducible proof-of-concept demonstrates real impact beyond the vuln class's baseline."


def success_for(vuln_class: str) -> str:
    return _SUCCESS_TEMPLATES.get(vuln_class, _DEFAULT_SUCCESS)


# ─── Attack / Plan model ────────────────────────────────────────────────────


@dataclass
class Attack:
    """estimated_execution_cost_minutes and maximum_time_minutes are
    deliberately the same number (both TESTING_TIME_ESTIMATES[vuln_class],
    the same static prior expected_value_per_hour() already uses) — this
    codebase has no separate request-count/CPU cost model to draw a
    different "execution cost" from, so both fields expose the identical
    reused value rather than one of them being invented."""

    id: str
    lead_id: str
    vuln_class: str
    skill: str
    priority: int
    ev_per_hour: float
    ev_label: str
    state: str = "PENDING"
    confidence: float | None = None
    confidence_note: str = "no informative signal yet — technology_match floor"
    calibrated_confidence: float | None = None
    calibration_note: str = "No calibration data available."
    risk_level: str = "LOW"
    dependencies: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    falsifier: str = ""
    success: str = ""
    stop_condition: str = ""
    minimum_time_minutes: float = MINIMUM_TIME_MINUTES
    maximum_time_minutes: float = DEFAULT_TESTING_TIME_MINUTES
    hard_cutoff_minutes: float = DEFAULT_TESTING_TIME_MINUTES
    estimated_execution_cost_minutes: float = DEFAULT_TESTING_TIME_MINUTES
    why: str = ""
    source: str = "lead-board"
    parallel_group: str = ""
    hard_kill: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(data: dict) -> "Attack":
        # Attack is a flat dataclass (no nested dataclass fields) and
        # to_dict() is a plain asdict() -- data's keys already match the
        # field names exactly, so reconstruction is a direct kwargs
        # unpack, not a bespoke per-field mapping to drift out of sync.
        return Attack(**data)


@dataclass
class Plan:
    target: str
    total_budget_hours: float
    attacks: list[Attack] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    checkpoints: list[str] = field(default_factory=list)
    summary: str = ""
    generated_at: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "total_budget_hours": self.total_budget_hours,
            "attacks": [a.to_dict() for a in self.attacks],
            "skipped": self.skipped,
            "checkpoints": self.checkpoints,
            "summary": self.summary,
            "generated_at": self.generated_at,
        }

    @staticmethod
    def from_dict(data: dict) -> "Plan":
        return Plan(
            target=data["target"],
            total_budget_hours=data["total_budget_hours"],
            attacks=[Attack.from_dict(a) for a in data.get("attacks", [])],
            skipped=data.get("skipped", []),
            checkpoints=data.get("checkpoints", []),
            summary=data.get("summary", ""),
            generated_at=data.get("generated_at", ""),
        )


def save_plan(plan: Plan, path: str) -> str:
    """JSON sidecar for replan() across process boundaries. hunt-plan.md
    stays the human-readable artifact for a hunter to read; this is the
    separate machine-readable one replan() actually needs when build-plan
    and replan run as two different CLI invocations instead of sharing one
    in-process Plan object. Plain json.dumps(plan.to_dict()) — the same
    to_dict() build-plan already prints to stdout, just persisted."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(plan.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(out_path)


def load_plan(path: str) -> Plan:
    """Inverse of save_plan() — round-trips to an equal Plan (see
    tests/test_director.py's TestPlanPersistence for the round-trip
    proof)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Plan.from_dict(data)


def default_plan_path(target: str, recon_dir: str | None = None) -> str:
    """Same recon/<target>/ convention hunt-plan.md already uses — the
    JSON sidecar sits right next to it as hunt-plan.json."""
    recon_dir = recon_dir if recon_dir is not None else os.path.join("recon", target)
    return str(Path(recon_dir) / "hunt-plan.json")


DEFAULT_CHECKPOINTS = [
    "After 30 minutes — re-check EV/hour ordering against anything discovered so far",
    "After first authentication success — unblock every dependent attack gated on auth",
    "After browser intelligence exhausted — re-ingest lead board, look for new never-called endpoints",
    "After first confirmed finding — reprioritize chains/hypotheses that build on it",
]

# expected_value_per_hour()'s own "Low" cutoff (< 25 ev/hr) — reused as the
# floor instead of inventing a new threshold.
_EV_FLOOR_LABEL = "Low"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _has_affinity_signal(vuln_class: str, tech_stack: list[str], patterns: list[dict],
                          failed_patterns: list[dict]) -> bool:
    """Replicates priority_score()'s own internal branch condition for
    "do we actually have memory data here" — calls the exact same public
    tech_vuln_affinity() priority_score() calls internally, with the same
    inputs, and applies the identical `affinity and wins+losses > 0` test.
    Not a new formula: this inspects an existing function's decision
    boundary instead of guessing "no data" from priority_score()'s output
    values, which would be fragile (technology_match's heuristic floor,
    20, is a value real affinity data could theoretically also produce)."""
    affinity_list = tech_vuln_affinity(tech_stack, patterns, failed_patterns)
    affinity = next((a for a in affinity_list if a["vuln_class"] == vuln_class), None)
    return bool(affinity and (affinity["wins"] + affinity["losses"]) > 0)


def _confidence_for(score_result: dict, has_signal: bool) -> tuple[float | None, str]:
    """priority_score()'s own technology_match component (0-100) as a
    confidence proxy — but ONLY when tech_vuln_affinity() actually found
    matching pattern/failed_pattern data for this vuln_class (has_signal).
    When it didn't, technology_match is just the hard-coded heuristic
    floor (20) priority_score() falls back to — indistinguishable, at
    that exact value, from a genuinely weak affinity score. Returning the
    floor as "confidence" would read as real signal when it's actually
    "we know nothing yet", so this returns None + an explicit note
    instead, the same treatment calibrated_confidence already gets on
    cold start. Not a new formula: recon-ranker.md's prose confidence
    bonus for matching memory patterns/chains/hypotheses is already
    folded into priority_score()'s technology_match and
    attack_chain_probability components, so a separate recomputation
    here would double-count the same signal instead of adding a new one."""
    if not has_signal:
        return None, "no informative signal yet — technology_match floor"
    return (
        float(score_result["components"]["technology_match"]),
        "technology_match component from tech_vuln_affinity() (memory-backed)",
    )


def _calibrate_confidence(confidence: float, calibration: dict) -> tuple[float | None, str]:
    """Clamp `confidence` against hypothesis_calibration()'s bucketed
    actual-hit-rate data instead of trusting the stated number blindly.
    Falls back to "No calibration data available." per-bucket (not just
    globally) when that bucket has zero resolved hypotheses yet — never
    fabricates a number to fill the gap."""
    for bucket in calibration.get("buckets", []):
        lo, hi = (int(x) for x in bucket["confidence_bucket"].split("-"))
        if lo <= confidence < hi:
            if bucket["resolved_count"] > 0 and bucket["actual_hit_rate"] is not None:
                return (
                    float(bucket["actual_hit_rate"]),
                    f"calibrated from {bucket['resolved_count']} resolved hypothesis "
                    f"outcome(s) in the {bucket['confidence_bucket']} confidence bucket "
                    f"(stated avg {bucket['stated_confidence_avg']}, gap {bucket['calibration_gap']})",
                )
            return None, "No calibration data available."
    return None, "No calibration data available."


def _stop_condition_for(vuln_class: str, maximum_minutes: float) -> str:
    return (
        f"should_stop() rule (memory/experiment_memory.py): abandon after "
        f"{MINIMUM_TIME_MINUTES:.0f} min elapsed with 0 successes, OR 3 payload "
        f"categories exhausted with 0 successes, OR {maximum_minutes:.0f} min "
        f"(this vuln class's estimated cost) reached — whichever comes first. "
        f"A single success always overrides the clock."
    )


class Director:
    """Converts lead-board + browser-intelligence leads into an executable,
    time-boxed, falsifiable research plan. Computes zero scores of its own
    — see module docstring."""

    def __init__(self, memory_dir: str = "hunt-memory"):
        self.memory_dir = memory_dir

    # ── plan construction ───────────────────────────────────────────────

    def build_plan(self, target: str, hours: float, memory_dir: str | None = None,
                    recon_dir: str | None = None) -> Plan:
        if hours <= 0:
            raise ValueError("hours must be positive")
        memory_dir = memory_dir if memory_dir is not None else self.memory_dir
        recon_dir = recon_dir if recon_dir is not None else os.path.join("recon", target)

        mem = load_memory(memory_dir)
        tech_stack = load_tech_stack(target, memory_dir)
        tech_attack_matrix = load_fingerprint_tech_attack_matrix(target, recon_dir)
        calibration = hypothesis_calibration(
            [h for h in mem["hypotheses"] if h.get("target") == target],
            journal_entries=mem["journal"], report_outcomes=mem["report_outcomes"],
        )

        board_leads = lead_board.load_ledger(target)
        board_leads = [ld for ld in board_leads if ld.get("status") == "new"]
        bi_leads = browser_intel_leads(target, recon_dir)
        graph_leads = attack_graph_leads(target, recon_dir, memory_dir)
        all_leads = board_leads + bi_leads + graph_leads

        candidates: list[dict] = []
        for lead in all_leads:
            candidates.append(self._score_lead(lead, target, tech_stack, mem, tech_attack_matrix))

        # Highest EV/hour first (ties broken by priority score) — this is
        # "maximize expected value per hour", the Director's stated goal,
        # not just raw priority.
        candidates.sort(key=lambda c: (c["ev_result"]["ev_per_hour"], c["score_result"]["score"]),
                         reverse=True)

        budget_minutes_remaining = hours * 60.0
        attacks: list[Attack] = []
        skipped: list[dict] = []
        attack_by_lead_id: dict[str, Attack] = {}

        for c in candidates:
            reason = self._skip_reason(c, budget_minutes_remaining)
            if reason is not None:
                skipped.append({
                    "lead_id": c["lead"]["id"],
                    "skill": c["lead"]["skill"],
                    "vuln_class": c["vuln_class"],
                    "evidence": c["lead"].get("evidence", ""),
                    "reason": reason,
                    "detail": c["skip_detail"],
                })
                continue

            attack = self._build_attack(c, calibration)
            budget_minutes_remaining -= attack.maximum_time_minutes
            attacks.append(attack)
            attack_by_lead_id[c["lead"]["id"]] = attack

        # Cascading DEPENDENCY_UNMET: a chain/hypothesis attack whose
        # prerequisite lead was itself skipped (for ANY reason above) can
        # never become READY. Move it into skipped[] with its own machine-
        # checkable reason instead of leaving it stuck in attacks[]
        # forever — this is what actually populates the DEPENDENCY_UNMET
        # skip reason the spec requires. Loops to a fixed point so a
        # 3-deep chain (A -> B -> C) cascades correctly if the middle leg
        # is the one that got skipped.
        changed = True
        while changed:
            changed = False
            survivors = []
            for attack in attacks:
                unmet = [dep for dep in attack.dependencies if dep not in attack_by_lead_id]
                if unmet:
                    skipped.append({
                        "lead_id": attack.lead_id, "skill": attack.skill,
                        "vuln_class": attack.vuln_class, "evidence": "; ".join(attack.evidence),
                        "reason": "DEPENDENCY_UNMET",
                        "detail": f"prerequisite lead(s) not present in this plan: {unmet}",
                    })
                    del attack_by_lead_id[attack.lead_id]
                    changed = True
                else:
                    survivors.append(attack)
            attacks = survivors

        self._resolve_dependencies(attacks)
        self._assign_parallel_groups(attacks)

        if not all_leads:
            summary_skip_note = ("No leads found for this target at all (empty lead board and no "
                                  "browser intelligence) — nothing to plan or skip yet. Run recon / "
                                  "lead_board.py ingest first.")
        elif not skipped:
            summary_skip_note = ("SUSPICIOUS: nothing was skipped — either the lead "
                                  "board is unusually small/clean or the skip "
                                  "classifier under-fired. Investigate before trusting this plan.")
        else:
            summary_skip_note = f"{len(skipped)} lead(s) skipped (see skipped[])."

        plan = Plan(
            target=target,
            total_budget_hours=hours,
            attacks=attacks,
            skipped=skipped,
            checkpoints=list(DEFAULT_CHECKPOINTS),
            summary=(
                f"{len(attacks)} attack(s) planned across {hours}h budget "
                f"({budget_minutes_remaining / 60.0:.2f}h unallocated). {summary_skip_note}"
            ),
            generated_at=_now_iso(),
        )
        self._last_plan_context = {"target": target, "memory_dir": memory_dir,
                                    "recon_dir": recon_dir, "candidates": candidates}
        return plan

    def _score_lead(self, lead: dict, target: str, tech_stack: list[str], mem: dict,
                     tech_attack_matrix: dict | None = None) -> dict:
        vuln_class = skill_to_vuln_class(lead["skill"])
        score_result = priority_score(
            vuln_class=vuln_class, tech_stack=tech_stack, target=target,
            technique=None, patterns=mem["patterns"], failed_patterns=mem["failed_patterns"],
            chains=mem["chains"], chain_detected=(lead.get("source") == "hypothesis"),
            report_outcomes=mem["report_outcomes"], tech_attack_matrix=tech_attack_matrix,
        )
        ev_result = expected_value_per_hour(
            vuln_class=vuln_class, tech_stack=tech_stack, target=target,
            technique=None, patterns=mem["patterns"], failed_patterns=mem["failed_patterns"],
            chains=mem["chains"], chain_detected=(lead.get("source") == "hypothesis"),
            report_outcomes=mem["report_outcomes"], tech_attack_matrix=tech_attack_matrix,
        )
        dup_check = duplicate_or_noise_check(
            target=target, vuln_class=vuln_class, endpoint=lead.get("evidence", ""),
            journal_entries=mem["journal"], report_outcomes=mem["report_outcomes"],
            failed_patterns=mem["failed_patterns"],
        )
        has_signal = _has_affinity_signal(vuln_class, tech_stack, mem["patterns"], mem["failed_patterns"])
        return {
            "lead": lead, "vuln_class": vuln_class, "score_result": score_result,
            "ev_result": ev_result, "dup_check": dup_check, "has_signal": has_signal, "skip_detail": "",
        }

    def _skip_reason(self, c: dict, budget_minutes_remaining: float) -> str | None:
        lead = c["lead"]
        ev_result = c["ev_result"]
        dup_check = c["dup_check"]

        if dup_check["is_duplicate"]:
            c["skip_detail"] = f"already found/reported: {dup_check['matching_report_outcomes']}"
            return "DUPLICATE"
        if dup_check["is_noise"] or c["score_result"]["hard_kill"]:
            c["skip_detail"] = c["score_result"].get("failed_pattern_reason") or "matches failed_patterns.jsonl"
            return "MATCHES_FAILED_PATTERN"
        if ev_result["ev_label"] == _EV_FLOOR_LABEL:
            c["skip_detail"] = f"ev/hr {ev_result['ev_per_hour']} below floor (label={_EV_FLOOR_LABEL})"
            return "BELOW_EV_FLOOR"
        if lead.get("priority") == "low" and lead.get("source") not in ("chain", "hypothesis", "nuclei"):
            c["skip_detail"] = "low-priority, unconfirmed, no chain/hypothesis correlation"
            return "INSUFFICIENT_EVIDENCE"
        estimated_minutes = ev_result["estimated_minutes"]
        if estimated_minutes > budget_minutes_remaining:
            c["skip_detail"] = (f"needs {estimated_minutes} min, only "
                                 f"{budget_minutes_remaining:.0f} min left in budget")
            return "TIME_CONSTRAINT"
        return None

    def _build_attack(self, c: dict, calibration: dict) -> Attack:
        lead = c["lead"]
        vuln_class = c["vuln_class"]
        score_result = c["score_result"]
        ev_result = c["ev_result"]
        maximum_minutes = float(ev_result["estimated_minutes"])
        confidence, confidence_note = _confidence_for(score_result, c["has_signal"])
        if confidence is None:
            # Nothing to calibrate against if there's no base confidence
            # to begin with — stay consistent with the "no data" story
            # instead of calibrating a floor value that isn't real signal.
            calibrated_confidence, calibration_note = None, "No calibration data available."
        else:
            calibrated_confidence, calibration_note = _calibrate_confidence(confidence, calibration)

        evidence_lines = [lead.get("evidence", ""), lead.get("signal", "")]
        if lead.get("source") == "browser-intel":
            evidence_lines.append(f"browser-intel artifact: {lead.get('browser_artifact', '?')}")
        if score_result["matching_chains"]:
            evidence_lines.append(f"matching confirmed chains: {score_result['matching_chains']}")

        dependencies = list(lead.get("chain_of", [])) if lead.get("source") in ("chain", "hypothesis") else []

        return Attack(
            id="atk-" + secrets.token_hex(3),
            lead_id=lead["id"],
            vuln_class=vuln_class,
            skill=lead["skill"],
            priority=score_result["score"],
            ev_per_hour=ev_result["ev_per_hour"],
            ev_label=ev_result["ev_label"],
            state="PENDING" if dependencies else "READY",
            confidence=confidence,
            confidence_note=confidence_note,
            calibrated_confidence=calibrated_confidence,
            calibration_note=calibration_note,
            risk_level=risk_level_for(lead["skill"], lead.get("source", ""), lead.get("evidence", "")),
            dependencies=dependencies,
            evidence=[e for e in evidence_lines if e],
            falsifier=falsifier_for(vuln_class),
            success=success_for(vuln_class),
            stop_condition=_stop_condition_for(vuln_class, maximum_minutes),
            minimum_time_minutes=MINIMUM_TIME_MINUTES,
            maximum_time_minutes=maximum_minutes,
            hard_cutoff_minutes=maximum_minutes,
            estimated_execution_cost_minutes=maximum_minutes,
            why=lead.get("why", ""),
            source=lead.get("source", "lead-board"),
            hard_kill=score_result["hard_kill"],
        )

    def _resolve_dependencies(self, attacks: list[Attack]) -> None:
        """A chain/hypothesis attack's dependencies are the OTHER leads'
        lead_ids in its chain_of. Translate lead_id -> attack_id now that
        build_plan()'s cascading DEPENDENCY_UNMET prune has already
        guaranteed every remaining dependency resolves to a surviving
        attack (the `unmet`/BLOCKED branch below is a defensive fallback
        for any future caller of this method that skips that prune)."""
        lead_id_to_attack_id = {a.lead_id: a.id for a in attacks}
        for attack in attacks:
            if not attack.dependencies:
                continue
            resolved = [lead_id_to_attack_id[dep] for dep in attack.dependencies if dep in lead_id_to_attack_id]
            unmet = [dep for dep in attack.dependencies if dep not in lead_id_to_attack_id]
            attack.dependencies = resolved
            if unmet:
                attack.state = "BLOCKED"
                attack.notes.append(f"prerequisite lead(s) not in this plan (pruned/skipped): {unmet}")
            elif resolved:
                attack.state = "PENDING"
            else:
                attack.state = "READY"

    def _assign_parallel_groups(self, attacks: list[Attack]) -> None:
        """Groups attacks that can safely run at the same time: same
        attack-surface shape (browser-only / passive / api-active) crossed
        with auth requirement. Purely descriptive bucketing over the lead's
        own `source` field (browser-intel vs. already-observed tech/nuclei/
        ai signals vs. everything that sends a live probe) — not a new
        scoring pass, and deliberately not derived from risk_level, which
        answers a different question (how loud is this probe) than surface
        (does this probe send a request at all). Two attacks in the same
        group are safe to run concurrently; different groups may still be
        fine, this just guarantees the same-group ones are."""
        for attack in attacks:
            if attack.source == "browser-intel":
                surface = "browser-only"
            elif attack.source in ("tech", "nuclei", "ai"):
                surface = "passive"
            else:
                surface = "api-active"
            auth = "authenticated" if attack.skill in _AUTH_REQUIRED_SKILLS else "unauthenticated"
            attack.parallel_group = f"{surface}/{auth}"

    def should_stop_now(self, attack: Attack, experiments_for_endpoint: list[dict],
                         elapsed_minutes: float) -> dict:
        """Passthrough to memory.experiment_memory.should_stop() using this
        attack's own minimum_time_minutes as the minute_limit — the actual
        mid-hunt stop/pivot decision once testing on this attack has
        started. Director never calls this itself during build_plan()/
        replan() (it has no elapsed_minutes at planning time); it's
        exposed here so whatever executes the plan doesn't reimplement
        the 5-minute rule."""
        return should_stop(experiments_for_endpoint, elapsed_minutes,
                            minute_limit=attack.minimum_time_minutes)

    # ── replanning ───────────────────────────────────────────────────────

    def replan(self, plan: Plan, results_so_far: dict) -> Plan:
        """results_so_far: {"completed": [attack_id, ...], "failed": [...],
        "abandoned": [...], "in_progress": [...], "notes": {attack_id: "..."},
        "revive": [attack_id, ...]} (all optional). Preserves IN_PROGRESS
        attacks untouched, never discards a COMPLETED/FAILED/ABANDONED
        attack's history, re-scores only what's left PENDING/READY/WAITING/
        BLOCKED, and unlocks dependents whose prerequisites just completed.
        Abandoned work stays abandoned unless its id is explicitly listed
        in `revive`."""
        results_so_far = results_so_far or {}
        completed = set(results_so_far.get("completed", []))
        failed = set(results_so_far.get("failed", []))
        abandoned = set(results_so_far.get("abandoned", []))
        in_progress = set(results_so_far.get("in_progress", []))
        revive = set(results_so_far.get("revive", []))
        note_updates = results_so_far.get("notes", {}) or {}

        by_id = {a.id: a for a in plan.attacks}
        for attack_id, note in note_updates.items():
            if attack_id in by_id:
                by_id[attack_id].notes.append(note)

        for attack in plan.attacks:
            if attack.id in completed:
                attack.state = "COMPLETED"
            elif attack.id in failed:
                attack.state = "FAILED"
            elif attack.id in abandoned and attack.id not in revive:
                attack.state = "ABANDONED"
            elif attack.id in revive and attack.state == "ABANDONED":
                attack.state = "READY" if not attack.dependencies else "PENDING"
            elif attack.id in in_progress:
                attack.state = "IN_PROGRESS"
            # Anything not mentioned keeps its current state untouched —
            # IN_PROGRESS work is never silently reset.

        completed_ids = {a.id for a in plan.attacks if a.state == "COMPLETED"}
        for attack in plan.attacks:
            if attack.state in ("PENDING", "BLOCKED") and attack.dependencies:
                if all(dep in completed_ids for dep in attack.dependencies):
                    attack.state = "READY"

        remaining_minutes = plan.total_budget_hours * 60.0
        for attack in plan.attacks:
            if attack.state in ("IN_PROGRESS", "COMPLETED"):
                remaining_minutes -= attack.maximum_time_minutes

        still_open = [a for a in plan.attacks if a.state in ("READY", "PENDING", "WAITING")]
        still_open.sort(key=lambda a: (a.ev_per_hour, a.priority), reverse=True)

        newly_skipped = []
        kept_open: list[Attack] = []
        for attack in still_open:
            if attack.state == "READY" and attack.maximum_time_minutes > remaining_minutes:
                attack.state = "SKIPPED"
                newly_skipped.append({
                    "lead_id": attack.lead_id, "skill": attack.skill, "vuln_class": attack.vuln_class,
                    "evidence": attack.evidence, "reason": "TIME_CONSTRAINT",
                    "detail": f"needs {attack.maximum_time_minutes} min, "
                              f"{remaining_minutes:.0f} min left after replan",
                })
                continue
            if attack.state == "READY":
                remaining_minutes -= attack.maximum_time_minutes
            kept_open.append(attack)

        plan.skipped = plan.skipped + newly_skipped
        plan.summary = (
            f"replanned: {sum(1 for a in plan.attacks if a.state == 'COMPLETED')} completed, "
            f"{sum(1 for a in plan.attacks if a.state == 'IN_PROGRESS')} in progress, "
            f"{sum(1 for a in plan.attacks if a.state == 'READY')} ready, "
            f"{len(newly_skipped)} newly skipped (time constraint)."
        )
        plan.generated_at = _now_iso()
        return plan

    # ── explanation ──────────────────────────────────────────────────────

    def explain(self, lead_id: str) -> str:
        """Why THIS lead outranked alternatives — not what the vuln class
        is. Requires build_plan() to have been called first on self."""
        ctx = getattr(self, "_last_plan_context", None)
        if ctx is None:
            return "No plan built yet — call build_plan() first."
        candidates = ctx["candidates"]
        match = next((c for c in candidates if c["lead"]["id"] == lead_id), None)
        if match is None:
            return f"No lead {lead_id!r} in the last build_plan() call."

        lead = match["lead"]
        score_result = match["score_result"]
        ev_result = match["ev_result"]
        components = score_result["components"]

        lines = [f"Lead {lead_id} ({lead['skill']}, vuln_class={match['vuln_class']}):"]
        lines.append(f"  Evidence: {lead.get('evidence', '(none)')}")
        lines.append(f"  Signal: {lead.get('signal', '?')} — {lead.get('why', '?')}")
        if lead.get("source") == "browser-intel":
            lines.append(f"  Produced by browser intelligence: {lead.get('browser_artifact', '?')}")
        elif lead.get("source") in ("chain", "hypothesis"):
            lines.append(f"  Correlated from leads: {lead.get('chain_of', [])} (source={lead['source']})")
        elif lead.get("source") == "attack-graph":
            # memory/attack_graph.py's top_paths() (Phase 4) — explain WHY
            # this multi-leg path exists, not just what vuln class it is:
            # weakest link, strongest evidence, every leg's assumption, and
            # what observation would kill it. path_legs (added to
            # top_paths()'s output shape in batch 2 specifically so this
            # can render without re-walking the graph) carries the
            # per-edge confidence/origin/contradiction detail.
            legs = lead.get("path_legs") or []
            lines.append(
                f"  Attack-graph path (memory/attack_graph.py): {len(legs)}-leg path, "
                f"path_score={lead.get('path_score', '?')}."
            )
            if legs:
                weakest = min(legs, key=lambda leg: leg["confidence"])
                strongest = max(legs, key=lambda leg: leg["confidence"])
                weak_line = (
                    f"  Weakest link: {weakest['from']} -({weakest['edge_type']})-> {weakest['to']} "
                    f"(confidence {weakest['confidence']}, origin={weakest['origin_source']})"
                )
                if weakest.get("contradiction"):
                    weak_line += f" — CONTRADICTED: {weakest['contradiction']}"
                lines.append(weak_line)
                lines.append(
                    f"  Strongest evidence: {strongest['from']} -({strongest['edge_type']})-> "
                    f"{strongest['to']} (confidence {strongest['confidence']}, "
                    f"origin={strongest['origin_source']})"
                )
                assumptions = sorted({leg["origin_source"] for leg in legs})
                lines.append(
                    f"  Assumptions required (every leg's origin must independently hold): {assumptions}"
                )
            if lead.get("chain_of"):
                lines.append(f"  Built from underlying lead(s): {lead['chain_of']}")
            lines.append(
                f"  Stopping condition (what invalidates this path): if any leg's origin artifact "
                f"is re-checked and no longer holds (e.g. a `grants` leg's target now correctly "
                f"401/403s), OR: {_stop_condition_for(match['vuln_class'], ev_result['estimated_minutes'])}"
            )
        lines.append(
            f"  Historical success rate on this tech stack: {components['historical_success_probability']}% "
            f"(sample-backed only if patterns/failed_patterns exist for this target+vuln_class)."
        )
        lines.append(f"  Tech-stack match confidence: {components['technology_match']}.")
        if score_result["matching_chains"]:
            lines.append(f"  Matches confirmed chain(s) from other targets: {score_result['matching_chains']}.")
        lines.append(
            f"  Ranked by EV/hour ({ev_result['ev_per_hour']}, {ev_result['payout_probability_source']}), "
            f"not raw priority score alone — this is why a lower-priority-but-faster candidate can rank above "
            f"a higher-priority-but-slower one."
        )
        others = [c for c in candidates if c["lead"]["id"] != lead_id]
        higher = sorted(
            (c for c in others if c["ev_result"]["ev_per_hour"] > ev_result["ev_per_hour"]),
            key=lambda c: c["ev_result"]["ev_per_hour"], reverse=True,
        )
        if higher:
            top = higher[0]
            lines.append(
                f"  Outranked by lead {top['lead']['id']} ({top['lead']['skill']}, "
                f"ev/hr {top['ev_result']['ev_per_hour']})."
            )
        else:
            lines.append("  This is the top-ranked candidate in the last plan (highest EV/hour).")
        return "\n".join(lines)

    # ── confidence ───────────────────────────────────────────────────────

    def confidence(self, plan: Plan) -> dict:
        """Passes through hypothesis_calibration() when calibration data
        exists. Cold start (no hypotheses.jsonl data resolved yet) states
        that explicitly instead of inventing a number."""
        ctx = getattr(self, "_last_plan_context", None)
        if ctx is None:
            return {"available": False, "message": "No calibration data available."}
        mem = load_memory(ctx["memory_dir"])
        hypotheses = [h for h in mem["hypotheses"] if h.get("target") == plan.target]
        calibration = hypothesis_calibration(
            hypotheses, journal_entries=mem["journal"], report_outcomes=mem["report_outcomes"],
        )
        resolved_buckets = [b for b in calibration["buckets"] if b["resolved_count"] > 0]
        if not resolved_buckets:
            return {
                "available": False,
                "message": "No calibration data available.",
                "raw_buckets": calibration["buckets"],
            }
        overall_gap = sum(b["calibration_gap"] for b in resolved_buckets if b["calibration_gap"] is not None)
        overall_gap = round(overall_gap / len(resolved_buckets), 1) if resolved_buckets else None
        return {
            "available": True,
            "buckets": calibration["buckets"],
            "overall_calibration_gap": overall_gap,
            "message": (
                f"Calibration based on {sum(b['resolved_count'] for b in resolved_buckets)} resolved "
                f"hypothesis outcome(s) across {len(resolved_buckets)} confidence bucket(s)."
            ),
        }

    # ── rendering ────────────────────────────────────────────────────────

    def render_markdown(self, plan: Plan) -> str:
        lines = [f"# Hunt Plan: {plan.target}", "", plan.summary, "",
                 f"Generated: {plan.generated_at} | Budget: {plan.total_budget_hours}h", ""]

        lines.append("## Planned Attacks")
        if not plan.attacks:
            lines.append("(none — every lead was skipped, see below)")
        for a in sorted(plan.attacks, key=lambda x: x.ev_per_hour, reverse=True):
            lines.append(f"\n### {a.id} — {a.vuln_class} ({a.skill})")
            lines.append(f"- Lead: {a.lead_id}")
            lines.append(f"- WHY: {a.why or '(no why recorded)'}")
            lines.append(f"- Evidence: {'; '.join(a.evidence) if a.evidence else '(none)'}")
            lines.append(f"- Priority: {a.priority} | EV/Hour: {a.ev_per_hour} ({a.ev_label})")
            cal = (f"{a.calibrated_confidence}" if a.calibrated_confidence is not None
                   else "No calibration data available.")
            conf = f"{a.confidence}" if a.confidence is not None else "None"
            lines.append(f"- Confidence: {conf} ({a.confidence_note}) | Calibrated confidence: {cal}")
            lines.append(f"- Risk level: {a.risk_level} (heuristic tier, not measured)")
            lines.append(f"- Time budget: {a.minimum_time_minutes}-{a.maximum_time_minutes} min "
                         f"(hard cutoff {a.hard_cutoff_minutes} min, estimated execution cost "
                         f"{a.estimated_execution_cost_minutes} min)")
            lines.append(f"- Dependencies: {a.dependencies if a.dependencies else 'none'}")
            lines.append(f"- Parallel group: {a.parallel_group}")
            lines.append(f"- SUCCESS: {a.success}")
            lines.append(f"- MANDATORY FALSIFIER: {a.falsifier}")
            lines.append(f"- Stop condition: {a.stop_condition}")
            lines.append(f"- Current state: {a.state}")
            if a.notes:
                lines.append(f"- Notes: {'; '.join(a.notes)}")

        lines.append("\n## SKIPPED")
        if not plan.skipped and not plan.attacks:
            lines.append("No leads at all for this target — nothing to skip yet.")
        elif not plan.skipped:
            lines.append("SUSPICIOUS: nothing was skipped. Verify the skip classifier ran against "
                          "a realistic (non-trivial) lead set before trusting this plan.")
        for s in plan.skipped:
            lines.append(f"\n- Lead {s['lead_id']} ({s['skill']}, {s.get('vuln_class', '?')})")
            lines.append(f"  Reason: {s['reason']}")
            lines.append(f"  Evidence: {s.get('evidence', '(none)')}")
            lines.append(f"  Detail: {s.get('detail', '')}")

        lines.append("\n## Checkpoint Schedule")
        for cp in plan.checkpoints:
            lines.append(f"- {cp}")

        return "\n".join(lines) + "\n"

    def write_plan(self, plan: Plan, recon_dir: str | None = None) -> str:
        recon_dir = recon_dir if recon_dir is not None else os.path.join("recon", plan.target)
        out_path = Path(recon_dir) / "hunt-plan.md"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(self.render_markdown(plan), encoding="utf-8")
        return str(out_path)


# ─── CLI ────────────────────────────────────────────────────────────────────


def _cmd_build_plan(args: argparse.Namespace) -> int:
    director = Director(memory_dir=args.memory_dir)
    plan = director.build_plan(args.target, args.hours, memory_dir=args.memory_dir,
                                recon_dir=args.recon_dir)
    if args.write:
        path = director.write_plan(plan, recon_dir=args.recon_dir)
        print(f"[+] wrote {path}")
        plan_file = args.plan_file or default_plan_path(args.target, args.recon_dir)
        json_path = save_plan(plan, plan_file)
        print(f"[+] wrote {json_path}")
    print(json.dumps(plan.to_dict(), indent=2))
    return 0


def _cmd_replan(args: argparse.Namespace) -> int:
    plan = load_plan(args.plan_file)
    results_so_far = {}
    if args.results_file:
        with open(args.results_file, encoding="utf-8") as fh:
            results_so_far = json.load(fh)
    director = Director()
    updated = director.replan(plan, results_so_far)
    save_plan(updated, args.plan_file)
    print(f"[+] updated {args.plan_file}")
    if args.write:
        recon_dir = args.recon_dir if args.recon_dir is not None else os.path.join("recon", updated.target)
        path = director.write_plan(updated, recon_dir=recon_dir)
        print(f"[+] wrote {path}")
    print(json.dumps(updated.to_dict(), indent=2))
    return 0


def _cmd_explain(args: argparse.Namespace) -> int:
    director = Director(memory_dir=args.memory_dir)
    director.build_plan(args.target, args.hours, memory_dir=args.memory_dir, recon_dir=args.recon_dir)
    print(director.explain(args.lead_id))
    return 0


def _cmd_confidence(args: argparse.Namespace) -> int:
    director = Director(memory_dir=args.memory_dir)
    plan = director.build_plan(args.target, args.hours, memory_dir=args.memory_dir, recon_dir=args.recon_dir)
    print(json.dumps(director.confidence(plan), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Research Director — leads -> executable, falsifiable plan")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_build = sub.add_parser("build-plan", help="Build a research plan for a target")
    p_build.add_argument("target")
    p_build.add_argument("--hours", type=float, required=True)
    p_build.add_argument("--memory-dir", default="hunt-memory")
    p_build.add_argument("--recon-dir", default=None)
    p_build.add_argument("--write", action="store_true",
                          help="Also write recon/<target>/hunt-plan.md and its hunt-plan.json sidecar")
    p_build.add_argument("--plan-file", default=None,
                          help="Override path for the JSON sidecar (default: recon/<target>/hunt-plan.json)")
    p_build.set_defaults(func=_cmd_build_plan)

    p_replan = sub.add_parser("replan", help="Update a saved plan with results-so-far, across process boundaries")
    p_replan.add_argument("--plan-file", required=True,
                           help="Path to a plan JSON previously written by build-plan --write")
    p_replan.add_argument("--results-file", default=None,
                           help='JSON file: {"completed": [...], "failed": [...], "abandoned": [...], '
                                '"in_progress": [...], "revive": [...], "notes": {...}}')
    p_replan.add_argument("--recon-dir", default=None)
    p_replan.add_argument("--write", action="store_true", help="Also (re)write recon/<target>/hunt-plan.md")
    p_replan.set_defaults(func=_cmd_replan)

    p_explain = sub.add_parser("explain", help="Explain why a lead ranked where it did")
    p_explain.add_argument("target")
    p_explain.add_argument("lead_id")
    p_explain.add_argument("--hours", type=float, required=True)
    p_explain.add_argument("--memory-dir", default="hunt-memory")
    p_explain.add_argument("--recon-dir", default=None)
    p_explain.set_defaults(func=_cmd_explain)

    p_conf = sub.add_parser("confidence", help="Calibrated confidence for a freshly-built plan")
    p_conf.add_argument("target")
    p_conf.add_argument("--hours", type=float, required=True)
    p_conf.add_argument("--memory-dir", default="hunt-memory")
    p_conf.add_argument("--recon-dir", default=None)
    p_conf.set_defaults(func=_cmd_confidence)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
