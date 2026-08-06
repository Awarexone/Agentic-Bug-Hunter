"""
Attack Graph v2 — Phase 4 batch 1.

Problem this solves: the Lead Board (tools/lead_board.py) already correlates
leads two-at-a-time (CHAIN_RULES) and three-at-a-time, same-host-only
(HYPOTHESIS_RECIPES), but both are hardcoded Python tables baked into
detect_chains()/detect_hypotheses(), and neither builds anything that can be
searched — they emit flat "these leads are worth looking at together" dicts,
not a graph a caller can path-find over. This module adds a typed capability
graph (Asset/Endpoint/Credential/Capability/Boundary/Impact nodes;
reveals/grants/crosses/impacts edges) built from the SAME day-one
correlation rules — now expressed as data (rules/chain_rules.yaml) instead
of only as Python tuples — plus Phase 1 browser-intelligence artifacts and
Phase 3 tech-fingerprint weight modifiers, and a bounded N-leg path search
over it from any Credential/Capability node to any Impact node.

THIS DOES NOT REPLACE tools/lead_board.py. CHAIN_RULES, HYPOTHESIS_RECIPES,
detect_chains(), and detect_hypotheses() keep running exactly as they did
before this module existed — tests/test_lead_board.py proves that,
unmodified. rules/chain_rules.yaml is an ADDITIONAL, separate transcription
of the same day-one rules, consumed only here.

ONE FORMULA, reused not reinvented: impact_weight and expected_minutes for
path scoring come directly from memory.vuln_intelligence.VULN_IMPACT_POTENTIAL
/ TESTING_TIME_ESTIMATES (the same tables priority_score()/
expected_value_per_hour() already use) — this module never redefines them.
tech-stack weight modifiers reuse memory.vuln_intelligence._matrix_technology_match()
(the same tech_attack_matrix.json lookup priority_score()'s cold-start floor
already uses) instead of a second matrix-matching implementation.

SCALE NOTE: every confidence/weight value in THIS module is 0-1. This is a
new, self-contained scale used only within attack_graph.py and
rules/chain_rules.yaml — NOT the 0-100 scale used elsewhere in this codebase
(hypothesis_calibration(), the --confidence CLI flag, historical_success_
probability, technology_match in priority_score()). VULN_IMPACT_POTENTIAL
values (0-100) are consumed as-is for impact_weight — path_score's 1/100
scale factor is implicit in the formula, not renormalized, since nothing in
this module compares path_score across formulas that expect a 0-100 range.

PROVENANCE (non-negotiable): every Node and Edge carries origin_lead_id
(the lead-board lead id it came from, or None for nodes with no single
originating lead — e.g. the Asset root, or a rule-synthesized Impact node),
origin_source (the artifact/rule that produced it — "lead_board",
"browser/auth-model.json", "rules/chain_rules.yaml#<id>#step<i>", ...), and
confidence_source (a human-readable note on where the edge/node's
confidence number came from). No node is ever created without an
origin_source.

CONTRADICTORY EVIDENCE (non-negotiable): see _apply_contradiction() below —
an observed runtime 401/403 in browser/api-calls.json for the exact URL an
inferred `grants` edge claims access to measurably reduces that edge's
confidence, and blocks the edge entirely below a floor. Nothing here is a
speculative general-purpose contradiction engine; this is the one concrete
check the Phase 4 batch 1 spec asked for. memory/vuln_intelligence.py's
duplicate_or_noise_check() (duplicate/already-reported finding detection)
and tools/validation_core.py were checked first — neither has anything that
does runtime-status-vs-inference contradiction checking, so this is new,
not a duplicate of existing logic.

Pure library + thin CLI-less module: no input(), no network access — same
convention as memory/vuln_intelligence.py and tools/director.py.
"""

from __future__ import annotations

import itertools
import json
import os
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools import lead_board  # noqa: E402
from tools import director  # noqa: E402  (skill_to_vuln_class, _read_browser_json)
from memory.vuln_intelligence import (  # noqa: E402
    VULN_IMPACT_POTENTIAL,
    DEFAULT_IMPACT_POTENTIAL,
    TESTING_TIME_ESTIMATES,
    DEFAULT_TESTING_TIME_MINUTES,
    _matrix_technology_match,  # reused, not reimplemented — see module docstring
)

DEFAULT_RULES_PATH = os.path.join(_REPO, "rules", "chain_rules.yaml")

# Reused, not redefined — tools/lead_board.py's existing combinatorial-cap
# convention for itertools.product() across leg candidate lists.
MAX_LEG_CANDIDATES = lead_board._MAX_LEG_CANDIDATES

# Bounded DFS depth (edges, i.e. legs) for path search (item 3).
MAX_PATH_DEPTH = 5

NODE_TYPES = {"Asset", "Endpoint", "Credential", "Capability", "Boundary", "Impact"}
EDGE_TYPES = {"reveals", "grants", "crosses", "impacts"}
# Step schema's own from_type/to_type enums, as specified for chain_rules.yaml
# (a subset of NODE_TYPES — Boundary nodes exist in the graph but no rule
# transcribed in this batch originates or terminates on one).
_STEP_FROM_TYPES = {"Credential", "Capability", "Endpoint", "Asset"}
_STEP_TO_TYPES = {"Credential", "Capability", "Endpoint", "Asset", "Impact"}


class RuleLoadError(Exception):
    """rules/chain_rules.yaml failed to parse or validate. Raised loudly —
    never silently skipped or defaulted, per the Phase 4 batch 1 spec."""


# ─────────────────────────────────────────────────────────────────────────
# Item 1 — rules as data: rules/chain_rules.yaml loader
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RuleStep:
    from_type: str
    from_values: tuple[str, ...]
    edge_type: str
    to_type: str
    to_values: tuple[str, ...]
    confidence: float


@dataclass(frozen=True)
class ChainRule:
    id: str
    description: str
    enabled: bool
    steps: tuple[RuleStep, ...]
    min_confidence: float
    impact: str | None = None


def _as_value_tuple(value, field_name: str, rule_id) -> tuple[str, ...]:
    """rules/chain_rules.yaml's from_value/to_value accept a scalar string
    OR a list of strings (OR-alternatives) — see the file's own header
    comment for why this is a deliberate, disclosed extension of the
    literal single-string schema handed down for this batch."""
    if isinstance(value, str) and value.strip():
        return (value,)
    if isinstance(value, list) and value and all(isinstance(v, str) and v.strip() for v in value):
        return tuple(value)
    raise RuleLoadError(
        f"rule {rule_id!r}: {field_name!r} must be a non-empty string or list of "
        f"non-empty strings, got {value!r}"
    )


def load_chain_rules(path: str | None = None) -> list[ChainRule]:
    """Load + validate rules/chain_rules.yaml. Raises RuleLoadError (or lets
    yaml.YAMLError propagate) on ANY malformed input — missing/mistyped
    fields, unknown enum values, bad YAML syntax. Never silently skips a
    bad rule or substitutes a default; a partially-broken rules file is
    treated as fully broken, so a typo can never quietly disable half the
    day-one correlation rules without anyone noticing."""
    path = path or DEFAULT_RULES_PATH
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except OSError as exc:
        raise RuleLoadError(f"cannot read {path}: {exc}") from exc
    # yaml.YAMLError (syntax errors) is intentionally NOT caught here — it
    # propagates as-is, which is itself "fails loudly," and callers/tests
    # can catch either RuleLoadError or yaml.YAMLError.

    if not isinstance(raw, list):
        raise RuleLoadError(f"{path}: top-level content must be a YAML list of rules, got {type(raw).__name__}")

    rules: list[ChainRule] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise RuleLoadError(f"{path}: rule #{i} is not a mapping")

        rid = item.get("id")
        if not isinstance(rid, str) or not rid.strip():
            raise RuleLoadError(f"{path}: rule #{i} missing required non-empty 'id'")

        description = item.get("description")
        if not isinstance(description, str) or not description.strip():
            raise RuleLoadError(f"rule {rid!r}: missing required non-empty 'description'")

        enabled = item.get("enabled", True)
        if not isinstance(enabled, bool):
            raise RuleLoadError(f"rule {rid!r}: 'enabled' must be a bool, got {enabled!r}")

        min_confidence = item.get("min_confidence", 0.5)
        if not isinstance(min_confidence, (int, float)) or isinstance(min_confidence, bool) \
                or not (0.0 <= float(min_confidence) <= 1.0):
            raise RuleLoadError(f"rule {rid!r}: 'min_confidence' must be a float in [0,1], got {min_confidence!r}")

        impact = item.get("impact")
        if impact is not None and not isinstance(impact, str):
            raise RuleLoadError(f"rule {rid!r}: 'impact' must be a string if present, got {impact!r}")

        steps_raw = item.get("steps")
        if not isinstance(steps_raw, list) or not steps_raw:
            raise RuleLoadError(f"rule {rid!r}: 'steps' must be a non-empty list")

        steps: list[RuleStep] = []
        for j, s in enumerate(steps_raw):
            if not isinstance(s, dict):
                raise RuleLoadError(f"rule {rid!r} step #{j}: not a mapping")
            ft = s.get("from_type")
            tt = s.get("to_type")
            et = s.get("edge_type")
            if ft not in _STEP_FROM_TYPES:
                raise RuleLoadError(f"rule {rid!r} step #{j}: invalid from_type {ft!r} (must be one of {sorted(_STEP_FROM_TYPES)})")
            if tt not in _STEP_TO_TYPES:
                raise RuleLoadError(f"rule {rid!r} step #{j}: invalid to_type {tt!r} (must be one of {sorted(_STEP_TO_TYPES)})")
            if et not in EDGE_TYPES:
                raise RuleLoadError(f"rule {rid!r} step #{j}: invalid edge_type {et!r} (must be one of {sorted(EDGE_TYPES)})")
            conf = s.get("confidence")
            if not isinstance(conf, (int, float)) or isinstance(conf, bool) or not (0.0 <= float(conf) <= 1.0):
                raise RuleLoadError(f"rule {rid!r} step #{j}: 'confidence' must be a float in [0,1], got {conf!r}")
            from_values = _as_value_tuple(s.get("from_value"), "from_value", rid)
            to_values = _as_value_tuple(s.get("to_value"), "to_value", rid)
            steps.append(RuleStep(ft, from_values, et, tt, to_values, float(conf)))

        rules.append(ChainRule(rid, description, enabled, tuple(steps), float(min_confidence), impact))

    return rules


def _rule_legs(rule: ChainRule) -> list[tuple[str, frozenset[str]]]:
    """A rule's N steps chain N+1 legs: leg0 -(step0)-> leg1 -(step1)-> ...
    Returns [(leg_type, leg_values_frozenset), ...] length len(steps)+1."""
    legs = [(rule.steps[0].from_type, frozenset(rule.steps[0].from_values))]
    for step in rule.steps:
        legs.append((step.to_type, frozenset(step.to_values)))
    return legs


# ─────────────────────────────────────────────────────────────────────────
# Item 1 (continued) — YAML-driven equivalents of lead_board.py's
# detect_chains()/detect_hypotheses(), used ONLY by the regression test
# proving day-one fidelity and by apply_chain_rules() below. lead_board.py's
# own detect_chains()/detect_hypotheses() are untouched and keep running.
# ─────────────────────────────────────────────────────────────────────────


def detect_chains_from_rules(target: str, leads: list[dict], rules: list[ChainRule] | None = None) -> list[dict]:
    """Equivalent of lead_board.detect_chains(), driven by chain_rules.yaml's
    1-step (2-leg) rules instead of the hardcoded CHAIN_RULES table. Pure —
    does not mutate `leads`, returns freshly synthesized chain dicts."""
    rules = rules if rules is not None else load_chain_rules()
    two_leg = [r for r in rules if r.enabled and len(r.steps) == 1]

    out: list[dict] = []
    existing_pairs: set[tuple[str, str]] = set()
    for rule in two_leg:
        legs = _rule_legs(rule)
        skills_a, skills_b = legs[0][1], legs[1][1]
        legs_a = [l for l in leads if l.get("skill") in skills_a and l.get("source") != "chain"]
        legs_b = [l for l in leads if l.get("skill") in skills_b and l.get("source") != "chain"]
        for a in legs_a:
            host_a = lead_board._host_of(a["evidence"])
            for b in legs_b:
                if a["id"] == b["id"]:
                    continue
                pair_key = tuple(sorted([a["id"], b["id"]]))
                if pair_key in existing_pairs:
                    continue
                host_b = lead_board._host_of(b["evidence"])
                same_host = host_a is not None and host_a == host_b
                out.append({
                    "id": "ag-" + secrets.token_hex(3),
                    "target": target,
                    "skill": b["skill"],
                    "priority": lead_board.P_HIGH if same_host else lead_board.P_MED,
                    "signal": f"CHAIN: {rule.description}",
                    "source": "chain",
                    "chain_name": rule.id,
                    "chain_of": [a["id"], b["id"]],
                    "status": "new",
                })
                existing_pairs.add(pair_key)
    return out


def detect_hypotheses_from_rules(target: str, leads: list[dict], rules: list[ChainRule] | None = None) -> list[dict]:
    """Equivalent of lead_board.detect_hypotheses(), driven by
    chain_rules.yaml's N-step (N+1 leg, terminal leg = Impact) rules instead
    of the hardcoded HYPOTHESIS_RECIPES table. Same same-host-required,
    id-unique, evidence-unique, MAX_LEG_CANDIDATES-capped matching as the
    original. Pure — returns freshly synthesized hypothesis dicts."""
    rules = rules if rules is not None else load_chain_rules()
    hyp_rules = [r for r in rules if r.enabled and len(r.steps) >= 2 and _rule_legs(r)[-1][0] == "Impact"]

    out: list[dict] = []
    existing: set[tuple[str, ...]] = set()
    for rule in hyp_rules:
        legs = _rule_legs(rule)
        skill_legs = legs[:-1]  # drop the terminal Impact leg — not lead-matchable
        candidate_legs = []
        for _type, skills in skill_legs:
            seen_evidence: set[str] = set()
            leg_candidates = []
            for l in leads:
                if l.get("skill") not in skills or l.get("source") in ("chain", "hypothesis"):
                    continue
                if l["evidence"] in seen_evidence:
                    continue
                seen_evidence.add(l["evidence"])
                leg_candidates.append(l)
            candidate_legs.append(leg_candidates[:MAX_LEG_CANDIDATES])
        if any(not c for c in candidate_legs):
            continue
        for combo in itertools.product(*candidate_legs):
            ids = [l["id"] for l in combo]
            if len(set(ids)) != len(ids):
                continue
            if len({l["evidence"] for l in combo}) != len(combo):
                continue
            key = tuple(sorted(ids))
            if key in existing:
                continue
            hosts = {lead_board._host_of(l["evidence"]) for l in combo}
            hosts.discard(None)
            if len(hosts) != 1:
                continue
            out.append({
                "id": "ag-" + secrets.token_hex(3),
                "target": target,
                "skill": combo[-1]["skill"],
                "priority": lead_board.P_HIGH,
                "signal": f"HYPOTHESIS: {rule.description}",
                "source": "hypothesis",
                "chain_name": rule.id,
                "chain_of": ids,
                "impact": rule.impact or "unknown",
                "status": "new",
            })
            existing.add(key)
    return out


# ─────────────────────────────────────────────────────────────────────────
# Item 2 — typed capability graph
# ─────────────────────────────────────────────────────────────────────────


@dataclass
class Node:
    id: str
    type: str
    label: str
    origin_lead_id: str | None
    origin_source: str
    confidence_source: str
    vuln_class: str | None = None
    impact_severity: str | None = None

    def __post_init__(self):
        if self.type not in NODE_TYPES:
            raise ValueError(f"invalid node type {self.type!r} for node {self.id!r}")
        if not self.origin_source:
            raise ValueError(f"node {self.id!r} has no origin_source — PROVENANCE guarantee violated")


@dataclass
class Edge:
    from_id: str
    to_id: str
    edge_type: str
    confidence: float
    origin_lead_id: str | None
    origin_source: str
    rule_id: str | None = None
    contradiction: str | None = None

    def __post_init__(self):
        if self.edge_type not in EDGE_TYPES:
            raise ValueError(f"invalid edge type {self.edge_type!r} on edge {self.from_id}->{self.to_id}")
        if not self.origin_source:
            raise ValueError(f"edge {self.from_id}->{self.to_id} has no origin_source — PROVENANCE guarantee violated")


@dataclass
class Graph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)

    def add_node(self, node: Node) -> str:
        if node.id not in self.nodes:
            self.nodes[node.id] = node
        return node.id

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)

    def edges_from(self, node_id: str) -> list[Edge]:
        return [e for e in self.edges if e.from_id == node_id]

    def edges_to(self, node_id: str) -> list[Edge]:
        return [e for e in self.edges if e.to_id == node_id]


# Coarse priority->confidence floor for lead-derived Endpoint/Credential
# nodes' Asset->node edge — lead_board leads have no numeric confidence of
# their own (only high/med/low priority), so this is the mapping used to
# give them one on entry into this 0-1-scale graph.
_PRIORITY_CONFIDENCE = {lead_board.P_HIGH: 0.7, lead_board.P_MED: 0.5, lead_board.P_LOW: 0.3}

_CONTRADICTING_STATUSES = {401, 403}
CONTRADICTION_PENALTY = 0.3   # multiply confidence by this on contradiction
CONTRADICTION_BLOCK_FLOOR = 0.15  # below this after penalty, block edge creation


def _apply_contradiction(confidence: float, edge_type: str, target_evidence: str,
                          observed_statuses: dict[str, int]) -> tuple[float, str | None]:
    """CONTRADICTORY EVIDENCE guarantee. Only `grants` edges assert "this
    capability actually works" — that's the one claim an observed runtime
    401/403 for the exact same URL can contradict. `reveals`/`crosses`/
    `impacts` edges aren't access claims this signal can speak to, so they
    pass through untouched. See module docstring for what was checked
    (duplicate_or_noise_check, validation_core.py) before writing this."""
    if edge_type != "grants":
        return confidence, None
    status = observed_statuses.get(target_evidence)
    if status not in _CONTRADICTING_STATUSES:
        return confidence, None
    adjusted = round(confidence * CONTRADICTION_PENALTY, 4)
    note = (f"observed HTTP {status} on {target_evidence} contradicts inferred "
            f"grant (confidence {confidence} -> {adjusted})")
    return adjusted, note


def _observed_statuses(recon_dir: str | None) -> dict[str, int]:
    """url -> last-seen response_status from browser/api-calls.json, best
    effort (missing/malformed file -> {})."""
    if not recon_dir:
        return {}
    payload = director._read_browser_json(recon_dir, "api-calls.json")
    if not payload:
        return {}
    out: dict[str, int] = {}
    for call in payload.get("calls", []) or []:
        if not isinstance(call, dict):
            continue
        url, status = call.get("url"), call.get("response_status")
        if url and isinstance(status, int) and not isinstance(status, bool):
            out[url] = status
    return out


def apply_chain_rules(graph: Graph, leads: list[dict], rules: list[ChainRule] | None = None,
                       observed_statuses: dict[str, int] | None = None) -> int:
    """Connect existing lead-derived nodes (added by build_capability_graph's
    raw-lead pass, node id f"lead:{lead_id}") with rule-driven edges from
    rules/chain_rules.yaml, creating terminal Impact nodes lazily where a
    hypothesis-shaped rule fires. Applies the CONTRADICTORY EVIDENCE check
    to every `grants` edge. Returns the number of edges added."""
    rules = rules if rules is not None else load_chain_rules()
    observed_statuses = observed_statuses or {}

    by_skill: dict[str, list[dict]] = {}
    for l in leads:
        if l.get("source") in ("chain", "hypothesis"):
            continue
        by_skill.setdefault(l.get("skill"), []).append(l)

    added = 0
    for rule in rules:
        if not rule.enabled:
            continue
        legs = _rule_legs(rule)
        is_impact_terminated = legs[-1][0] == "Impact"
        skill_legs = legs[:-1] if is_impact_terminated else legs

        leg_candidates = []
        for _type, skills in skill_legs:
            cands: list[dict] = []
            for sk in skills:
                cands.extend(by_skill.get(sk, []))
            leg_candidates.append(cands[:MAX_LEG_CANDIDATES])
        if any(not c for c in leg_candidates):
            continue

        for combo in itertools.product(*leg_candidates):
            ids = [l["id"] for l in combo]
            if len(set(ids)) != len(ids):
                continue
            if len({l["evidence"] for l in combo}) != len(combo):
                continue
            if is_impact_terminated:
                hosts = {lead_board._host_of(l["evidence"]) for l in combo}
                hosts.discard(None)
                if len(hosts) != 1:
                    continue  # same-host gate, mirrors detect_hypotheses()

            prev_node_id = f"lead:{combo[0]['id']}"
            if prev_node_id not in graph.nodes:
                continue

            ok = True
            new_edges: list[Edge] = []
            cur_node_id = prev_node_id
            for i, step in enumerate(rule.steps):
                if i + 1 < len(combo):
                    leg_lead = combo[i + 1]
                    to_node_id = f"lead:{leg_lead['id']}"
                    to_evidence = leg_lead["evidence"]
                    if to_node_id not in graph.nodes:
                        ok = False
                        break
                else:
                    to_node_id = f"impact:{rule.id}"
                    to_evidence = step.to_values[0]
                    if to_node_id not in graph.nodes:
                        graph.add_node(Node(
                            to_node_id, "Impact", to_evidence,
                            origin_lead_id=None,
                            origin_source=f"rules/chain_rules.yaml#{rule.id}",
                            confidence_source="hypothesis rule terminal leg",
                            impact_severity=rule.impact,
                        ))

                confidence, note = _apply_contradiction(step.confidence, step.edge_type, to_evidence, observed_statuses)
                if confidence < CONTRADICTION_BLOCK_FLOOR:
                    ok = False
                    break
                new_edges.append(Edge(
                    cur_node_id, to_node_id, step.edge_type, confidence,
                    origin_lead_id=combo[0]["id"],
                    origin_source=f"rules/chain_rules.yaml#{rule.id}#step{i}",
                    rule_id=rule.id, contradiction=note,
                ))
                cur_node_id = to_node_id

            if not ok:
                continue
            for e in new_edges:
                graph.add_edge(e)
                added += 1
    return added


def apply_tech_modifiers(graph: Graph, tech_stack: list[str] | None, tech_attack_matrix: dict | None) -> int:
    """Phase 3 tech_attack_matrix weight MODIFIER only — never creates a new
    node or edge, only nudges confidence on edges pointing at nodes whose
    vuln_class this target's tech stack is known to be more/less exposed to.
    Reuses memory.vuln_intelligence._matrix_technology_match() (the same
    weight lookup priority_score()'s cold-start floor already uses) instead
    of a second matrix-matching implementation. weight is 0-100 (that
    function's own scale); mapped to a bounded multiplier centered at 1.0 so
    the function's own no-match floor (20) leaves confidence unchanged,
    while a strong match (weight near 100) can raise confidence up to 1.4x
    of its prior value, capped at 1.0 overall."""
    if not tech_stack or not tech_attack_matrix:
        return 0
    modified = 0
    for node in graph.nodes.values():
        if not node.vuln_class:
            continue
        weight = _matrix_technology_match(node.vuln_class, tech_stack, tech_attack_matrix)
        multiplier = 1.0 + max(0.0, (weight - 20) / 200.0)
        for edge in graph.edges_to(node.id):
            edge.confidence = min(1.0, round(edge.confidence * multiplier, 4))
            modified += 1
    return modified


def build_capability_graph(target: str, recon_dir: str | None = None, leads: list[dict] | None = None,
                            rules: list[ChainRule] | None = None, tech_stack: list[str] | None = None,
                            tech_attack_matrix: dict | None = None,
                            cross_host_recon_dirs: dict[str, str] | None = None) -> Graph:
    """Build the typed capability graph for `target` from:
      - tools/lead_board.load_ledger(target) (or a caller-supplied `leads`)
      - Phase 1 recon/<target>/browser/*.json artifacts
      - rule-driven edges from rules/chain_rules.yaml (item 1)
      - Phase 3 tech_attack_matrix weight modifiers (never new nodes)
      - Item 5 (batch 2): cross-host bridging via add_cross_host_edges(),
        ONLY when the caller passes cross_host_recon_dirs (an explicit
        {host: recon_dir} map — see add_cross_host_edges()'s docstring for
        why there's no auto-discovered layout to default to). Omitted by
        default so single-host callers (and every batch-1 test) see no
        behavior change.
    Never raises on missing/malformed recon artifacts (same best-effort
    convention as tools/director.py's browser_intel_leads()); never makes a
    network request."""
    recon_dir = recon_dir or os.path.join(_REPO, "recon", target)
    leads = leads if leads is not None else lead_board.load_ledger(target)
    rules = rules if rules is not None else load_chain_rules()

    g = Graph()
    asset_id = f"asset:{target}"
    g.add_node(Node(asset_id, "Asset", target, origin_lead_id=None,
                     origin_source="target", confidence_source="given"))

    # 1. raw lead_board leads -> Endpoint/Credential nodes. Chain/hypothesis
    # leads (lead_board's OWN correlation synthesis) are skipped — this
    # graph builds its own rule-driven edges over the raw legs instead of
    # re-consuming lead_board's already-synthesized composite leads.
    for l in leads:
        if l.get("source") in ("chain", "hypothesis") or not l.get("skill"):
            continue
        node_id = f"lead:{l['id']}"
        node_type = "Credential" if l["skill"] == "hunt-source-leak" else "Endpoint"
        vuln_class = director.skill_to_vuln_class(l["skill"])
        g.add_node(Node(node_id, node_type, (l.get("evidence") or "")[:120],
                         origin_lead_id=l["id"], origin_source="lead_board",
                         confidence_source=f"lead priority={l.get('priority', '?')}",
                         vuln_class=vuln_class))
        g.add_edge(Edge(asset_id, node_id, "reveals",
                         confidence=_PRIORITY_CONFIDENCE.get(l.get("priority"), 0.4),
                         origin_lead_id=l["id"], origin_source="lead_board"))

    # 2. Phase 1 browser intelligence artifacts.
    auth_model = director._read_browser_json(recon_dir, "auth-model.json")
    if auth_model:
        for const in auth_model.get("role_permission_constants", []) or []:
            if not const:
                continue
            node_id = f"capability:{const}"
            if node_id not in g.nodes:
                g.add_node(Node(node_id, "Capability", const, origin_lead_id=None,
                                 origin_source="browser/auth-model.json",
                                 confidence_source="role/permission constant extracted from client bundle"))
                g.add_edge(Edge(asset_id, node_id, "grants", confidence=0.5,
                                 origin_lead_id=None, origin_source="browser/auth-model.json"))
        for route in auth_model.get("candidate_privileged_client_routes", []) or []:
            if not route:
                continue
            node_id = f"boundary:{route}"
            if node_id not in g.nodes:
                g.add_node(Node(node_id, "Boundary", route, origin_lead_id=None,
                                 origin_source="browser/auth-model.json",
                                 confidence_source="client-side-only privileged-route heuristic "
                                                    "(browser_recon.py find_candidate_privileged_routes)"))
                g.add_edge(Edge(asset_id, node_id, "crosses", confidence=0.4,
                                 origin_lead_id=None, origin_source="browser/auth-model.json"))
        for url in auth_model.get("auth_lifecycle_endpoints", []) or []:
            if not url:
                continue
            node_id = f"endpoint:{url}"
            if node_id not in g.nodes:
                g.add_node(Node(node_id, "Endpoint", url, origin_lead_id=None,
                                 origin_source="browser/auth-model.json",
                                 confidence_source="auth-lifecycle endpoint cross-referenced from api-calls.json"))
                g.add_edge(Edge(asset_id, node_id, "reveals", confidence=0.5,
                                 origin_lead_id=None, origin_source="browser/auth-model.json"))

    for artifact_name, list_field in (("routes.json", "routes"), ("never-called.json", "never_called")):
        payload = director._read_browser_json(recon_dir, artifact_name)
        if not payload:
            continue
        for ep in payload.get(list_field, []) or []:
            if not ep:
                continue
            node_id = f"endpoint:{ep}"
            if node_id in g.nodes:
                continue
            g.add_node(Node(node_id, "Endpoint", ep, origin_lead_id=None,
                             origin_source=f"browser/{artifact_name}",
                             confidence_source="Phase 1 browser recon artifact"))
            g.add_edge(Edge(asset_id, node_id, "reveals", confidence=0.45,
                             origin_lead_id=None, origin_source=f"browser/{artifact_name}"))

    # 3. rule-driven edges (item 1), with the CONTRADICTORY EVIDENCE check.
    observed = _observed_statuses(recon_dir)
    apply_chain_rules(g, leads, rules=rules, observed_statuses=observed)

    # 4. Phase 3 weight modifiers — MODIFIERS ONLY, never new nodes.
    if tech_stack and tech_attack_matrix:
        apply_tech_modifiers(g, tech_stack, tech_attack_matrix)

    # 5. (batch 2) cross-host bridging — opt-in only, see docstring.
    if cross_host_recon_dirs:
        add_cross_host_edges(g, cross_host_recon_dirs)

    return g


# ─────────────────────────────────────────────────────────────────────────
# Item 3 — N-leg path search (bounded DFS, depth <= 5, cycle-protected)
# ─────────────────────────────────────────────────────────────────────────


@dataclass
class GraphPath:
    edges: list[Edge]

    @property
    def node_ids(self) -> list[str]:
        if not self.edges:
            return []
        return [self.edges[0].from_id] + [e.to_id for e in self.edges]


def find_paths(graph: Graph, max_depth: int = MAX_PATH_DEPTH,
               max_leg_candidates: int = MAX_LEG_CANDIDATES) -> list[GraphPath]:
    """Bounded DFS from every Credential/Capability node to every reachable
    Impact node, depth (edge count) <= max_depth. Cycle protection: the
    visited-node set is threaded PER PATH (a new frozenset on each
    recursive branch), never shared/global, so a cycle can't be walked
    twice within one path while the same node remains reachable via a
    different branch from a different start. Branching at each node is
    capped to `max_leg_candidates` highest-confidence outgoing edges —
    same defensive-cap convention as tools/lead_board.py's
    _MAX_LEG_CANDIDATES, applied here to graph fan-out instead of
    itertools.product() legs."""
    if max_depth < 0:
        raise ValueError("max_depth must be >= 0")
    starts = [n for n in graph.nodes.values() if n.type in ("Credential", "Capability")]
    paths: list[GraphPath] = []
    for start in starts:
        _dfs_paths(graph, start.id, [], frozenset({start.id}), max_depth, max_leg_candidates, paths)
    return paths


def _dfs_paths(graph: Graph, node_id: str, edge_path: list[Edge], visited: frozenset[str],
               depth_remaining: int, cap: int, out: list[GraphPath]) -> None:
    node = graph.nodes.get(node_id)
    if node is None:
        return
    if node.type == "Impact" and edge_path:
        out.append(GraphPath(edges=list(edge_path)))
    if depth_remaining <= 0:
        return
    outgoing = sorted(graph.edges_from(node_id), key=lambda e: e.confidence, reverse=True)[:cap]
    for e in outgoing:
        if e.to_id not in graph.nodes or e.to_id in visited:
            continue  # cycle protection: never revisit a node already on THIS path
        _dfs_paths(graph, e.to_id, edge_path + [e], visited | {e.to_id},
                   depth_remaining - 1, cap, out)


# ─────────────────────────────────────────────────────────────────────────
# Item 4 — path scoring
# ─────────────────────────────────────────────────────────────────────────


def path_score(min_confidence: float, impact_weight: float, expected_minutes: float) -> float:
    """path_score = min(leg_confidence) * impact_weight * (1 / expected_minutes).
    Pure function — no graph traversal — so monotonicity in confidence and
    impact_weight is directly testable without building a graph."""
    if expected_minutes <= 0:
        raise ValueError("expected_minutes must be positive")
    return min_confidence * impact_weight * (1.0 / expected_minutes)


def _path_vuln_class(graph: Graph, path: GraphPath) -> str | None:
    """The vuln_class informing impact_weight/expected_minutes is read from
    the node NEAREST the Impact end of the path that actually carries one
    (lead-derived Endpoint/Credential nodes do via skill_to_vuln_class();
    browser-artifact-derived Capability/Boundary/Endpoint nodes and the
    Impact node itself generally don't) — the leg closest to the impact is
    the most specific evidence for what kind of vulnerability this path
    actually is."""
    for node_id in reversed(path.node_ids):
        node = graph.nodes.get(node_id)
        if node and node.vuln_class:
            return node.vuln_class
    return None


def score_graph_path(graph: Graph, path: GraphPath) -> dict:
    leg_confidences = [e.confidence for e in path.edges]
    min_confidence = min(leg_confidences) if leg_confidences else 0.0
    vuln_class = _path_vuln_class(graph, path)
    impact_weight = VULN_IMPACT_POTENTIAL.get(vuln_class, DEFAULT_IMPACT_POTENTIAL) if vuln_class else DEFAULT_IMPACT_POTENTIAL
    expected_minutes = TESTING_TIME_ESTIMATES.get(vuln_class, DEFAULT_TESTING_TIME_MINUTES) if vuln_class else DEFAULT_TESTING_TIME_MINUTES
    return {
        "min_confidence": min_confidence,
        "vuln_class": vuln_class,
        "impact_weight": impact_weight,
        "expected_minutes": expected_minutes,
        "path_score": path_score(min_confidence, impact_weight, expected_minutes),
    }


def top_paths(target: str, graph: Graph, max_depth: int = MAX_PATH_DEPTH,
              max_leg_candidates: int = MAX_LEG_CANDIDATES) -> list[dict]:
    """Item 3 (bounded DFS) + item 4 (scoring), reduced to the single
    best-scoring path per reachable Impact node (item 4's "emit the
    top-scoring path per Impact node as ONE candidate").

    Output is deliberately lead-board-shaped (id/target/skill/priority/
    signal/why/evidence/source/status/chain_of/created/last_seen/
    seen_count) — this is the exact shape tools/director.py's
    browser_intel_leads() already returns, and build_plan() already
    concatenates `board_leads + bi_leads` before scoring every lead
    identically. A future batch wiring this into build_plan() only needs
    `all_leads = board_leads + bi_leads + top_paths(...)`, no new candidate
    type or parallel scoring path — see this module's docstring and the
    Phase 4 batch 1 report for why this shape was chosen now even though
    the wiring itself is OUT OF SCOPE for this batch.
    """
    paths = find_paths(graph, max_depth, max_leg_candidates)
    best_by_impact: dict[str, tuple[GraphPath, dict]] = {}
    for p in paths:
        if not p.edges:
            continue
        impact_id = p.edges[-1].to_id
        scored = score_graph_path(graph, p)
        cur = best_by_impact.get(impact_id)
        if cur is None or scored["path_score"] > cur[1]["path_score"]:
            best_by_impact[impact_id] = (p, scored)

    out: list[dict] = []
    for impact_id, (p, scored) in best_by_impact.items():
        impact_node = graph.nodes.get(impact_id)
        start_node = graph.nodes.get(p.node_ids[0])
        node_labels = [graph.nodes[nid].label for nid in p.node_ids if nid in graph.nodes]
        chain_of = [graph.nodes[nid].origin_lead_id for nid in p.node_ids
                    if nid in graph.nodes and graph.nodes[nid].origin_lead_id]
        vuln_class = scored["vuln_class"]
        skill = f"hunt-{vuln_class}" if vuln_class else "hunt-misc"
        score = scored["path_score"]
        priority = lead_board.P_HIGH if score >= 1.0 else (lead_board.P_MED if score >= 0.2 else lead_board.P_LOW)
        now = lead_board.now_iso()
        # path_legs: per-edge detail (Director.explain()'s source=="attack-
        # graph" case, tools/director.py, needs this to render the weakest
        # link / strongest evidence / assumptions required for a graph-
        # generated path — the aggregate min_confidence in `why` alone
        # isn't enough to say WHICH leg or WHY it's weak).
        path_legs = [{
            "from": graph.nodes[e.from_id].label if e.from_id in graph.nodes else e.from_id,
            "to": graph.nodes[e.to_id].label if e.to_id in graph.nodes else e.to_id,
            "edge_type": e.edge_type,
            "confidence": e.confidence,
            "origin_source": e.origin_source,
            "rule_id": e.rule_id,
            "contradiction": e.contradiction,
        } for e in p.edges]
        out.append({
            "id": "ag-" + secrets.token_hex(3),
            "target": target,
            "skill": skill,
            "priority": priority,
            "signal": f"ATTACK PATH: {start_node.label if start_node else '?'} -> "
                      f"{impact_node.label if impact_node else impact_id}",
            "why": f"{len(p.edges)}-leg path, min leg confidence {scored['min_confidence']}, "
                   f"vuln_class={vuln_class}",
            "evidence": " -> ".join(node_labels),
            "source": "attack-graph",
            "chain_of": chain_of,
            "path_score": score,
            "path_legs": path_legs,
            "impact_weight": scored["impact_weight"],
            "expected_minutes": scored["expected_minutes"],
            "status": "new", "note": "",
            "created": now, "last_seen": now, "seen_count": 1,
        })
    out.sort(key=lambda l: l["path_score"], reverse=True)
    return out


# ─────────────────────────────────────────────────────────────────────────
# Item 5 (batch 2) — cross-host chains via a shared Credential/Capability
# fingerprint.
#
# Problem: a single tools/browser_recon.py run only ever analyzes ONE host
# (analyze_auth_model()'s entry_urls[0] for cookies/storage — see its own
# docstring) and writes ONE recon/<target>/browser/auth-model.json +
# api-calls.json. There is no existing repo-wide "recon dir per subdomain"
# convention to auto-discover (checked tools/director.py, tools/
# fingerprint.py, tools/recon_adapter.py — subdomains.txt/live-hosts.txt
# are host LISTS inside one recon_dir, but browser/*.json artifacts are
# singular per recon_dir; --recon-dir is just a caller-supplied path, no
# multi-host layout enforced anywhere). So cross-host correlation here is
# explicitly caller-supplied: run browser_recon.py once per host into its
# own recon_dir (whatever layout the caller already uses), then pass the
# resulting {host: recon_dir} map to find_cross_host_credential_links()/
# add_cross_host_edges() below.
#
# The link itself: a cross-host `grants`-shaped edge is created ONLY when
# the exact same value_fingerprint (Phase 4 batch 2's addition to
# tools/browser_recon.py's _classify_cookies/_classify_storage_keys/
# ApiCallRecorder — sha256(value)[:16], never the raw value) is observed on
# TWO OR MORE DISTINCT HOSTS. Domain-suffix similarity (api.foo.com and
# www.foo.com sharing nothing but ".foo.com") is NEVER sufficient by
# itself — see tests/test_attack_graph.py's explicit negative-path test.
# ─────────────────────────────────────────────────────────────────────────

CROSS_HOST_GRANT_BASE_CONFIDENCE = 0.6  # same order as chain_rules.yaml's chain-shaped (0.6) rules


def _host_artifact_fingerprints(recon_dir: str) -> list[dict]:
    """Fingerprint records found in a SINGLE recon_dir's
    browser/auth-model.json (cookies + local/session storage) and
    browser/api-calls.json (request_headers_auth_fingerprint) — Phase 4
    batch 2's additions to tools/browser_recon.py. Best-effort: missing or
    malformed artifacts (via director._read_browser_json, same convention
    as everywhere else in this module) yield [] for that artifact rather
    than raising. Each record: {fingerprint, kind, name, artifact}."""
    out: list[dict] = []
    auth_model = director._read_browser_json(recon_dir, "auth-model.json")
    if auth_model:
        for c in auth_model.get("cookies", []) or []:
            if not isinstance(c, dict):
                continue
            fp = c.get("value_fingerprint")
            if fp:
                out.append({"fingerprint": fp, "kind": "cookie", "name": c.get("name"),
                            "artifact": "auth-model.json"})
        for area in ("local_storage", "session_storage"):
            for item in auth_model.get(area, []) or []:
                if not isinstance(item, dict):
                    continue
                fp = item.get("value_fingerprint")
                if fp:
                    out.append({"fingerprint": fp, "kind": area, "name": item.get("key"),
                                "artifact": "auth-model.json"})
    api_calls = director._read_browser_json(recon_dir, "api-calls.json")
    if api_calls:
        for call in api_calls.get("calls", []) or []:
            if not isinstance(call, dict):
                continue
            for hname, fp in (call.get("request_headers_auth_fingerprint") or {}).items():
                if fp:
                    out.append({"fingerprint": fp, "kind": "header", "name": hname,
                                "artifact": "api-calls.json"})
    return out


def find_cross_host_credential_links(host_recon_dirs: dict[str, str]) -> list[dict]:
    """host_recon_dirs: {host: recon_dir}, one recon_dir per subdomain
    (caller-supplied — see module note above for why there's no
    auto-discovered layout). Returns one record per fingerprint value
    observed on 2+ DISTINCT hosts: {"fingerprint": ..., "hosts": [{"host",
    "recon_dir", "kind", "name", "artifact"}, ...]}. A fingerprint seen on
    only one host (even if seen twice under two different cookie names on
    that same host) never produces a link — this is the PROVENANCE-bearing
    core of the cross-host guarantee: same-domain-family alone is never
    enough, only a genuinely matching secret value is. Best-effort: a host
    with no/malformed browser artifacts contributes nothing, never raises."""
    by_fp: dict[str, dict[str, dict]] = {}
    for host, recon_dir in host_recon_dirs.items():
        for rec in _host_artifact_fingerprints(recon_dir):
            fp = rec["fingerprint"]
            by_fp.setdefault(fp, {})
            # first record wins per host — one shared-secret edge per
            # (fingerprint, host) pair is enough provenance, not every
            # cookie/header alias of the same value.
            by_fp[fp].setdefault(host, {**rec, "host": host, "recon_dir": recon_dir})

    links: list[dict] = []
    for fp, hosts in by_fp.items():
        if len(hosts) < 2:
            continue
        links.append({"fingerprint": fp, "hosts": list(hosts.values())})
    return links


def add_cross_host_edges(graph: Graph, host_recon_dirs: dict[str, str]) -> int:
    """Item 5 (batch 2). Extends an already-built Graph (from
    build_capability_graph()) with cross-host bridging, least-invasively:
    for every shared-fingerprint link found by
    find_cross_host_credential_links(), adds ONE shared Credential node
    (id f"credential:xhost:{fingerprint}") plus a `reveals` edge from the
    graph's existing Asset node, and a `grants` edge from that Credential
    node into every existing lead-derived Endpoint/Credential node whose
    evidence resolves (tools.lead_board._host_of()) to one of the linked
    hosts — i.e. "possessing this credential value grants access to what
    was already observed on that host". Each `grants` edge goes through
    the SAME CONTRADICTORY EVIDENCE check as same-host grants edges
    (_apply_contradiction(), using THAT host's own recon_dir's observed
    401/403s) — no new contradiction mechanism, the existing one applied
    per-host. Returns edges+nodes added. Best-effort: a graph with no
    Asset node (shouldn't happen via build_capability_graph, but this
    function doesn't assume its caller) yields 0, never raises."""
    asset_nodes = [n for n in graph.nodes.values() if n.type == "Asset"]
    if not asset_nodes:
        return 0
    asset_id = asset_nodes[0].id

    links = find_cross_host_credential_links(host_recon_dirs)
    added = 0
    for link in links:
        fp = link["fingerprint"]
        hosts_desc = ", ".join(
            f"{h['host']}/{h['artifact']}#{h['kind']}:{h['name']}" for h in link["hosts"]
        )
        node_id = f"credential:xhost:{fp}"
        if node_id not in graph.nodes:
            graph.add_node(Node(
                node_id, "Credential",
                f"shared secret (fingerprint {fp}) observed on: {hosts_desc}",
                origin_lead_id=None,
                origin_source=f"cross-host-fingerprint-match:{hosts_desc}",
                confidence_source=f"value_fingerprint {fp} matched across {len(link['hosts'])} host(s)",
            ))
            graph.add_edge(Edge(
                asset_id, node_id, "reveals", confidence=0.55,
                origin_lead_id=None, origin_source=f"cross-host-fingerprint-match:{hosts_desc}",
            ))
            added += 1

        for h in link["hosts"]:
            observed = _observed_statuses(h["recon_dir"])
            leg_note = f"cross-host-fingerprint-match:{h['host']}/{h['artifact']}#{h['kind']}:{h['name']}"
            for target_node in graph.nodes.values():
                if target_node.id in (node_id, asset_id) or target_node.type not in ("Endpoint", "Credential"):
                    continue
                if lead_board._host_of(target_node.label) != h["host"]:
                    continue
                confidence, contradiction = _apply_contradiction(
                    CROSS_HOST_GRANT_BASE_CONFIDENCE, "grants", target_node.label, observed,
                )
                if confidence < CONTRADICTION_BLOCK_FLOOR:
                    continue
                graph.add_edge(Edge(
                    node_id, target_node.id, "grants", confidence,
                    origin_lead_id=None, origin_source=leg_note, contradiction=contradiction,
                ))
                added += 1
    return added
