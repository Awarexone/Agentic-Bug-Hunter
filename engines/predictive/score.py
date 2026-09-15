"""Explainable Change-Risk and Security Debt scoring.

Factors are listed explicitly — never a single opaque number without breakdown.
"""

from __future__ import annotations

from typing import Any

from engines.predictive.schema import CONF_HIGH, CONF_LOW, CONF_MEDIUM, CONF_UNKNOWN

# Change-risk factor keys (documented weights)
FACTOR_NEW_PUBLIC_ENTRY = "new_public_entrypoints"
FACTOR_NEW_ATTACK_PATHS = "new_attack_paths"
FACTOR_WEAKENED_CONTROLS = "weakened_controls"
FACTOR_PRIVILEGE_TRANSITIONS = "privilege_transitions"
FACTOR_CROSS_TENANT = "cross_tenant_edges"
FACTOR_AI_TOOLS = "privileged_ai_tools"
FACTOR_EXTERNAL_SERVICES = "external_services"
FACTOR_SECRET_ASSETS = "secret_assets"
FACTOR_MEMORY_REGRESSIONS = "memory_regressions"
FACTOR_AUTHZ_DRIFT = "authorization_drift"

CHANGE_RISK_WEIGHTS: dict[str, float] = {
    FACTOR_NEW_PUBLIC_ENTRY: 3.0,
    FACTOR_NEW_ATTACK_PATHS: 2.5,
    FACTOR_WEAKENED_CONTROLS: 3.5,
    FACTOR_PRIVILEGE_TRANSITIONS: 3.0,
    FACTOR_CROSS_TENANT: 3.5,
    FACTOR_AI_TOOLS: 2.5,
    FACTOR_EXTERNAL_SERVICES: 1.5,
    FACTOR_SECRET_ASSETS: 2.0,
    FACTOR_MEMORY_REGRESSIONS: 4.0,
    FACTOR_AUTHZ_DRIFT: 3.0,
}

DEBT_UNRESOLVED_PATHS = "unresolved_attack_paths"
DEBT_WEAK_CONTROLS = "persistently_weak_controls"
DEBT_EXTERNAL_TRUST = "external_trust_edges"
DEBT_SECRET_SURFACE = "secret_asset_surface"
DEBT_AI_SURFACE = "ai_agent_tool_surface"
DEBT_COMPLEX_CONTROLS = "control_mesh_complexity"
DEBT_HISTORICAL_REGRESSIONS = "historical_regressions"

DEBT_WEIGHTS: dict[str, float] = {
    DEBT_UNRESOLVED_PATHS: 1.0,
    DEBT_WEAK_CONTROLS: 1.5,
    DEBT_EXTERNAL_TRUST: 0.8,
    DEBT_SECRET_SURFACE: 1.2,
    DEBT_AI_SURFACE: 1.0,
    DEBT_COMPLEX_CONTROLS: 0.6,
    DEBT_HISTORICAL_REGRESSIONS: 2.0,
}


def _factor(name: str, count: float, weight_map: dict[str, float], *, evidence: str) -> dict[str, Any]:
    unit = float(weight_map.get(name) or 1.0)
    weight = round(unit * max(float(count), 0.0), 3)
    return {
        "factor": name,
        "count": count,
        "unit_weight": unit,
        "weight": weight,
        "evidence": evidence,
    }


def compute_change_risk(
    *,
    risks: list[dict[str, Any]] | None = None,
    attack_graph: dict[str, Any] | None = None,
    base_attack_graph: dict[str, Any] | None = None,
    memory_regressions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Explainable Change-Risk model from observed deltas and risk signals."""
    factors: list[dict[str, Any]] = []
    risks = risks or []
    ag = attack_graph or {}
    base = base_attack_graph

    def _metric(result: dict[str, Any], key: str) -> int:
        try:
            from engines.attack_graph.predictive import surface_metrics

            return int(surface_metrics(result).get(key) or 0)
        except Exception:  # noqa: BLE001
            if key == "attack_paths":
                return len(result.get("paths") or [])
            return 0

    if base is not None:
        d_pub = _metric(ag, "public_entrypoints") - _metric(base, "public_entrypoints")
        if d_pub > 0:
            factors.append(
                _factor(
                    FACTOR_NEW_PUBLIC_ENTRY,
                    d_pub,
                    CHANGE_RISK_WEIGHTS,
                    evidence="public_entrypoints delta",
                )
            )
        d_paths = _metric(ag, "attack_paths") - _metric(base, "attack_paths")
        if d_paths > 0:
            factors.append(
                _factor(
                    FACTOR_NEW_ATTACK_PATHS,
                    d_paths,
                    CHANGE_RISK_WEIGHTS,
                    evidence="attack_paths delta",
                )
            )
        d_ext = _metric(ag, "external_services") - _metric(base, "external_services")
        if d_ext > 0:
            factors.append(
                _factor(
                    FACTOR_EXTERNAL_SERVICES,
                    d_ext,
                    CHANGE_RISK_WEIGHTS,
                    evidence="external_services delta",
                )
            )
        d_sec = _metric(ag, "secret_assets") - _metric(base, "secret_assets")
        if d_sec > 0:
            factors.append(
                _factor(
                    FACTOR_SECRET_ASSETS,
                    d_sec,
                    CHANGE_RISK_WEIGHTS,
                    evidence="secret_assets delta",
                )
            )

    # Category-driven contributions from detector outputs
    cat_map = {
        "PRIVILEGE_EXPANSION": FACTOR_PRIVILEGE_TRANSITIONS,
        "TENANT_ISOLATION_RISK": FACTOR_CROSS_TENANT,
        "TOOL_PERMISSION_RISK": FACTOR_AI_TOOLS,
        "AI_AGENT_PRIVILEGE_RISK": FACTOR_AI_TOOLS,
        "AUTHORIZATION_DRIFT": FACTOR_AUTHZ_DRIFT,
        "REGRESSION_RISK": FACTOR_WEAKENED_CONTROLS,
        "SECURITY_CONTROL_COMPLEXITY": FACTOR_WEAKENED_CONTROLS,
    }
    seen: set[str] = set()
    for r in risks:
        cat = str(r.get("category") or "")
        fname = cat_map.get(cat)
        if not fname or fname in seen:
            continue
        if str(r.get("change_status") or "") in {"RISK_DECREASED", "RESOLVED", "STABLE"} and cat != "REGRESSION_RISK":
            if str(r.get("change_status")) != "RISK_INCREASED":
                # Still count NEW_RISK / RISK_INCREASED primarily
                if str(r.get("change_status")) not in {"NEW_RISK", "RISK_INCREASED"}:
                    continue
        seen.add(fname)
        factors.append(
            _factor(
                fname,
                1,
                CHANGE_RISK_WEIGHTS,
                evidence=f"detector:{cat}:{r.get('risk_id')}",
            )
        )

    mem = memory_regressions or {}
    regressed = mem.get("REGRESSED") or mem.get("regressed") or []
    if isinstance(regressed, dict):
        regressed = regressed.get("REGRESSED") or regressed.get("items") or []
    if isinstance(regressed, list) and regressed:
        factors.append(
            _factor(
                FACTOR_MEMORY_REGRESSIONS,
                len(regressed),
                CHANGE_RISK_WEIGHTS,
                evidence="security_memory regressions",
            )
        )

    total = round(sum(float(f["weight"]) for f in factors), 3)
    band = _band(total)
    return {
        "model": "change_risk_v1",
        "factors": factors,
        "total_weight": total,
        "band": band,
        "confidence": _score_confidence(factors),
        "explanation": (
            "Change-Risk is the sum of listed factor weights from observed deltas "
            "and detector signals. It is not a probability of exploitation."
        ),
    }


def compute_security_debt(
    *,
    attack_graph: dict[str, Any] | None = None,
    twin: dict[str, Any] | None = None,
    memory_regressions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Security Debt factor breakdown — never a meaningless single number alone."""
    ag = attack_graph or {}
    twin = twin or {}
    factors: list[dict[str, Any]] = []

    paths = ag.get("paths") or []
    live = sum(
        1
        for p in paths
        if str(p.get("status") or "").upper() in {"CONFIRMED", "LIKELY", "UNVERIFIED"}
    )
    if live:
        factors.append(
            _factor(
                DEBT_UNRESOLVED_PATHS,
                live,
                DEBT_WEIGHTS,
                evidence="open/likely attack paths in current graph",
            )
        )

    weak = 0
    for p in paths:
        for c in p.get("controls_encountered") or []:
            if isinstance(c, dict) and str(c.get("effectiveness") or "").lower() in {
                "weak",
                "bypassed",
                "missing",
                "ineffective",
            }:
                weak += 1
    if weak:
        factors.append(
            _factor(
                DEBT_WEAK_CONTROLS,
                weak,
                DEBT_WEIGHTS,
                evidence="weak/bypassed control encounters on paths",
            )
        )

    nodes = list((ag.get("graph") or {}).get("nodes") or [])
    ext = sum(1 for n in nodes if n.get("type") == "external_service")
    if ext:
        factors.append(
            _factor(
                DEBT_EXTERNAL_TRUST,
                ext,
                DEBT_WEIGHTS,
                evidence="external_service nodes",
            )
        )
    secrets = sum(
        1
        for n in nodes
        if n.get("type") == "asset"
        and str(n.get("kind") or "").lower() in {"secret", "credential", "token"}
    )
    if secrets:
        factors.append(
            _factor(
                DEBT_SECRET_SURFACE,
                secrets,
                DEBT_WEIGHTS,
                evidence="secret/credential assets",
            )
        )
    ai = sum(1 for n in nodes if n.get("type") in {"ai_component", "tool"})
    entities = twin.get("entities") or []
    ai += sum(1 for e in entities if e.get("type") in {"AIAgent", "AITool", "MCPServer"})
    if ai:
        factors.append(
            _factor(
                DEBT_AI_SURFACE,
                ai,
                DEBT_WEIGHTS,
                evidence="AI agent/tool/MCP entities",
            )
        )
    controls = sum(1 for n in nodes if n.get("type") == "control")
    if controls >= 5:
        factors.append(
            _factor(
                DEBT_COMPLEX_CONTROLS,
                controls,
                DEBT_WEIGHTS,
                evidence="control node count (mesh complexity)",
            )
        )

    mem = memory_regressions or {}
    regressed = mem.get("REGRESSED") or mem.get("regressed") or []
    if isinstance(regressed, dict):
        regressed = regressed.get("REGRESSED") or regressed.get("items") or []
    if isinstance(regressed, list) and regressed:
        factors.append(
            _factor(
                DEBT_HISTORICAL_REGRESSIONS,
                len(regressed),
                DEBT_WEIGHTS,
                evidence="security_memory historical regressions",
            )
        )

    total = round(sum(float(f["weight"]) for f in factors), 3)
    return {
        "model": "security_debt_v1",
        "factors": factors,
        "total_weight": total,
        "band": _band(total),
        "summary": {
            "factor_count": len(factors),
            "top_factors": sorted(factors, key=lambda f: f["weight"], reverse=True)[:5],
        },
        "explanation": (
            "Security Debt is a weighted sum of listed structural factors. "
            "Use the factor list for decisions; do not treat the total as a severity grade."
        ),
    }


def attach_scores_to_risks(
    risks: list[dict[str, Any]],
    change_risk: dict[str, Any],
) -> list[dict[str, Any]]:
    """Copy relevant score factors onto each risk for explainability."""
    factors = change_risk.get("factors") or []
    out: list[dict[str, Any]] = []
    for r in risks:
        item = dict(r)
        if not item.get("score_factors"):
            cat = str(item.get("category") or "")
            related = [
                f
                for f in factors
                if cat.lower() in str(f.get("evidence") or "").lower()
                or cat.replace("_", "").lower() in str(f.get("factor") or "").replace("_", "").lower()
            ]
            item["score_factors"] = related or list(factors)[:3]
        if item.get("change_risk_score") is None and change_risk.get("total_weight") is not None:
            # Per-risk contribution approx from its own factors
            own = item.get("score_factors") or []
            item["change_risk_score"] = round(
                sum(float(f.get("weight") or 0) for f in own), 3
            )
        out.append(item)
    return out


def _band(total: float) -> str:
    if total <= 0:
        return "NONE"
    if total < 3:
        return "LOW"
    if total < 8:
        return "MODERATE"
    if total < 15:
        return "ELEVATED"
    return "HIGH"


def _score_confidence(factors: list[dict[str, Any]]) -> str:
    if not factors:
        return CONF_UNKNOWN
    if any("memory" in str(f.get("evidence") or "") for f in factors):
        return CONF_HIGH
    if len(factors) >= 3:
        return CONF_MEDIUM
    return CONF_LOW
