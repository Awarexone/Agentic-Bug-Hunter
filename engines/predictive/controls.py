"""Security control complexity / regression predictive detectors."""

from __future__ import annotations

from typing import Any

from engines.predictive.model import risk_to_dict, try_build_predictive_risk
from engines.predictive.schema import (
    CAT_REGRESSION_RISK,
    CAT_SECURITY_CONTROL_COMPLEXITY,
    CONF_HIGH,
    CONF_LOW,
    CONF_MEDIUM,
    HORIZON_IMMEDIATE,
    HORIZON_NEAR_TERM,
    STATUS_RISK_INCREASED,
    STATUS_STABLE,
)


def _control_stats(ag: dict[str, Any]) -> dict[str, Any]:
    nodes = list((ag.get("graph") or {}).get("nodes") or [])
    controls = [n for n in nodes if n.get("type") == "control"]
    weak = 0
    for path in ag.get("paths") or []:
        for c in path.get("controls_encountered") or []:
            if isinstance(c, dict) and str(c.get("effectiveness") or "").lower() in {
                "weak",
                "bypassed",
                "missing",
                "ineffective",
            }:
                weak += 1
    return {"control_count": len(controls), "weak_encounters": weak}


def detect_control_risks(
    *,
    attack_graph: dict[str, Any] | None = None,
    twin: dict[str, Any] | None = None,
    base_attack_graph: dict[str, Any] | None = None,
    base_twin: dict[str, Any] | None = None,
    memory_regressions: dict[str, Any] | None = None,
    mode: str = "default",
) -> list[dict[str, Any]]:
    del twin, base_twin, mode
    ag = attack_graph or {}
    if not ag and not memory_regressions:
        return []

    risks: list[dict[str, Any]] = []
    cur = _control_stats(ag) if ag else {"control_count": 0, "weak_encounters": 0}
    base = _control_stats(base_attack_graph) if base_attack_graph else None

    # Complexity: many overlapping controls with weak encounters
    if cur["control_count"] >= 5 and cur["weak_encounters"] > 0:
        risk = try_build_predictive_risk(
            category=CAT_SECURITY_CONTROL_COMPLEXITY,
            title=(
                f"{cur['control_count']} controls with {cur['weak_encounters']} "
                "weak/bypass encounters"
            ),
            trigger_change={
                "kind": "control_complexity",
                "observation": "dense control graph with weak effectiveness signals",
                "controls": cur["control_count"],
                "weak_encounters": cur["weak_encounters"],
            },
            supporting_evidence=[{"source": "attack_graph", **cur}],
            security_effect="Complex control meshes are harder to reason about and easier to misconfigure",
            risk_signal="Security control complexity elevates misconfiguration risk",
            confidence=CONF_MEDIUM if base else CONF_LOW,
            time_horizon=HORIZON_NEAR_TERM,
            change_status=STATUS_STABLE if not base else STATUS_RISK_INCREASED,
        )
        if risk:
            risks.append(risk_to_dict(risk))

    if base is not None and cur["weak_encounters"] > base["weak_encounters"]:
        delta = cur["weak_encounters"] - base["weak_encounters"]
        risk = try_build_predictive_risk(
            category=CAT_REGRESSION_RISK,
            title=f"{delta} additional weakened control encounter(s)",
            trigger_change={
                "kind": "control_regression",
                "observation": "weak control encounters increased vs base",
                "before": base["weak_encounters"],
                "after": cur["weak_encounters"],
            },
            supporting_evidence=[
                {
                    "source": "attack_graph",
                    "before": base,
                    "after": cur,
                }
            ],
            security_effect="Controls that previously blocked paths may no longer hold",
            risk_signal="Control regression trend",
            confidence=CONF_HIGH,
            time_horizon=HORIZON_IMMEDIATE,
            change_status=STATUS_RISK_INCREASED,
        )
        if risk:
            risks.append(risk_to_dict(risk))

    # Memory regressions only when real data exists
    mem = memory_regressions or {}
    regressed = mem.get("REGRESSED") or mem.get("regressed") or mem.get("regressions") or []
    if isinstance(regressed, dict):
        regressed = (
            regressed.get("REGRESSED")
            or regressed.get("items")
            or regressed.get("findings")
            or []
        )
    if isinstance(regressed, list) and regressed:
        risk = try_build_predictive_risk(
            category=CAT_REGRESSION_RISK,
            title=f"{len(regressed)} historical regression(s) from Security Memory",
            trigger_change={
                "kind": "memory_regression",
                "observation": "Security Memory recorded regressions between snapshots",
                "count": len(regressed),
            },
            supporting_evidence=[
                {
                    "source": "security_memory",
                    "sample": [
                        (r if isinstance(r, dict) else {"summary": str(r)})
                        for r in regressed[:5]
                    ],
                }
            ],
            historical_evidence=[
                {
                    "source": "security_memory",
                    "kind": "regression",
                    "item": (r if isinstance(r, dict) else {"summary": str(r)}),
                }
                for r in regressed[:10]
            ],
            security_effect="Previously improved issues reappeared — structural risk rising",
            risk_signal="Historical regression evidence elevates predictive risk",
            confidence=CONF_HIGH,
            time_horizon=HORIZON_IMMEDIATE,
            change_status=STATUS_RISK_INCREASED,
        )
        if risk:
            risks.append(risk_to_dict(risk))

    return risks
