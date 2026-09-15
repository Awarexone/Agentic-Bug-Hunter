"""Authorization drift predictive detectors."""

from __future__ import annotations

from typing import Any

from engines.predictive.model import risk_to_dict, try_build_predictive_risk
from engines.predictive.schema import (
    CAT_AUTHORIZATION_DRIFT,
    CONF_HIGH,
    CONF_LOW,
    CONF_MEDIUM,
    HORIZON_IMMEDIATE,
    HORIZON_NEAR_TERM,
    STATUS_RISK_INCREASED,
    STATUS_STABLE,
)


def _authz_signals(ag: dict[str, Any]) -> dict[str, Any]:
    nodes = list((ag.get("graph") or {}).get("nodes") or [])
    edges = list((ag.get("graph") or {}).get("edges") or [])
    controls = [n for n in nodes if n.get("type") == "control"]
    authz_controls = [
        c
        for c in controls
        if any(
            k in str(c.get("id") or "").lower()
            or k in str(c.get("name") or "").lower()
            or k in str(c.get("kind") or "").lower()
            for k in ("authz", "authoriz", "rbac", "acl", "permission", "policy")
        )
    ]
    weakened = []
    for path in ag.get("paths") or []:
        for c in path.get("controls_encountered") or []:
            if not isinstance(c, dict):
                continue
            eff = str(c.get("effectiveness") or "").lower()
            if eff in {"weak", "bypassed", "missing", "ineffective", "unknown"}:
                name = str(c.get("id") or c.get("name") or "")
                if any(k in name.lower() for k in ("auth", "rbac", "acl", "perm")):
                    weakened.append(c)
    grants = [e for e in edges if str(e.get("type") or "") in {"grants", "escalates_to"}]
    return {
        "authz_controls": authz_controls,
        "weakened": weakened,
        "grants": grants,
        "control_count": len(controls),
        "authz_control_count": len(authz_controls),
    }


def detect_auth_drift_risks(
    *,
    attack_graph: dict[str, Any] | None = None,
    twin: dict[str, Any] | None = None,
    base_attack_graph: dict[str, Any] | None = None,
    base_twin: dict[str, Any] | None = None,
    memory_regressions: dict[str, Any] | None = None,
    mode: str = "default",
) -> list[dict[str, Any]]:
    del twin, base_twin, memory_regressions, mode
    ag = attack_graph or {}
    if not ag:
        return []

    risks: list[dict[str, Any]] = []
    cur = _authz_signals(ag)
    base = _authz_signals(base_attack_graph) if base_attack_graph else None

    if base is not None:
        # Fewer authz controls or more weakened → drift
        lost = base["authz_control_count"] - cur["authz_control_count"]
        weak_delta = len(cur["weakened"]) - len(base["weakened"])
        grant_delta = len(cur["grants"]) - len(base["grants"])

        if lost > 0 or weak_delta > 0 or grant_delta > 0:
            risk = try_build_predictive_risk(
                category=CAT_AUTHORIZATION_DRIFT,
                title="Authorization posture drifted vs base",
                trigger_change={
                    "kind": "authorization_drift",
                    "observation": "authz controls/grants/weakened edges changed",
                    "authz_controls_lost": max(lost, 0),
                    "weakened_delta": weak_delta,
                    "grants_delta": grant_delta,
                },
                supporting_evidence=[
                    {
                        "source": "attack_graph",
                        "before": {
                            "authz_controls": base["authz_control_count"],
                            "weakened": len(base["weakened"]),
                            "grants": len(base["grants"]),
                        },
                        "after": {
                            "authz_controls": cur["authz_control_count"],
                            "weakened": len(cur["weakened"]),
                            "grants": len(cur["grants"]),
                        },
                    }
                ],
                security_effect="Authorization checks may be thinner or more bypassable",
                risk_signal="Authorization drift — review new grants and weakened controls",
                confidence=CONF_HIGH if lost > 0 or weak_delta > 0 else CONF_MEDIUM,
                time_horizon=HORIZON_IMMEDIATE,
                change_status=STATUS_RISK_INCREASED,
            )
            if risk:
                risks.append(risk_to_dict(risk))
    elif cur["weakened"] or (cur["grants"] and cur["authz_control_count"] == 0):
        risk = try_build_predictive_risk(
            category=CAT_AUTHORIZATION_DRIFT,
            title="Weak or missing authorization controls observed",
            trigger_change={
                "kind": "authorization_snapshot",
                "observation": "weakened authz controls or grants without authz controls",
                "weakened": len(cur["weakened"]),
                "grants": len(cur["grants"]),
                "authz_controls": cur["authz_control_count"],
            },
            supporting_evidence=[
                {
                    "source": "attack_graph",
                    "weakened_sample": cur["weakened"][:5],
                    "grants_count": len(cur["grants"]),
                }
            ],
            security_effect=(
                "Authorization gaps increase the likelihood of "
                "authorization-bypass or privilege-misuse conditions"
            ),
            risk_signal="Authorization weakness present (no baseline drift claim)",
            confidence=CONF_LOW,
            time_horizon=HORIZON_NEAR_TERM,
            change_status=STATUS_STABLE,
        )
        if risk:
            risks.append(risk_to_dict(risk))

    return risks
