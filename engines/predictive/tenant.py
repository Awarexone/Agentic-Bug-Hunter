"""Tenant isolation predictive detectors."""

from __future__ import annotations

from typing import Any

from engines.predictive.model import risk_to_dict, try_build_predictive_risk
from engines.predictive.schema import (
    CAT_TENANT_ISOLATION_RISK,
    CONF_HIGH,
    CONF_LOW,
    CONF_MEDIUM,
    HORIZON_IMMEDIATE,
    HORIZON_NEAR_TERM,
    STATUS_RISK_INCREASED,
    STATUS_STABLE,
)


def _tenant_edges(ag: dict[str, Any]) -> list[dict[str, Any]]:
    edges = list((ag.get("graph") or {}).get("edges") or [])
    out = [
        e
        for e in edges
        if str(e.get("type") or "") in {"crosses_tenant", "CROSSES_TENANT"}
        or "tenant" in str(e.get("type") or "").lower()
    ]
    for path in ag.get("paths") or []:
        tags = {str(t).lower() for t in (path.get("tags") or [])}
        if tags & {"tenant", "cross_tenant", "idor", "horizontal"}:
            out.append(
                {
                    "path_id": path.get("path_id") or path.get("id"),
                    "tags": list(tags),
                    "status": path.get("status"),
                }
            )
    return out


def detect_tenant_risks(
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
    cur = _tenant_edges(ag)
    base_n = len(_tenant_edges(base_attack_graph)) if base_attack_graph else None

    if cur and base_n is not None and len(cur) > base_n:
        delta = len(cur) - base_n
        risk = try_build_predictive_risk(
            category=CAT_TENANT_ISOLATION_RISK,
            title=f"{delta} new cross-tenant / isolation edge(s)",
            trigger_change={
                "kind": "tenant_isolation_delta",
                "observation": "cross-tenant edges or tagged paths increased",
                "before": base_n,
                "after": len(cur),
                "delta": delta,
            },
            supporting_evidence=[
                {"source": "attack_graph", "count": len(cur), "sample": cur[:5]}
            ],
            security_effect="Tenant isolation boundary may be weaker than before",
            risk_signal="Increasing cross-tenant reachability risk",
            confidence=CONF_HIGH if delta >= 2 else CONF_MEDIUM,
            time_horizon=HORIZON_IMMEDIATE,
            change_status=STATUS_RISK_INCREASED,
        )
        if risk:
            risks.append(risk_to_dict(risk))
    elif cur:
        risk = try_build_predictive_risk(
            category=CAT_TENANT_ISOLATION_RISK,
            title=f"{len(cur)} tenant-isolation signal(s) observed",
            trigger_change={
                "kind": "tenant_isolation_snapshot",
                "observation": "cross-tenant edges or tagged paths present",
                "count": len(cur),
            },
            supporting_evidence=[
                {"source": "attack_graph", "count": len(cur), "sample": cur[:5]}
            ],
            security_effect="Cross-tenant reachability exists in the structural model",
            risk_signal="Tenant isolation risk present (no growth claim without base)",
            confidence=CONF_LOW if base_n is None else CONF_MEDIUM,
            time_horizon=HORIZON_NEAR_TERM,
            change_status=STATUS_STABLE,
        )
        if risk:
            risks.append(risk_to_dict(risk))

    return risks
