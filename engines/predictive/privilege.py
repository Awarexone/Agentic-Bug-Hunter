"""Privilege expansion predictive detectors."""

from __future__ import annotations

from typing import Any

from engines.predictive.model import risk_to_dict, try_build_predictive_risk
from engines.predictive.schema import (
    CAT_CLOUD_PRIVILEGE_RISK,
    CAT_PRIVILEGE_EXPANSION,
    CONF_HIGH,
    CONF_LOW,
    CONF_MEDIUM,
    HORIZON_IMMEDIATE,
    HORIZON_NEAR_TERM,
    STATUS_NEW_RISK,
    STATUS_RISK_INCREASED,
    STATUS_STABLE,
)


def _privilege_transitions(ag: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        from engines.attack_graph import privilege as priv_mod

        # Prefer module helpers if present
        if hasattr(priv_mod, "analyze_privilege_transitions"):
            return list(priv_mod.analyze_privilege_transitions(ag) or [])
        if hasattr(priv_mod, "privilege_transitions"):
            return list(priv_mod.privilege_transitions(ag) or [])
    except Exception:  # noqa: BLE001
        pass

    # Fallback: scan path tags / edges for escalation language
    out: list[dict[str, Any]] = []
    for path in ag.get("paths") or []:
        tags = {str(t).lower() for t in (path.get("tags") or [])}
        if tags & {"privilege_escalation", "vertical", "confused_deputy", "horizontal"}:
            out.append(
                {
                    "path_id": path.get("path_id") or path.get("id"),
                    "tags": list(tags),
                    "status": path.get("status"),
                }
            )
        for hop in path.get("hops") or []:
            if isinstance(hop, dict) and "escalat" in str(hop.get("type") or "").lower():
                out.append({"path_id": path.get("path_id") or path.get("id"), "hop": hop})
    edges = (ag.get("graph") or {}).get("edges") or []
    for e in edges:
        if str(e.get("type") or "") in {"escalates_to", "grants"}:
            out.append({"edge": e})
    return out


def detect_privilege_risks(
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
    cur = _privilege_transitions(ag)
    base_n = len(_privilege_transitions(base_attack_graph)) if base_attack_graph else None

    if cur and base_n is not None and len(cur) > base_n:
        delta = len(cur) - base_n
        risk = try_build_predictive_risk(
            category=CAT_PRIVILEGE_EXPANSION,
            title=f"{delta} additional privilege transition(s) vs base",
            trigger_change={
                "kind": "privilege_transition_delta",
                "observation": "privilege transitions increased",
                "before": base_n,
                "after": len(cur),
                "delta": delta,
            },
            supporting_evidence=[
                {"source": "attack_graph.privilege", "count": len(cur), "sample": cur[:5]}
            ],
            security_effect="More paths admit vertical/horizontal privilege movement",
            risk_signal="Privilege expansion trend from structural transitions",
            confidence=CONF_HIGH if delta >= 2 else CONF_MEDIUM,
            time_horizon=HORIZON_IMMEDIATE,
            change_status=STATUS_RISK_INCREASED,
            related_paths=[
                str(t.get("path_id")) for t in cur if t.get("path_id")
            ][:10],
        )
        if risk:
            risks.append(risk_to_dict(risk))
    elif cur:
        risk = try_build_predictive_risk(
            category=CAT_PRIVILEGE_EXPANSION,
            title=f"{len(cur)} privilege transition(s) observed in graph",
            trigger_change={
                "kind": "privilege_transition_snapshot",
                "observation": "privilege transitions present",
                "count": len(cur),
            },
            supporting_evidence=[
                {"source": "attack_graph.privilege", "count": len(cur), "sample": cur[:5]}
            ],
            security_effect="Privilege movement edges exist in the current model",
            risk_signal="Privilege surface present (growth not claimed without base)",
            confidence=CONF_LOW if base_n is None else CONF_MEDIUM,
            time_horizon=HORIZON_NEAR_TERM,
            change_status=STATUS_STABLE if base_n is None else STATUS_NEW_RISK,
        )
        if risk:
            risks.append(risk_to_dict(risk))

    # Cloud privilege — cloud_resource / IAM-ish nodes
    nodes = list((ag.get("graph") or {}).get("nodes") or [])
    cloud = [
        n
        for n in nodes
        if n.get("type") in {"cloud_resource", "asset"}
        and any(
            k in str(n.get("kind") or "").lower()
            or k in str(n.get("id") or "").lower()
            for k in ("iam", "role", "policy", "cloud", "aws", "gcp", "azure")
        )
    ]
    if cloud:
        risk = try_build_predictive_risk(
            category=CAT_CLOUD_PRIVILEGE_RISK,
            title=f"{len(cloud)} cloud/IAM-related node(s) in model",
            trigger_change={
                "kind": "cloud_privilege_nodes",
                "observation": "cloud or IAM-related nodes observed",
                "count": len(cloud),
            },
            supporting_evidence=[
                {
                    "source": "attack_graph",
                    "ids": [str(n.get("id")) for n in cloud[:10]],
                }
            ],
            security_effect="Cloud privilege objects concentrate over-permission risk",
            risk_signal="Cloud privilege surface warrants least-privilege review",
            confidence=CONF_LOW,
            time_horizon=HORIZON_NEAR_TERM,
            change_status=STATUS_STABLE,
            related_entities=[str(n.get("id")) for n in cloud[:10]],
        )
        if risk:
            risks.append(risk_to_dict(risk))

    return risks
