"""Attack-surface / API / network exposure predictive detectors."""

from __future__ import annotations

from typing import Any

from engines.predictive.model import try_build_predictive_risk, risk_to_dict
from engines.predictive.schema import (
    CAT_API_EXPOSURE_RISK,
    CAT_ARCHITECTURE_DRIFT,
    CAT_ATTACK_SURFACE_EXPANSION,
    CAT_NETWORK_EXPOSURE_RISK,
    CAT_TRUST_BOUNDARY_EXPANSION,
    CONF_HIGH,
    CONF_LOW,
    CONF_MEDIUM,
    HORIZON_IMMEDIATE,
    HORIZON_NEAR_TERM,
    STATUS_NEW_RISK,
    STATUS_RISK_INCREASED,
    STATUS_STABLE,
)


def _nodes(ag: dict[str, Any]) -> list[dict[str, Any]]:
    return list((ag.get("graph") or {}).get("nodes") or [])


def _surface_counts(ag: dict[str, Any]) -> dict[str, int]:
    nodes = _nodes(ag)
    public = sum(
        1
        for n in nodes
        if n.get("type") == "entrypoint"
        and str(n.get("reachability") or "").lower()
        in {"public", "unauthenticated", "internet"}
    )
    entries = sum(1 for n in nodes if n.get("type") == "entrypoint")
    externals = sum(1 for n in nodes if n.get("type") == "external_service")
    boundaries = sum(1 for n in nodes if n.get("type") == "trust_boundary")
    try:
        from engines.attack_graph.predictive import surface_metrics

        m = surface_metrics(ag)
        return {
            "public_entrypoints": int(m.get("public_entrypoints") or public),
            "entrypoints": entries,
            "external_services": int(m.get("external_services") or externals),
            "trust_boundaries": boundaries,
            "attack_paths": int(m.get("attack_paths") or len(ag.get("paths") or [])),
        }
    except Exception:  # noqa: BLE001
        return {
            "public_entrypoints": public,
            "entrypoints": entries,
            "external_services": externals,
            "trust_boundaries": boundaries,
            "attack_paths": len(ag.get("paths") or []),
        }


def detect_surface_risks(
    *,
    attack_graph: dict[str, Any] | None = None,
    twin: dict[str, Any] | None = None,
    base_attack_graph: dict[str, Any] | None = None,
    base_twin: dict[str, Any] | None = None,
    memory_regressions: dict[str, Any] | None = None,
    mode: str = "default",
) -> list[dict[str, Any]]:
    """Surface / trust-boundary / API / network predictive risks from observed graph."""
    del twin, base_twin, memory_regressions, mode  # unused; soft interface
    ag = attack_graph or {}
    if not ag:
        return []

    risks: list[dict[str, Any]] = []
    cur = _surface_counts(ag)
    base = _surface_counts(base_attack_graph) if base_attack_graph else None

    # --- Attack surface expansion (diff when base present) ---
    if base is not None:
        delta_public = cur["public_entrypoints"] - base["public_entrypoints"]
        if delta_public > 0:
            risk = try_build_predictive_risk(
                category=CAT_ATTACK_SURFACE_EXPANSION,
                title=f"{delta_public} new publicly-reachable entrypoint(s)",
                trigger_change={
                    "kind": "entrypoint_delta",
                    "observation": "public_entrypoints increased between base and head",
                    "metric": "public_entrypoints",
                    "before": base["public_entrypoints"],
                    "after": cur["public_entrypoints"],
                    "delta": delta_public,
                },
                supporting_evidence=[
                    {
                        "source": "attack_graph",
                        "metric": "public_entrypoints",
                        "before": base["public_entrypoints"],
                        "after": cur["public_entrypoints"],
                    }
                ],
                security_effect="Attack surface widened via newly reachable entrypoints",
                risk_signal="Increasing exposure to unauthenticated or public callers",
                confidence=CONF_HIGH if delta_public >= 2 else CONF_MEDIUM,
                time_horizon=HORIZON_IMMEDIATE,
                change_status=STATUS_RISK_INCREASED,
            )
            if risk:
                risks.append(risk_to_dict(risk))

        delta_ext = cur["external_services"] - base["external_services"]
        if delta_ext > 0:
            risk = try_build_predictive_risk(
                category=CAT_TRUST_BOUNDARY_EXPANSION,
                title=f"{delta_ext} new external service dependency(ies)",
                trigger_change={
                    "kind": "external_service_delta",
                    "observation": "external_services increased",
                    "before": base["external_services"],
                    "after": cur["external_services"],
                    "delta": delta_ext,
                },
                supporting_evidence=[
                    {
                        "source": "attack_graph",
                        "metric": "external_services",
                        "before": base["external_services"],
                        "after": cur["external_services"],
                    }
                ],
                security_effect="Trust boundary expands to additional third parties",
                risk_signal="Wider blast radius if an external integration is abused",
                confidence=CONF_MEDIUM,
                time_horizon=HORIZON_NEAR_TERM,
                change_status=STATUS_RISK_INCREASED,
            )
            if risk:
                risks.append(risk_to_dict(risk))

        delta_paths = cur["attack_paths"] - base["attack_paths"]
        if delta_paths > 0:
            risk = try_build_predictive_risk(
                category=CAT_ARCHITECTURE_DRIFT,
                title=f"{delta_paths} additional attack path(s) in structural model",
                trigger_change={
                    "kind": "path_count_delta",
                    "observation": "attack path count increased",
                    "before": base["attack_paths"],
                    "after": cur["attack_paths"],
                    "delta": delta_paths,
                },
                supporting_evidence=[
                    {
                        "source": "attack_graph",
                        "metric": "attack_paths",
                        "before": base["attack_paths"],
                        "after": cur["attack_paths"],
                    }
                ],
                security_effect="Architecture now admits more chained reachability",
                risk_signal="Structural drift toward denser attack connectivity",
                confidence=CONF_MEDIUM,
                time_horizon=HORIZON_NEAR_TERM,
                change_status=STATUS_RISK_INCREASED,
            )
            if risk:
                risks.append(risk_to_dict(risk))
    else:
        # Single snapshot — describe observed surface without claiming growth
        if cur["public_entrypoints"] > 0:
            risk = try_build_predictive_risk(
                category=CAT_ATTACK_SURFACE_EXPANSION,
                title=(
                    f"{cur['public_entrypoints']} publicly-reachable entrypoint(s) "
                    "form the observed attack surface"
                ),
                trigger_change={
                    "kind": "surface_snapshot",
                    "observation": "public entrypoints present in current graph",
                    "metric": "public_entrypoints",
                    "value": cur["public_entrypoints"],
                },
                supporting_evidence=[
                    {
                        "source": "attack_graph",
                        "metric": "public_entrypoints",
                        "value": cur["public_entrypoints"],
                    }
                ],
                security_effect="Public surface is a persistent exposure plane",
                risk_signal="Emerging attack surface (snapshot; no baseline growth claim)",
                confidence=CONF_LOW,
                time_horizon=HORIZON_NEAR_TERM,
                change_status=STATUS_STABLE,
            )
            if risk:
                risks.append(risk_to_dict(risk))

        if cur["external_services"] > 0:
            risk = try_build_predictive_risk(
                category=CAT_TRUST_BOUNDARY_EXPANSION,
                title=f"{cur['external_services']} external service(s) in trust boundary",
                trigger_change={
                    "kind": "trust_boundary_snapshot",
                    "observation": "external services observed",
                    "value": cur["external_services"],
                },
                supporting_evidence=[
                    {
                        "source": "attack_graph",
                        "metric": "external_services",
                        "value": cur["external_services"],
                    }
                ],
                security_effect="External trust edges widen the system boundary",
                risk_signal="Trust-boundary surface present (no growth claim without base)",
                confidence=CONF_LOW,
                time_horizon=HORIZON_NEAR_TERM,
                change_status=STATUS_STABLE,
            )
            if risk:
                risks.append(risk_to_dict(risk))

    # API exposure — entrypoints that look like HTTP/API
    api_nodes = [
        n
        for n in _nodes(ag)
        if n.get("type") == "entrypoint"
        and any(
            k in str(n.get("id") or "").lower() or k in str(n.get("name") or "").lower()
            for k in ("/api", "api.", "graphql", "rest", "rpc")
        )
    ]
    if api_nodes:
        public_api = [
            n
            for n in api_nodes
            if str(n.get("reachability") or "").lower()
            in {"public", "unauthenticated", "internet"}
        ]
        if public_api or (base is not None and len(api_nodes) > 0):
            risk = try_build_predictive_risk(
                category=CAT_API_EXPOSURE_RISK,
                title=f"{len(api_nodes)} API-shaped entrypoint(s) observed",
                trigger_change={
                    "kind": "api_entrypoint_observed",
                    "observation": "API-like entrypoints in graph",
                    "count": len(api_nodes),
                    "public_count": len(public_api),
                },
                supporting_evidence=[
                    {
                        "source": "attack_graph",
                        "ids": [str(n.get("id")) for n in api_nodes[:10]],
                        "public_count": len(public_api),
                    }
                ],
                security_effect="API surfaces concentrate authz and input-validation risk",
                risk_signal="API exposure warrants authz and input-path review",
                confidence=CONF_MEDIUM if public_api else CONF_LOW,
                time_horizon=HORIZON_NEAR_TERM,
                change_status=(
                    STATUS_RISK_INCREASED
                    if base and public_api
                    else (STATUS_NEW_RISK if public_api else STATUS_STABLE)
                ),
                related_entities=[str(n.get("id")) for n in api_nodes[:10]],
            )
            if risk:
                risks.append(risk_to_dict(risk))

    # Network exposure — internet/public reachability tags
    net_exposed = [
        n
        for n in _nodes(ag)
        if str(n.get("reachability") or "").lower() in {"public", "internet", "unauthenticated"}
        or "network" in str(n.get("kind") or "").lower()
    ]
    if net_exposed and (base is not None or len(net_exposed) >= 2):
        risk = try_build_predictive_risk(
            category=CAT_NETWORK_EXPOSURE_RISK,
            title=f"{len(net_exposed)} network-reachable node(s) observed",
            trigger_change={
                "kind": "network_reachability",
                "observation": "nodes with public/internet reachability",
                "count": len(net_exposed),
            },
            supporting_evidence=[
                {
                    "source": "attack_graph",
                    "count": len(net_exposed),
                    "sample_ids": [str(n.get("id")) for n in net_exposed[:8]],
                }
            ],
            security_effect="Network-reachable components enlarge remote attack options",
            risk_signal="Network exposure trend from observed reachability tags",
            confidence=CONF_MEDIUM if base is not None else CONF_LOW,
            time_horizon=HORIZON_NEAR_TERM,
            change_status=STATUS_RISK_INCREASED if base else STATUS_STABLE,
            related_entities=[str(n.get("id")) for n in net_exposed[:8]],
        )
        if risk:
            risks.append(risk_to_dict(risk))

    return risks
