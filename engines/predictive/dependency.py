"""Dependency / external integration / secret / sensitive-data detectors."""

from __future__ import annotations

from typing import Any

from engines.predictive.model import risk_to_dict, try_build_predictive_risk
from engines.predictive.schema import (
    CAT_DEPENDENCY_RISK,
    CAT_EXTERNAL_INTEGRATION_RISK,
    CAT_SECRET_MANAGEMENT_RISK,
    CAT_SENSITIVE_DATA_FLOW,
    CONF_LOW,
    CONF_MEDIUM,
    HORIZON_LONGER_TERM,
    HORIZON_NEAR_TERM,
    STATUS_NEW_RISK,
    STATUS_RISK_INCREASED,
    STATUS_STABLE,
)


def _count_type(ag: dict[str, Any], node_type: str, *, kinds: set[str] | None = None) -> int:
    n = 0
    for node in (ag.get("graph") or {}).get("nodes") or []:
        if node.get("type") != node_type:
            continue
        if kinds is None:
            n += 1
            continue
        if str(node.get("kind") or "").lower() in kinds:
            n += 1
    return n


def _sbom_hints(ag: dict[str, Any]) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    sbom = ag.get("sbom") or ag.get("dependencies") or {}
    if isinstance(sbom, dict):
        for key in ("packages", "components", "dependencies"):
            items = sbom.get(key)
            if isinstance(items, list) and items:
                hints.append({"source": "sbom", "key": key, "count": len(items)})
    # Soft SBOM module
    try:
        from engines.attack_graph import sbom as sbom_mod

        if hasattr(sbom_mod, "summarize_dependencies") and callable(
            sbom_mod.summarize_dependencies
        ):
            summary = sbom_mod.summarize_dependencies(ag)
            if isinstance(summary, dict) and summary:
                hints.append({"source": "attack_graph.sbom", **summary})
    except Exception:  # noqa: BLE001
        pass
    return hints


def detect_dependency_risks(
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
    ext = _count_type(ag, "external_service")
    base_ext = _count_type(base_attack_graph, "external_service") if base_attack_graph else None
    secrets = _count_type(
        ag, "asset", kinds={"secret", "credential", "token", "api_key", "password"}
    )
    base_secrets = (
        _count_type(
            base_attack_graph,
            "asset",
            kinds={"secret", "credential", "token", "api_key", "password"},
        )
        if base_attack_graph
        else None
    )

    # Sensitive data flows — paths tagged or ending at sensitive assets
    sensitive_paths = []
    for path in ag.get("paths") or []:
        tags = {str(t).lower() for t in (path.get("tags") or [])}
        if tags & {"sensitive_data", "pii", "secret", "credential", "exfiltration"}:
            sensitive_paths.append(path)
        target = str(path.get("target") or "").lower()
        if any(k in target for k in ("secret", "credential", "pii", "database")):
            sensitive_paths.append(path)

    if base_ext is not None and ext > base_ext:
        risk = try_build_predictive_risk(
            category=CAT_EXTERNAL_INTEGRATION_RISK,
            title=f"{ext - base_ext} new external integration(s)",
            trigger_change={
                "kind": "external_integration_delta",
                "observation": "external_service nodes increased",
                "before": base_ext,
                "after": ext,
            },
            supporting_evidence=[
                {"source": "attack_graph", "metric": "external_services", "before": base_ext, "after": ext}
            ],
            security_effect="More third-party trust edges increase supply-chain / SSRF options",
            risk_signal="External integration expansion",
            confidence=CONF_MEDIUM,
            time_horizon=HORIZON_NEAR_TERM,
            change_status=STATUS_RISK_INCREASED,
        )
        if risk:
            risks.append(risk_to_dict(risk))
    elif ext:
        risk = try_build_predictive_risk(
            category=CAT_EXTERNAL_INTEGRATION_RISK,
            title=f"{ext} external integration(s) observed",
            trigger_change={
                "kind": "external_integration_snapshot",
                "observation": "external_service nodes present",
                "value": ext,
            },
            supporting_evidence=[{"source": "attack_graph", "metric": "external_services", "value": ext}],
            security_effect="External trust edges are part of the attack surface",
            risk_signal="External integration surface present",
            confidence=CONF_LOW,
            time_horizon=HORIZON_NEAR_TERM,
            change_status=STATUS_STABLE,
        )
        if risk:
            risks.append(risk_to_dict(risk))

    sbom = _sbom_hints(ag)
    if sbom:
        risk = try_build_predictive_risk(
            category=CAT_DEPENDENCY_RISK,
            title="Dependency inventory signals present in model",
            trigger_change={
                "kind": "dependency_inventory",
                "observation": "SBOM/dependency metadata observed",
                "hints": len(sbom),
            },
            supporting_evidence=[{"source": "sbom", "hints": sbom[:5]}],
            security_effect="Dependency surface can introduce transitive privilege/reachability",
            risk_signal="Dependency risk from observed inventory (not CVE prediction)",
            confidence=CONF_LOW,
            time_horizon=HORIZON_LONGER_TERM,
            change_status=STATUS_STABLE,
        )
        if risk:
            risks.append(risk_to_dict(risk))

    if base_secrets is not None and secrets > base_secrets:
        risk = try_build_predictive_risk(
            category=CAT_SECRET_MANAGEMENT_RISK,
            title=f"{secrets - base_secrets} additional secret/credential asset(s)",
            trigger_change={
                "kind": "secret_asset_delta",
                "observation": "secret/credential assets increased",
                "before": base_secrets,
                "after": secrets,
            },
            supporting_evidence=[
                {"source": "attack_graph", "metric": "secret_assets", "before": base_secrets, "after": secrets}
            ],
            security_effect="More secret material expands credential-leak blast radius",
            risk_signal="Secret management surface expanding",
            confidence=CONF_MEDIUM,
            time_horizon=HORIZON_NEAR_TERM,
            change_status=STATUS_RISK_INCREASED,
        )
        if risk:
            risks.append(risk_to_dict(risk))
    elif secrets:
        risk = try_build_predictive_risk(
            category=CAT_SECRET_MANAGEMENT_RISK,
            title=f"{secrets} secret/credential asset(s) observed",
            trigger_change={
                "kind": "secret_asset_snapshot",
                "observation": "secret/credential assets present",
                "value": secrets,
            },
            supporting_evidence=[{"source": "attack_graph", "metric": "secret_assets", "value": secrets}],
            security_effect="Secret assets concentrate confidentiality risk",
            risk_signal="Secret management surface present",
            confidence=CONF_LOW,
            time_horizon=HORIZON_NEAR_TERM,
            change_status=STATUS_STABLE,
        )
        if risk:
            risks.append(risk_to_dict(risk))

    if sensitive_paths:
        risk = try_build_predictive_risk(
            category=CAT_SENSITIVE_DATA_FLOW,
            title=f"{len(sensitive_paths)} sensitive-data path signal(s)",
            trigger_change={
                "kind": "sensitive_data_paths",
                "observation": "paths tagged or targeting sensitive assets",
                "count": len(sensitive_paths),
            },
            supporting_evidence=[
                {
                    "source": "attack_graph.paths",
                    "path_ids": [
                        str(p.get("path_id") or p.get("id")) for p in sensitive_paths[:8]
                    ],
                }
            ],
            security_effect="Sensitive data may be reachable along observed structural paths",
            risk_signal="Sensitive data flow risk from path tags/targets",
            confidence=CONF_MEDIUM,
            time_horizon=HORIZON_NEAR_TERM,
            change_status=STATUS_NEW_RISK if base_attack_graph else STATUS_STABLE,
            related_paths=[
                str(p.get("path_id") or p.get("id")) for p in sensitive_paths[:8]
            ],
        )
        if risk:
            risks.append(risk_to_dict(risk))

    return risks
