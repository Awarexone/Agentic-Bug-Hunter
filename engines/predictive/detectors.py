"""Predictive detector registry — category constants and runner.

Focused detectors live in sibling modules (surface, privilege, …).
This module owns the category catalog and orchestration helpers.
"""

from __future__ import annotations

from typing import Any, Callable

from engines.predictive.schema import (
    CAT_AI_AGENT_PRIVILEGE_RISK,
    CAT_API_EXPOSURE_RISK,
    CAT_ARCHITECTURE_DRIFT,
    CAT_ATTACK_SURFACE_EXPANSION,
    CAT_AUTHORIZATION_DRIFT,
    CAT_CLOUD_PRIVILEGE_RISK,
    CAT_DEPENDENCY_RISK,
    CAT_EXTERNAL_INTEGRATION_RISK,
    CAT_MCP_TRUST_RISK,
    CAT_NETWORK_EXPOSURE_RISK,
    CAT_PRIVILEGE_EXPANSION,
    CAT_REGRESSION_RISK,
    CAT_SECRET_MANAGEMENT_RISK,
    CAT_SECURITY_CONTROL_COMPLEXITY,
    CAT_SECURITY_DEBT,
    CAT_SENSITIVE_DATA_FLOW,
    CAT_TENANT_ISOLATION_RISK,
    CAT_TOOL_PERMISSION_RISK,
    CAT_TRUST_BOUNDARY_EXPANSION,
    RISK_CATEGORIES,
)

# Public alias used by docs / CLI help
DETECTOR_CATEGORIES = sorted(RISK_CATEGORIES)

DetectorFn = Callable[..., list[dict[str, Any]]]


def _soft_call(fn: DetectorFn, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
    try:
        result = fn(*args, **kwargs)
        return list(result or [])
    except Exception:  # noqa: BLE001 — soft-fail individual detectors
        return []


def run_all_detectors(
    *,
    attack_graph: dict[str, Any] | None = None,
    twin: dict[str, Any] | None = None,
    base_attack_graph: dict[str, Any] | None = None,
    base_twin: dict[str, Any] | None = None,
    memory_regressions: dict[str, Any] | None = None,
    mode: str = "default",
) -> list[dict[str, Any]]:
    """Run focused detectors; soft-import failures yield empty lists."""
    from engines.predictive import (
        agent_mcp,
        auth_drift,
        controls,
        debt,
        dependency,
        privilege,
        surface,
        tenant,
    )

    risks: list[dict[str, Any]] = []
    ctx = dict(
        attack_graph=attack_graph or {},
        twin=twin or {},
        base_attack_graph=base_attack_graph,
        base_twin=base_twin,
        memory_regressions=memory_regressions or {},
        mode=mode,
    )

    risks.extend(_soft_call(surface.detect_surface_risks, **ctx))
    risks.extend(_soft_call(privilege.detect_privilege_risks, **ctx))
    risks.extend(_soft_call(auth_drift.detect_auth_drift_risks, **ctx))
    risks.extend(_soft_call(tenant.detect_tenant_risks, **ctx))
    risks.extend(_soft_call(dependency.detect_dependency_risks, **ctx))
    risks.extend(_soft_call(agent_mcp.detect_agent_mcp_risks, **ctx))
    risks.extend(_soft_call(controls.detect_control_risks, **ctx))
    risks.extend(_soft_call(debt.detect_debt_risks, **ctx))

    # Mode filters (additive narrowing, never invent)
    if mode == "agent":
        allow = {
            CAT_AI_AGENT_PRIVILEGE_RISK,
            CAT_TOOL_PERMISSION_RISK,
            CAT_MCP_TRUST_RISK,
            CAT_SENSITIVE_DATA_FLOW,
            CAT_SECURITY_DEBT,
            CAT_REGRESSION_RISK,
        }
        risks = [r for r in risks if r.get("category") in allow]
    elif mode == "mcp":
        allow = {
            CAT_MCP_TRUST_RISK,
            CAT_TOOL_PERMISSION_RISK,
            CAT_AI_AGENT_PRIVILEGE_RISK,
            CAT_EXTERNAL_INTEGRATION_RISK,
            CAT_TRUST_BOUNDARY_EXPANSION,
            CAT_REGRESSION_RISK,
        }
        risks = [r for r in risks if r.get("category") in allow]
    elif mode == "architecture":
        allow = {
            CAT_ATTACK_SURFACE_EXPANSION,
            CAT_ARCHITECTURE_DRIFT,
            CAT_TRUST_BOUNDARY_EXPANSION,
            CAT_API_EXPOSURE_RISK,
            CAT_NETWORK_EXPOSURE_RISK,
            CAT_EXTERNAL_INTEGRATION_RISK,
            CAT_SECURITY_CONTROL_COMPLEXITY,
            CAT_SECURITY_DEBT,
            CAT_DEPENDENCY_RISK,
        }
        risks = [r for r in risks if r.get("category") in allow]
    elif mode == "pr":
        # PR mode keeps change-driven signals; drop pure single-snapshot debt noise
        # unless a base/diff is present
        if not base_attack_graph and not base_twin:
            risks = [
                r
                for r in risks
                if r.get("category")
                not in {CAT_SECURITY_DEBT, CAT_SECURITY_CONTROL_COMPLEXITY}
                or r.get("change_status") != "STABLE"
            ]

    return risks


__all__ = [
    "DETECTOR_CATEGORIES",
    "RISK_CATEGORIES",
    "CAT_ATTACK_SURFACE_EXPANSION",
    "CAT_PRIVILEGE_EXPANSION",
    "CAT_TRUST_BOUNDARY_EXPANSION",
    "CAT_AUTHORIZATION_DRIFT",
    "CAT_TENANT_ISOLATION_RISK",
    "CAT_SENSITIVE_DATA_FLOW",
    "CAT_EXTERNAL_INTEGRATION_RISK",
    "CAT_DEPENDENCY_RISK",
    "CAT_CLOUD_PRIVILEGE_RISK",
    "CAT_SECRET_MANAGEMENT_RISK",
    "CAT_AI_AGENT_PRIVILEGE_RISK",
    "CAT_MCP_TRUST_RISK",
    "CAT_TOOL_PERMISSION_RISK",
    "CAT_SECURITY_CONTROL_COMPLEXITY",
    "CAT_SECURITY_DEBT",
    "CAT_REGRESSION_RISK",
    "CAT_ARCHITECTURE_DRIFT",
    "CAT_API_EXPOSURE_RISK",
    "CAT_NETWORK_EXPOSURE_RISK",
    "run_all_detectors",
]
