"""Security debt predictive detectors — factor breakdown, not a opaque score."""

from __future__ import annotations

from typing import Any

from engines.predictive.model import risk_to_dict, try_build_predictive_risk
from engines.predictive.schema import (
    CAT_SECURITY_DEBT,
    CONF_LOW,
    CONF_MEDIUM,
    HORIZON_LONGER_TERM,
    STATUS_STABLE,
)
from engines.predictive.score import compute_security_debt


def detect_debt_risks(
    *,
    attack_graph: dict[str, Any] | None = None,
    twin: dict[str, Any] | None = None,
    base_attack_graph: dict[str, Any] | None = None,
    base_twin: dict[str, Any] | None = None,
    memory_regressions: dict[str, Any] | None = None,
    mode: str = "default",
) -> list[dict[str, Any]]:
    del base_attack_graph, base_twin, mode
    ag = attack_graph or {}
    if not ag and not twin:
        return []

    debt = compute_security_debt(
        attack_graph=ag,
        twin=twin or {},
        memory_regressions=memory_regressions or {},
    )
    factors = debt.get("factors") or []
    if not factors:
        return []

    # Only emit a debt risk when at least one factor has non-zero weight evidence
    active = [f for f in factors if float(f.get("weight") or 0) > 0]
    if not active:
        return []

    risk = try_build_predictive_risk(
        category=CAT_SECURITY_DEBT,
        title="Security debt factors from observed structure",
        trigger_change={
            "kind": "security_debt_factors",
            "observation": "multiple structural debt factors present",
            "factor_count": len(active),
            "total_weight": debt.get("total_weight"),
        },
        supporting_evidence=[{"source": "score.security_debt", "factors": active}],
        security_effect="Accumulated structural debt increases future regression likelihood",
        risk_signal="Security debt present — see factor breakdown (not a CVE forecast)",
        confidence=CONF_MEDIUM if len(active) >= 3 else CONF_LOW,
        time_horizon=HORIZON_LONGER_TERM,
        change_status=STATUS_STABLE,
        debt_factors=active,
        score_factors=active,
        change_risk_score=debt.get("total_weight"),
        meta={"debt_summary": debt.get("summary")},
    )
    if not risk:
        return []
    return [risk_to_dict(risk)]
