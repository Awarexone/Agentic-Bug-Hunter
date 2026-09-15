"""PredictiveRisk builders — require observable trigger + supporting evidence."""

from __future__ import annotations

from typing import Any

from engines.predictive.schema import (
    CONF_UNKNOWN,
    CONFIDENCE_LEVELS,
    DISCLAIMER,
    HORIZON_NEAR_TERM,
    RISK_CATEGORIES,
    RISK_CHANGE_STATUSES,
    STATUS_NEW_RISK,
    TIME_HORIZONS,
    PredictiveRisk,
    new_risk_id,
)


class PredictiveBuildError(ValueError):
    """Raised when a predictive risk lacks required observed grounding."""


def _normalize_evidence(items: list[Any] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in items or []:
        if isinstance(item, dict):
            out.append(dict(item))
        elif item is not None:
            out.append({"summary": str(item)})
    return out


def _require_trigger(trigger_change: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(trigger_change, dict) or not trigger_change:
        raise PredictiveBuildError(
            "trigger_change is required — predictive risks need an observed change"
        )
    # Must describe something observed, not a naked guess
    if not any(
        trigger_change.get(k)
        for k in ("observation", "change", "metric", "description", "kind", "diff")
    ):
        if "summary" not in trigger_change and len(trigger_change) < 1:
            raise PredictiveBuildError("trigger_change must describe an observed change")
    return dict(trigger_change)


def _require_evidence(supporting_evidence: list[Any] | None) -> list[dict[str, Any]]:
    evidence = _normalize_evidence(supporting_evidence)
    if not evidence:
        raise PredictiveBuildError(
            "supporting_evidence is required — never invent predictive risks without evidence"
        )
    return evidence


def build_predictive_risk(
    *,
    category: str,
    title: str,
    trigger_change: dict[str, Any],
    supporting_evidence: list[Any],
    security_effect: str,
    risk_signal: str,
    confidence: str = CONF_UNKNOWN,
    time_horizon: str = HORIZON_NEAR_TERM,
    change_status: str = STATUS_NEW_RISK,
    historical_evidence: list[Any] | None = None,
    structural_evidence: list[Any] | None = None,
    score_factors: list[dict[str, Any]] | None = None,
    debt_factors: list[dict[str, Any]] | None = None,
    change_risk_score: float | None = None,
    related_paths: list[str] | None = None,
    related_entities: list[str] | None = None,
    risk_id: str | None = None,
    meta: dict[str, Any] | None = None,
) -> PredictiveRisk:
    """Build a PredictiveRisk. Never invents history; historical_evidence optional."""
    if category not in RISK_CATEGORIES:
        raise PredictiveBuildError(f"unknown category: {category}")
    trigger = _require_trigger(trigger_change)
    evidence = _require_evidence(supporting_evidence)
    conf = confidence if confidence in CONFIDENCE_LEVELS else CONF_UNKNOWN
    horizon = time_horizon if time_horizon in TIME_HORIZONS else HORIZON_NEAR_TERM
    status = change_status if change_status in RISK_CHANGE_STATUSES else STATUS_NEW_RISK

    hist = _normalize_evidence(historical_evidence)
    # Never fabricate history — empty is fine; callers supply only real memory hits
    structural = _normalize_evidence(structural_evidence)

    return PredictiveRisk(
        risk_id=risk_id or new_risk_id(),
        category=category,
        title=str(title).strip() or "Predictive risk",
        trigger_change=trigger,
        supporting_evidence=evidence,
        security_effect=str(security_effect).strip() or UNKNOWN_EFFECT,
        risk_signal=str(risk_signal).strip() or UNKNOWN_SIGNAL,
        confidence=conf,
        time_horizon=horizon,
        change_status=status,
        historical_evidence=hist,
        structural_evidence=structural,
        score_factors=list(score_factors or []),
        debt_factors=list(debt_factors or []),
        change_risk_score=change_risk_score,
        related_paths=list(related_paths or []),
        related_entities=list(related_entities or []),
        disclaimer=DISCLAIMER,
        meta=dict(meta or {}),
    )


UNKNOWN_EFFECT = "Security effect not yet characterized from available evidence"
UNKNOWN_SIGNAL = "Risk direction uncertain — insufficient structural evidence"


def risk_to_dict(risk: PredictiveRisk | dict[str, Any]) -> dict[str, Any]:
    if isinstance(risk, PredictiveRisk):
        return risk.to_dict()
    return dict(risk)


def try_build_predictive_risk(**kwargs: Any) -> PredictiveRisk | None:
    """Soft builder — returns None instead of raising when grounding is missing."""
    try:
        return build_predictive_risk(**kwargs)
    except PredictiveBuildError:
        return None
