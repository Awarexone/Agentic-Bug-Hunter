"""Compare previous vs new predictive risks — change status vocabulary."""

from __future__ import annotations

from typing import Any

from engines.predictive.schema import (
    STATUS_NEW_RISK,
    STATUS_RESOLVED,
    STATUS_RISK_DECREASED,
    STATUS_RISK_INCREASED,
    STATUS_STABLE,
)


def _fingerprint(risk: dict[str, Any]) -> str:
    cat = str(risk.get("category") or "")
    trigger = risk.get("trigger_change") or {}
    kind = str(trigger.get("kind") or trigger.get("metric") or "")
    title = str(risk.get("title") or "")[:80]
    return f"{cat}|{kind}|{title}".lower()


def _signal_strength(risk: dict[str, Any]) -> float:
    score = risk.get("change_risk_score")
    if isinstance(score, (int, float)):
        return float(score)
    conf = str(risk.get("confidence") or "").upper()
    return {"HIGH": 3.0, "MEDIUM": 2.0, "LOW": 1.0}.get(conf, 0.5)


def compare_risk_sets(
    previous: list[dict[str, Any]] | None,
    current: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Diff two predictive risk lists into RISK_* / STABLE / RESOLVED / NEW_RISK."""
    prev = list(previous or [])
    cur = list(current or [])
    prev_map = {_fingerprint(r): r for r in prev}
    cur_map = {_fingerprint(r): r for r in cur}

    comparisons: list[dict[str, Any]] = []
    updated_current: list[dict[str, Any]] = []

    for fp, risk in cur_map.items():
        item = dict(risk)
        if fp not in prev_map:
            item["change_status"] = STATUS_NEW_RISK
            comparisons.append(
                {
                    "fingerprint": fp,
                    "status": STATUS_NEW_RISK,
                    "risk_id": item.get("risk_id"),
                    "category": item.get("category"),
                    "title": item.get("title"),
                }
            )
        else:
            before = prev_map[fp]
            delta = _signal_strength(item) - _signal_strength(before)
            if delta > 0.25:
                status = STATUS_RISK_INCREASED
            elif delta < -0.25:
                status = STATUS_RISK_DECREASED
            else:
                status = STATUS_STABLE
            item["change_status"] = status
            item["meta"] = {
                **(item.get("meta") or {}),
                "previous_risk_id": before.get("risk_id"),
                "strength_delta": round(delta, 3),
            }
            comparisons.append(
                {
                    "fingerprint": fp,
                    "status": status,
                    "risk_id": item.get("risk_id"),
                    "previous_risk_id": before.get("risk_id"),
                    "category": item.get("category"),
                    "strength_delta": round(delta, 3),
                }
            )
        updated_current.append(item)

    for fp, before in prev_map.items():
        if fp not in cur_map:
            comparisons.append(
                {
                    "fingerprint": fp,
                    "status": STATUS_RESOLVED,
                    "previous_risk_id": before.get("risk_id"),
                    "category": before.get("category"),
                    "title": before.get("title"),
                }
            )

    by_status: dict[str, int] = {}
    for c in comparisons:
        st = str(c.get("status") or STATUS_STABLE)
        by_status[st] = by_status.get(st, 0) + 1

    return {
        "comparisons": comparisons,
        "risks": updated_current,
        "summary": {
            "previous_count": len(prev),
            "current_count": len(cur),
            "by_status": by_status,
        },
    }


def apply_comparison_statuses(
    risks: list[dict[str, Any]],
    previous_risks: list[dict[str, Any]] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (updated_risks, comparisons)."""
    if not previous_risks:
        # Without history, keep existing statuses (often NEW_RISK or STABLE)
        return list(risks), []
    result = compare_risk_sets(previous_risks, risks)
    return list(result.get("risks") or []), list(result.get("comparisons") or [])
