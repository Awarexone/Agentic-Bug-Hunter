"""Thin what-if wrapper over Security Twin counterfactual analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engines.predictive.schema import DISCLAIMER


def run_predictive_what_if(
    target: Path | str | None = None,
    *,
    twin: dict[str, Any] | None = None,
    scenario: str | None = None,
    remove_control: str | None = None,
    grant_agent_tool: str | None = None,
    compromise_entity: str | None = None,
    assumptions: list[str] | None = None,
) -> dict[str, Any]:
    """Run twin counterfactual and wrap as predictive what-if output.

    Soft-fails if twin engine is unavailable. Never claims confirmed vulns.
    """
    try:
        from engines.twin.pipeline import run_twin_what_if
        from engines.twin.build import build_security_twin
    except Exception as exc:  # noqa: BLE001
        return {
            "available": False,
            "error": f"Security Twin unavailable: {exc}",
            "disclaimer": DISCLAIMER,
        }

    path = Path(target) if target is not None else None
    try:
        if twin is None and path is not None:
            pack = run_twin_what_if(
                path,
                scenario=scenario,
                remove_control=remove_control,
                grant_agent_tool=grant_agent_tool,
                compromise_entity=compromise_entity,
                assumptions=assumptions,
            )
        else:
            tw = twin
            if tw is None and path is not None:
                tw = build_security_twin(path)
            if tw is None:
                return {
                    "available": False,
                    "error": "no twin or target provided",
                    "disclaimer": DISCLAIMER,
                }
            from engines.twin.counterfactual import run_counterfactual

            cf = run_counterfactual(
                tw,
                scenario=scenario,
                remove_control=remove_control,
                grant_agent_tool=grant_agent_tool,
                compromise_entity=compromise_entity,
                assumptions=assumptions,
            )
            pack = {"twin": tw, "counterfactual": cf}
    except Exception as exc:  # noqa: BLE001
        return {
            "available": False,
            "error": str(exc),
            "disclaimer": DISCLAIMER,
        }

    cf = pack.get("counterfactual") or {}
    simulated = cf.get("simulated_paths") or []
    return {
        "available": True,
        "scenario": cf.get("scenario"),
        "assumptions": cf.get("assumptions") or [],
        "observed_summary": cf.get("observed_summary"),
        "simulated_path_count": len(simulated),
        "simulated_paths": simulated[:20],
        "control_analysis": (cf.get("control_analysis") or [])[:20],
        "disclaimer": cf.get("disclaimer") or DISCLAIMER,
        "note": (
            "What-if paths are SIMULATED under stated assumptions — "
            "not verified findings."
        ),
    }
