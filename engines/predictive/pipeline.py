"""Predictive Security pipeline — OBSERVED CHANGE → RISK SIGNAL."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from engines.predictive.compare import apply_comparison_statuses
from engines.predictive.detectors import run_all_detectors
from engines.predictive.memory_bridge import (
    historical_evidence_from_memory,
    load_memory_regressions,
)
from engines.predictive.report import write_predictive_report
from engines.predictive.schema import (
    MODE_DEFAULT,
    MODE_WHAT_IF,
    PREDICT_MODES,
    UNKNOWN,
    empty_predict_result,
    utc_now,
)
from engines.predictive.score import (
    attach_scores_to_risks,
    compute_change_risk,
    compute_security_debt,
)
from engines.predictive.whatif import run_predictive_what_if


def _summarize(risks: list[dict[str, Any]]) -> dict[str, Any]:
    by_cat: dict[str, int] = {}
    by_conf: dict[str, int] = {}
    by_status: dict[str, int] = {}
    by_horizon: dict[str, int] = {}
    for r in risks:
        cat = str(r.get("category") or UNKNOWN)
        by_cat[cat] = by_cat.get(cat, 0) + 1
        conf = str(r.get("confidence") or UNKNOWN)
        by_conf[conf] = by_conf.get(conf, 0) + 1
        st = str(r.get("change_status") or UNKNOWN)
        by_status[st] = by_status.get(st, 0) + 1
        hz = str(r.get("time_horizon") or UNKNOWN)
        by_horizon[hz] = by_horizon.get(hz, 0) + 1
    return {
        "risk_count": len(risks),
        "by_category": by_cat,
        "by_confidence": by_conf,
        "by_change_status": by_status,
        "by_horizon": by_horizon,
    }


def _load_attack_graph(target: Path) -> dict[str, Any] | None:
    try:
        from engines.attack_graph import run_attack_graph

        return run_attack_graph(target)
    except Exception:  # noqa: BLE001
        return None


def _load_twin(target: Path, attack_graph: dict[str, Any] | None) -> dict[str, Any] | None:
    try:
        from engines.twin.build import build_security_twin

        return build_security_twin(target, attack_graph=attack_graph)
    except Exception:  # noqa: BLE001
        return None


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def run_predict(
    target: Path | str | dict[str, Any] | None = ".",
    *,
    base: Path | str | dict[str, Any] | None = None,
    mode: str = MODE_DEFAULT,
    attack_graph: dict[str, Any] | None = None,
    base_attack_graph: dict[str, Any] | None = None,
    twin: dict[str, Any] | None = None,
    base_twin: dict[str, Any] | None = None,
    previous_risks: list[dict[str, Any]] | None = None,
    memory_dir: Path | str | None = None,
    scenario: str | None = None,
    remove_control: str | None = None,
    grant_agent_tool: str | None = None,
    compromise_entity: str | None = None,
    assumptions: list[str] | None = None,
    out_dir: Path | str | None = None,
    write_report: bool = True,
    with_twin: bool = True,
    with_memory: bool = True,
) -> dict[str, Any]:
    """Run Predictive Security Intelligence.

    Modes: architecture | agent | mcp | pr | what-if | default.
    Soft-imports Twin / Memory / Attack Graph. Never invents history.
    """
    mode_key = (mode or MODE_DEFAULT).strip().lower()
    if mode_key not in PREDICT_MODES:
        mode_key = MODE_DEFAULT

    path: Path | None = None
    payload: dict[str, Any] | None = None
    if isinstance(target, dict):
        payload = target
    elif target is not None:
        path = Path(target)
        if path.is_file() and path.suffix.lower() == ".json":
            payload = _load_json(path)
            path = None
        elif path.exists():
            path = path.resolve()

    target_label = UNKNOWN
    if path is not None:
        target_label = str(path)
    elif payload is not None:
        target_label = str(payload.get("target") or "payload")

    result = empty_predict_result(target=target_label, mode=mode_key)
    result["generated_at"] = utc_now()

    # Resolve graphs / twins
    ag = attack_graph
    tw = twin
    if payload:
        ag = ag or payload.get("attack_graph") or payload
        tw = tw or payload.get("twin")
        if previous_risks is None and isinstance(payload.get("risks"), list):
            # Allow feeding a prior predict result as previous via base
            pass

    if ag is None and path is not None and path.is_dir():
        ag = _load_attack_graph(path)
    if with_twin and tw is None and path is not None and path.is_dir():
        tw = _load_twin(path, ag)

    # Base (for PR / compare)
    base_ag = base_attack_graph
    base_tw = base_twin
    if base is not None:
        if isinstance(base, dict):
            base_ag = base_ag or base.get("attack_graph") or (
                base if "graph" in base or "paths" in base else None
            )
            base_tw = base_tw or base.get("twin")
            if previous_risks is None and isinstance(base.get("risks"), list):
                previous_risks = list(base["risks"])
        else:
            base_path = Path(base)
            if base_path.is_file() and base_path.suffix.lower() == ".json":
                base_payload = _load_json(base_path)
                if base_payload:
                    if isinstance(base_payload.get("risks"), list):
                        previous_risks = previous_risks or list(base_payload["risks"])
                    base_ag = base_ag or base_payload.get("attack_graph") or (
                        base_payload
                        if "graph" in base_payload or "paths" in base_payload
                        else None
                    )
                    base_tw = base_tw or base_payload.get("twin")
            elif base_path.is_dir():
                base_ag = base_ag or _load_attack_graph(base_path.resolve())
                if with_twin:
                    base_tw = base_tw or _load_twin(base_path.resolve(), base_ag)

    # Memory (real data only)
    memory_pack: dict[str, Any] = {}
    if with_memory:
        mem_root = memory_dir
        if mem_root is None and path is not None:
            mem_root = path / ".findings" / "axguard" / "memory"
        memory_pack = load_memory_regressions(mem_root)
    result["memory"] = memory_pack if memory_pack else {"available": False}

    mem_regs = {}
    if memory_pack.get("available"):
        mem_regs = {
            "REGRESSED": memory_pack.get("REGRESSED") or [],
            "regressions": memory_pack.get("regressions") or {},
            "summary": memory_pack.get("summary") or {},
        }

    # What-if mode short-circuit (still can attach detectors if graph present)
    what_if = None
    if mode_key == MODE_WHAT_IF or scenario or remove_control or grant_agent_tool:
        what_if = run_predictive_what_if(
            path,
            twin=tw,
            scenario=scenario,
            remove_control=remove_control,
            grant_agent_tool=grant_agent_tool,
            compromise_entity=compromise_entity,
            assumptions=assumptions,
        )
        result["what_if"] = what_if
        if mode_key == MODE_WHAT_IF and not ag:
            result["summary"] = _summarize([])
            if write_report and out_dir:
                result["report"] = write_predictive_report(result, Path(out_dir))
            return result

    risks = run_all_detectors(
        attack_graph=ag,
        twin=tw,
        base_attack_graph=base_ag,
        base_twin=base_tw,
        memory_regressions=mem_regs,
        mode=mode_key,
    )

    # Attach historical evidence from memory where applicable
    hist = historical_evidence_from_memory(memory_pack)
    if hist:
        for r in risks:
            if r.get("category") == "REGRESSION_RISK" and not r.get("historical_evidence"):
                r["historical_evidence"] = hist
            elif hist and str(r.get("change_status")) == "RISK_INCREASED":
                # Soft attach — do not invent; only annotate with real memory
                existing = list(r.get("historical_evidence") or [])
                if not existing:
                    r["historical_evidence"] = hist[:3]

    risks, comparisons = apply_comparison_statuses(risks, previous_risks)

    change_risk = compute_change_risk(
        risks=risks,
        attack_graph=ag,
        base_attack_graph=base_ag,
        memory_regressions=mem_regs,
    )
    debt = compute_security_debt(
        attack_graph=ag,
        twin=tw or {},
        memory_regressions=mem_regs,
    )
    risks = attach_scores_to_risks(risks, change_risk)

    result["risks"] = risks
    result["comparisons"] = comparisons
    result["scores"] = {"change_risk": change_risk}
    result["debt"] = debt
    result["summary"] = _summarize(risks)
    result["meta"] = {
        "has_attack_graph": bool(ag),
        "has_twin": bool(tw),
        "has_base": bool(base_ag or base_tw),
        "has_memory": bool(memory_pack.get("available")),
        "principle": (
            "OBSERVED CHANGE → SECURITY EFFECT → RISK SIGNAL → "
            "HISTORICAL/STRUCTURAL EVIDENCE → PREDICTIVE RISK"
        ),
    }

    if write_report and out_dir:
        result["report"] = write_predictive_report(result, Path(out_dir))

    return result
