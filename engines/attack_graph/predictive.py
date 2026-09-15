"""Predictive risk & architecture-drift signals (Phase 6 Part 2).

This module turns *structural* observations — either a single attack-graph
result's surface, or a :mod:`engines.attack_graph.diff` between two runs — into
forward-looking **signals**. It deliberately speaks the language of trend and
surface, never of confirmed exploitation:

- "increasing security risk", "emerging attack surface", "architecture drift"
- **never** "vulnerability" / "exploitable" unless current evidence already
  proved it (which is Phase 1-5's job, not this module's).

Every signal is tagged ``status: "PREDICTIVE"`` and carries the structural
evidence it was derived from, so a reader can audit the inference. A signal is
a hypothesis about direction of risk, not a finding.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from engines.attack_graph import diff as diff_mod

PREDICTIVE_STATUS = "PREDICTIVE"

# direction vocabulary
DIR_INCREASING = "increasing"
DIR_DECREASING = "decreasing"
DIR_STABLE = "stable"

# category vocabulary
CAT_PREDICTIVE_RISK = "predictive_risk"
CAT_ARCHITECTURE_DRIFT = "architecture_drift"
CAT_ATTACK_SURFACE = "attack_surface"

_DISCLAIMER = (
    "Predictive signal — a forward-looking trend/surface observation, NOT a "
    "confirmed security finding. Interpret as risk direction, not proof of "
    "exploitability."
)


def _signal(
    signal: str,
    *,
    direction: str,
    category: str,
    language: str,
    evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "signal": signal,
        "direction": direction,
        "category": category,
        "status": PREDICTIVE_STATUS,
        "language": language,
        "evidence": evidence or [],
        "disclaimer": _DISCLAIMER,
    }


# ---------------------------------------------------------------------------
# single-graph surface signals
# ---------------------------------------------------------------------------
def _nodes(result: dict[str, Any]) -> list[dict[str, Any]]:
    return list((result.get("graph") or {}).get("nodes") or [])


def surface_metrics(result: dict[str, Any]) -> dict[str, int]:
    """Measured, non-speculative surface counts for a single attack-graph run."""
    nodes = _nodes(result)
    public_entries = sum(
        1
        for n in nodes
        if n.get("type") == "entrypoint"
        and str(n.get("reachability")) in {"public", "unauthenticated"}
    )
    ai_components = sum(1 for n in nodes if n.get("type") == "ai_component")
    tools = sum(1 for n in nodes if n.get("type") == "tool")
    externals = sum(1 for n in nodes if n.get("type") == "external_service")
    secrets = sum(
        1
        for n in nodes
        if n.get("type") == "asset"
        and str(n.get("kind")) in {"secret", "credential", "token"}
    )
    paths = result.get("paths") or []
    live_paths = sum(1 for p in paths if str(p.get("status")) in {"CONFIRMED", "LIKELY"})
    return {
        "public_entrypoints": public_entries,
        "ai_components": ai_components,
        "ai_tools": tools,
        "external_services": externals,
        "secret_assets": secrets,
        "attack_paths": len(paths),
        "live_attack_paths": live_paths,
    }


def surface_report(result: dict[str, Any]) -> dict[str, Any]:
    """Emerging-attack-surface signals from a *single* current graph.

    Without a baseline we cannot claim growth, so these signals describe the
    *current* surface and flag areas that tend to grow risk over time. Direction
    is reported ``stable`` (single snapshot) unless a diff is provided.
    """
    m = surface_metrics(result)
    signals: list[dict[str, Any]] = []
    if m["public_entrypoints"]:
        signals.append(
            _signal(
                f"{m['public_entrypoints']} publicly-reachable entrypoint(s) form the current attack surface",
                direction=DIR_STABLE,
                category=CAT_ATTACK_SURFACE,
                language="emerging attack surface",
                evidence=[{"metric": "public_entrypoints", "value": m["public_entrypoints"]}],
            )
        )
    if m["ai_components"] or m["ai_tools"]:
        signals.append(
            _signal(
                f"{m['ai_components']} AI component(s) with {m['ai_tools']} tool(s) present — autonomous-execution surface",
                direction=DIR_STABLE,
                category=CAT_ATTACK_SURFACE,
                language="emerging attack surface",
                evidence=[
                    {"metric": "ai_components", "value": m["ai_components"]},
                    {"metric": "ai_tools", "value": m["ai_tools"]},
                ],
            )
        )
    if m["external_services"]:
        signals.append(
            _signal(
                f"{m['external_services']} external service dependency(ies) widen the trust boundary",
                direction=DIR_STABLE,
                category=CAT_ATTACK_SURFACE,
                language="emerging attack surface",
                evidence=[{"metric": "external_services", "value": m["external_services"]}],
            )
        )
    return {
        "kind": "predictive_surface",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": PREDICTIVE_STATUS,
        "metrics": m,
        "signal_count": len(signals),
        "signals": signals,
        "disclaimer": _DISCLAIMER,
    }


# ---------------------------------------------------------------------------
# diff-driven drift signals
# ---------------------------------------------------------------------------
def _count(changes: list[dict[str, Any]], change_type: str) -> int:
    return sum(1 for c in changes if c.get("change") == change_type)


def predictive_report(before: Any, after: Any) -> dict[str, Any]:
    """Predictive risk + architecture-drift signals from two graph runs.

    ``before``/``after`` may be result dicts or paths to attack-paths.json.
    """
    diff = diff_mod.compare_attack_graphs(before, after)
    changes = diff.get("changes") or []

    signals: list[dict[str, Any]] = []

    new_paths = _count(changes, diff_mod.CHANGE_NEW_ATTACK_PATH)
    removed_paths = _count(changes, diff_mod.CHANGE_REMOVED_ATTACK_PATH)
    weakened = _count(changes, diff_mod.CHANGE_WEAKENED_CONTROL)
    strengthened = _count(changes, diff_mod.CHANGE_STRENGTHENED_CONTROL)
    new_entries = _count(changes, diff_mod.CHANGE_NEW_ENTRY_POINT)
    removed_entries = _count(changes, diff_mod.CHANGE_REMOVED_ENTRY_POINT)
    regressed = sum(
        1
        for c in changes
        if c.get("change") == diff_mod.CHANGE_PATH_STATUS_CHANGE
        and c.get("direction") == "regressed"
    )

    if new_paths:
        signals.append(
            _signal(
                f"{new_paths} new attack path(s) appeared between runs",
                direction=DIR_INCREASING,
                category=CAT_PREDICTIVE_RISK,
                language="increasing security risk",
                evidence=[{"metric": "new_attack_paths", "value": new_paths}],
            )
        )
    if weakened:
        signals.append(
            _signal(
                f"{weakened} control(s) weakened or stopped blocking a path",
                direction=DIR_INCREASING,
                category=CAT_PREDICTIVE_RISK,
                language="increasing security risk (control regression trend)",
                evidence=[{"metric": "weakened_controls", "value": weakened}],
            )
        )
    if regressed:
        signals.append(
            _signal(
                f"{regressed} existing path(s) regressed to a stronger status tier",
                direction=DIR_INCREASING,
                category=CAT_PREDICTIVE_RISK,
                language="increasing security risk",
                evidence=[{"metric": "regressed_paths", "value": regressed}],
            )
        )
    if new_entries:
        signals.append(
            _signal(
                f"{new_entries} new entry point(s) added",
                direction=DIR_INCREASING,
                category=CAT_ARCHITECTURE_DRIFT,
                language="emerging attack surface",
                evidence=[{"metric": "new_entry_points", "value": new_entries}],
            )
        )
    if removed_paths or strengthened or removed_entries:
        signals.append(
            _signal(
                f"{removed_paths} path(s) removed, {strengthened} control(s) strengthened, "
                f"{removed_entries} entry point(s) removed",
                direction=DIR_DECREASING,
                category=CAT_PREDICTIVE_RISK,
                language="decreasing security risk (surface reduction trend)",
                evidence=[
                    {"metric": "removed_attack_paths", "value": removed_paths},
                    {"metric": "strengthened_controls", "value": strengthened},
                    {"metric": "removed_entry_points", "value": removed_entries},
                ],
            )
        )

    if not signals:
        signals.append(
            _signal(
                "no material structural change between runs",
                direction=DIR_STABLE,
                category=CAT_ARCHITECTURE_DRIFT,
                language="stable attack surface",
            )
        )

    # Overall drift direction: increasing wins if any increasing signal exists.
    directions = {s["direction"] for s in signals}
    if DIR_INCREASING in directions:
        overall = DIR_INCREASING
    elif directions == {DIR_DECREASING} or (DIR_DECREASING in directions and DIR_STABLE in directions):
        overall = DIR_DECREASING
    else:
        overall = DIR_STABLE

    return {
        "kind": "predictive_drift",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": PREDICTIVE_STATUS,
        "overall_direction": overall,
        "diff_summary": diff.get("summary"),
        "signal_count": len(signals),
        "signals": signals,
        "disclaimer": _DISCLAIMER,
    }


def render_predictive_markdown(report: dict[str, Any]) -> str:
    """Human-readable rendering for either a surface or drift report."""
    lines = [
        "# AXguard predictive analysis (diagnostic)",
        "",
        "Forward-looking risk/surface signals. These describe **trend and "
        "surface**, not confirmed vulnerabilities.",
        "",
    ]
    if report.get("overall_direction"):
        lines.append(f"- **Overall direction:** {report['overall_direction']}")
    if report.get("metrics"):
        lines.append(f"- **Surface metrics:** {report['metrics']}")
    lines.append(f"- **Signals:** {report.get('signal_count', 0)}")
    lines.append("")
    for s in report.get("signals") or []:
        lines.append(
            f"- **[{s.get('direction')}] {s.get('language')}** — {s.get('signal')}"
        )
    lines.append("")
    return "\n".join(lines)
