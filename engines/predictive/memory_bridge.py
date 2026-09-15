"""Security Memory bridge — historical regressions only when real data exists."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engines.predictive.schema import UNKNOWN


def load_memory_regressions(
    memory_dir: Path | str | None = None,
    *,
    before_id: str | None = None,
    after_id: str | None = None,
) -> dict[str, Any]:
    """Load real Security Memory regressions. Empty dict if unavailable."""
    try:
        from engines.memory.pipeline import run_memory_regressions
        from engines.memory.store import resolve_memory_dir
    except Exception:  # noqa: BLE001
        return {}

    try:
        root = resolve_memory_dir(memory_dir)
    except Exception:  # noqa: BLE001
        return {}

    try:
        result = run_memory_regressions(
            root,
            before_id=before_id,
            after_id=after_id,
        )
    except Exception:  # noqa: BLE001
        return {}

    if not isinstance(result, dict):
        return {}
    if result.get("error"):
        return {}

    regs = result
    # detect_regressions / get_regressions shapes
    regressed = regs.get("REGRESSED") or regs.get("regressed") or []
    if isinstance(regressed, dict):
        regressed = (
            regressed.get("REGRESSED")
            or regressed.get("items")
            or regressed.get("findings")
            or []
        )

    summary = regs.get("summary") or {}
    has_signal = bool(regressed) or bool(summary) or bool(regs.get("predictive"))
    if not has_signal:
        # Still mark available if memory answered without error — empty is honest
        return {
            "available": True,
            "memory_dir": str(root),
            "regressions": regs,
            "REGRESSED": [],
            "summary": summary,
            "source": "security_memory",
        }

    return {
        "available": True,
        "memory_dir": str(root),
        "regressions": regs,
        "REGRESSED": list(regressed) if isinstance(regressed, list) else [],
        "summary": summary,
        "source": "security_memory",
    }


def historical_evidence_from_memory(
    memory_pack: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Extract historical evidence entries only from real memory hits."""
    if not memory_pack or not memory_pack.get("available"):
        return []
    out: list[dict[str, Any]] = []
    for item in memory_pack.get("REGRESSED") or []:
        if isinstance(item, dict):
            out.append(
                {
                    "source": "security_memory",
                    "kind": "regression",
                    "id": item.get("id") or item.get("fingerprint") or UNKNOWN,
                    "summary": item.get("summary") or item.get("title") or UNKNOWN,
                    "detail": item,
                }
            )
        else:
            out.append(
                {
                    "source": "security_memory",
                    "kind": "regression",
                    "summary": str(item),
                }
            )
    return out
