"""GitHub Check / PR formatting — Verified vs Predictive vs Improvements.

Never mix buckets. No false-certainty language.
"""

from __future__ import annotations

from typing import Any

from engines.predictive.schema import DISCLAIMER

_VERIFIED_STATUSES = frozenset({"CONFIRMED", "VERIFIED", "LIKELY", "REGRESSED"})
_IMPROVEMENT_HINTS = frozenset(
    {"RISK_DECREASED", "RESOLVED", "FALSE_POSITIVE", "STRENGTHENED"}
)

SECTION_VERIFIED = "Verified findings"
SECTION_PREDICTIVE = "Predictive Security"
SECTION_IMPROVEMENTS = "Improvements"


def _safe(text: Any, *, limit: int = 400) -> str:
    """Truncate and sanitize untrusted/repo-derived strings for GitHub Markdown."""
    s = str(text or "").strip()
    try:
        from engines.github.untrusted import sanitize_untrusted_text

        s = sanitize_untrusted_text(s, max_len=limit)
    except Exception:  # noqa: BLE001 — soft if github adapter absent
        if len(s) > limit:
            s = s[: limit - 3] + "..."
    return s


def format_verified_section(findings: list[Any], *, limit: int = 15) -> list[str]:
    """Format verified / strong findings only."""
    lines = [f"### {SECTION_VERIFIED}", ""]
    verified: list[Any] = []
    for f in findings or []:
        status = ""
        if isinstance(f, dict):
            status = str(f.get("status") or "").upper()
        else:
            status = str(getattr(f, "status", "") or "").upper()
        if status in _VERIFIED_STATUSES:
            verified.append(f)
    if not verified:
        lines.append("No verified security issues reported for this change.")
        lines.append("")
        return lines

    lines.append(f"**Count:** {len(verified)}")
    lines.append("")
    for f in verified[:limit]:
        if isinstance(f, dict):
            sev = str(f.get("severity") or "unknown").upper()
            title = _safe(f.get("title") or f.get("finding_id"))
            status = f.get("status")
            conf = f.get("confidence")
            file_ = f.get("file")
            line = f.get("line")
        else:
            sev = str(getattr(f, "severity", "unknown") or "unknown").upper()
            title = _safe(getattr(f, "title", None) or getattr(f, "finding_id", ""))
            status = getattr(f, "status", None)
            conf = getattr(f, "confidence", None)
            file_ = getattr(f, "file", None)
            line = getattr(f, "line", None)
        loc = f" `{file_}:{line}`" if file_ else ""
        lines.append(f"- **{sev}** {title}{loc}")
        lines.append(f"  - Status: `{status}` · Confidence: `{conf}`")
    lines.append("")
    return lines


def format_predictive_section(
    predictive: dict[str, Any] | None,
    *,
    limit: int = 12,
) -> list[str]:
    """Format predictive risks — explicit PREDICTIVE language, no certainty claims."""
    lines = [f"### {SECTION_PREDICTIVE}", ""]
    if not predictive or not (predictive.get("risks") or predictive.get("summary")):
        lines.append("_No predictive signals from observed structural change._")
        lines.append("")
        lines.append(f"> {_safe(DISCLAIMER, limit=500)}")
        lines.append("")
        return lines

    summary = predictive.get("summary") or {}
    scores = (predictive.get("scores") or {}).get("change_risk") or {}
    lines.append(
        f"**Signals:** {summary.get('risk_count', len(predictive.get('risks') or []))} "
        f"· Change-Risk band: `{scores.get('band') or 'n/a'}`"
    )
    lines.append("")
    lines.append(
        "These are forward-looking structural signals — "
        "**not** confirmed vulnerabilities."
    )
    lines.append("")

    for r in (predictive.get("risks") or [])[:limit]:
        cat = r.get("category")
        title = _safe(r.get("title"))
        conf = r.get("confidence")
        horizon = r.get("time_horizon")
        status = r.get("change_status")
        lines.append(
            f"- **[{cat}]** {title} "
            f"(confidence `{conf}`, horizon `{horizon}`, status `{status}`)"
        )
        effect = _safe(r.get("security_effect"), limit=200)
        signal = _safe(r.get("risk_signal"), limit=200)
        if effect:
            lines.append(f"  - Effect: {effect}")
        if signal:
            lines.append(f"  - Signal: {signal}")
        trigger = r.get("trigger_change") or {}
        obs = trigger.get("observation") or trigger.get("kind")
        if obs:
            lines.append(f"  - Observed: {_safe(obs, limit=180)}")
    lines.append("")
    lines.append(f"> {_safe(predictive.get('disclaimer') or DISCLAIMER, limit=500)}")
    lines.append("")
    return lines


def format_improvements_section(
    *,
    findings: list[Any] | None = None,
    comparisons: list[dict[str, Any]] | None = None,
    regressions_resolved: list[str] | None = None,
    limit: int = 10,
) -> list[str]:
    """Improvements / risk decreases — separate from verified and predictive."""
    lines = [f"### {SECTION_IMPROVEMENTS}", ""]
    items: list[str] = []

    for f in findings or []:
        if isinstance(f, dict):
            status = str(f.get("status") or "").upper()
            life = str(f.get("lifecycle") or "").upper()
            title = _safe(f.get("title") or f.get("finding_id"))
        else:
            status = str(getattr(f, "status", "") or "").upper()
            life = str(getattr(getattr(f, "lifecycle", None), "value", getattr(f, "lifecycle", "")) or "").upper()
            title = _safe(getattr(f, "title", None) or getattr(f, "finding_id", ""))
        if status == "FALSE_POSITIVE" or life == "RESOLVED" or status == "RESOLVED":
            items.append(f"Resolved / rejected: {title} (`{status or life}`)")

    for c in comparisons or []:
        st = str(c.get("status") or "")
        if st in _IMPROVEMENT_HINTS:
            items.append(
                f"{st}: {c.get('category')} — {_safe(c.get('title') or c.get('fingerprint'))}"
            )

    for r in regressions_resolved or []:
        items.append(f"Regression cleared: {_safe(r)}")

    if not items:
        lines.append("No security improvements recorded for this change.")
        lines.append("")
        return lines

    for item in items[:limit]:
        lines.append(f"- {item}")
    lines.append("")
    return lines


def format_github_check_text(
    *,
    verified_findings: list[Any] | None = None,
    predictive: dict[str, Any] | None = None,
    comparisons: list[dict[str, Any]] | None = None,
    extra_lines: list[str] | None = None,
) -> str:
    """Full Check Run text with three separated sections."""
    parts: list[str] = []
    parts.extend(format_verified_section(list(verified_findings or [])))
    parts.append("---")
    parts.append("")
    parts.extend(format_predictive_section(predictive))
    parts.append("---")
    parts.append("")
    parts.extend(
        format_improvements_section(
            findings=list(verified_findings or []),
            comparisons=comparisons or (predictive or {}).get("comparisons"),
        )
    )
    if extra_lines:
        parts.append("")
        parts.extend(extra_lines)
    return "\n".join(parts).rstrip() + "\n"


def format_github_pr_predictive_block(predictive: dict[str, Any] | None) -> str:
    """Standalone PR markdown block for predictive section only."""
    return "\n".join(format_predictive_section(predictive)).rstrip() + "\n"


def merge_predictive_into_summary_lines(
    existing_lines: list[str] | None,
    predictive: dict[str, Any] | None,
) -> list[str]:
    """Append a clearly separated predictive block to summary_lines (additive)."""
    lines = list(existing_lines or [])
    if not predictive or not predictive.get("risks"):
        return lines
    if lines and lines[-1].strip():
        lines.append("")
    lines.append("---")
    lines.extend(format_predictive_section(predictive))
    return lines
