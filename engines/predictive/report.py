"""Predictive Security report rendering (markdown + HTML)."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from engines.predictive.schema import DISCLAIMER, UNKNOWN


def render_predictive_markdown(result: dict[str, Any]) -> str:
    summary = result.get("summary") or {}
    lines = [
        "# AXguard Predictive Security",
        "",
        f"- **Target:** `{result.get('target') or UNKNOWN}`",
        f"- **Mode:** `{result.get('mode') or UNKNOWN}`",
        f"- **Generated:** `{result.get('generated_at') or UNKNOWN}`",
        f"- **Risk signals:** {summary.get('risk_count', 0)}",
        "",
        f"> {result.get('disclaimer') or DISCLAIMER}",
        "",
        "## Principle",
        "",
        "OBSERVED CHANGE → SECURITY EFFECT → RISK SIGNAL → "
        "HISTORICAL/STRUCTURAL EVIDENCE → PREDICTIVE RISK",
        "",
        "_Never pattern→guess→future CVE._",
        "",
    ]

    scores = (result.get("scores") or {}).get("change_risk") or {}
    if scores:
        lines.extend(
            [
                "## Change-Risk (explainable)",
                "",
                f"- **Band:** `{scores.get('band')}`",
                f"- **Total weight:** {scores.get('total_weight')}",
                f"- **Confidence:** `{scores.get('confidence')}`",
                f"- {scores.get('explanation') or ''}",
                "",
            ]
        )
        for f in scores.get("factors") or []:
            lines.append(
                f"  - `{f.get('factor')}` count={f.get('count')} "
                f"unit={f.get('unit_weight')} weight={f.get('weight')} "
                f"— {f.get('evidence')}"
            )
        lines.append("")

    debt = result.get("debt") or {}
    if debt.get("factors"):
        lines.extend(
            [
                "## Security Debt (factor breakdown)",
                "",
                f"- **Band:** `{debt.get('band')}`",
                f"- **Total weight:** {debt.get('total_weight')}",
                f"- {debt.get('explanation') or ''}",
                "",
            ]
        )
        for f in debt.get("factors") or []:
            lines.append(
                f"  - `{f.get('factor')}` count={f.get('count')} "
                f"weight={f.get('weight')} — {f.get('evidence')}"
            )
        lines.append("")

    if result.get("comparisons"):
        lines.extend(["## Risk change vs previous", ""])
        for c in result["comparisons"][:30]:
            lines.append(
                f"- `{c.get('status')}` — {c.get('category')}: "
                f"{c.get('title') or c.get('risk_id') or c.get('fingerprint')}"
            )
        lines.append("")

    lines.extend(["## Predictive risks", ""])
    risks = result.get("risks") or []
    if not risks:
        lines.append("_No predictive risk signals from observed structure._")
        lines.append("")
    for r in risks:
        lines.extend(_one_risk_md(r))

    what_if = result.get("what_if")
    if isinstance(what_if, dict) and what_if.get("available"):
        lines.extend(
            [
                "## What-if (SIMULATED)",
                "",
                f"- **Scenario:** {what_if.get('scenario')}",
                f"- **Simulated paths:** {what_if.get('simulated_path_count', 0)}",
                f"- {what_if.get('note') or ''}",
                "",
            ]
        )

    mem = result.get("memory") or {}
    if mem.get("available"):
        lines.extend(
            [
                "## Security Memory",
                "",
                f"- Regressions used: {len(mem.get('REGRESSED') or [])}",
                "",
            ]
        )

    return "\n".join(lines)


def _one_risk_md(r: dict[str, Any]) -> list[str]:
    lines = [
        f"### `{r.get('risk_id')}` — {r.get('title') or UNKNOWN}",
        "",
        f"- **Category:** `{r.get('category')}`",
        f"- **Confidence:** `{r.get('confidence')}`",
        f"- **Horizon:** `{r.get('time_horizon')}`",
        f"- **Change status:** `{r.get('change_status')}`",
        f"- **Security effect:** {r.get('security_effect')}",
        f"- **Risk signal:** {r.get('risk_signal')}",
        "",
        "**Trigger (observed):**",
        "",
        f"```json\n{json.dumps(r.get('trigger_change') or {}, indent=2, default=str)}\n```",
        "",
        "**Supporting evidence:**",
        "",
    ]
    for ev in (r.get("supporting_evidence") or [])[:8]:
        lines.append(f"- {json.dumps(ev, default=str)}")
    if r.get("historical_evidence"):
        lines.append("")
        lines.append("**Historical evidence (Security Memory):**")
        lines.append("")
        for ev in r["historical_evidence"][:5]:
            lines.append(f"- {json.dumps(ev, default=str)}")
    if r.get("score_factors"):
        lines.append("")
        lines.append("**Score factors:**")
        lines.append("")
        for f in r["score_factors"][:8]:
            lines.append(
                f"- `{f.get('factor')}` weight={f.get('weight')} — {f.get('evidence')}"
            )
    lines.append("")
    lines.append(f"_{r.get('disclaimer') or DISCLAIMER}_")
    lines.append("")
    return lines


def render_predictive_html_section(result: dict[str, Any]) -> str:
    md = render_predictive_markdown(result)
    escaped = html.escape(md)
    return f"""<section class="axguard-predictive-security">
<style>
.axguard-predictive-security {{ font-family: system-ui, sans-serif; max-width: 960px; margin: 1rem auto; }}
.axguard-predictive-security .disclaimer {{ background: #fff8e6; border-left: 4px solid #e67e22; padding: 0.75rem; }}
.axguard-predictive-security .verified {{ border-left: 4px solid #2ecc71; padding-left: 1rem; }}
.axguard-predictive-security .predictive {{ border-left: 4px solid #e67e22; padding-left: 1rem; }}
.axguard-predictive-security pre {{ background: #f4f4f4; padding: 1rem; overflow-x: auto; white-space: pre-wrap; }}
</style>
<div class="disclaimer">{html.escape(str(result.get('disclaimer') or DISCLAIMER))}</div>
<div class="predictive"><h2>Predictive Security</h2><pre>{escaped}</pre></div>
</section>"""


def write_predictive_report(result: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "predictive-security.json"
    md_path = out_dir / "predictive-security.md"
    html_path = out_dir / "predictive-security.html"

    json_path.write_text(json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8")
    md_path.write_text(render_predictive_markdown(result), encoding="utf-8")
    html_path.write_text(
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>Predictive Security</title></head><body>"
        f"{render_predictive_html_section(result)}</body></html>\n",
        encoding="utf-8",
    )
    return {"json": str(json_path), "markdown": str(md_path), "html": str(html_path)}
