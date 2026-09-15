"""AXguard Predictive Security Intelligence.

OBSERVED CHANGE → SECURITY EFFECT → RISK SIGNAL → HISTORICAL/STRUCTURAL EVIDENCE
→ PREDICTIVE RISK.

Never pattern→guess→future CVE. Soft-imports Twin / Memory / Attack Graph.
"""

from __future__ import annotations

from engines.predictive.compare import apply_comparison_statuses, compare_risk_sets
from engines.predictive.detectors import DETECTOR_CATEGORIES, run_all_detectors
from engines.predictive.github_output import (
    format_github_check_text,
    format_github_pr_predictive_block,
    format_improvements_section,
    format_predictive_section,
    format_verified_section,
    merge_predictive_into_summary_lines,
)
from engines.predictive.memory_bridge import (
    historical_evidence_from_memory,
    load_memory_regressions,
)
from engines.predictive.model import (
    PredictiveBuildError,
    build_predictive_risk,
    risk_to_dict,
    try_build_predictive_risk,
)
from engines.predictive.pipeline import run_predict
from engines.predictive.report import (
    render_predictive_html_section,
    render_predictive_markdown,
    write_predictive_report,
)
from engines.predictive.schema import (
    CONF_HIGH,
    CONF_LOW,
    CONF_MEDIUM,
    CONF_UNKNOWN,
    DISCLAIMER,
    HORIZON_IMMEDIATE,
    HORIZON_LONGER_TERM,
    HORIZON_NEAR_TERM,
    MODE_AGENT,
    MODE_ARCHITECTURE,
    MODE_DEFAULT,
    MODE_MCP,
    MODE_PR,
    MODE_WHAT_IF,
    PREDICTIVE_VERSION,
    PredictiveRisk,
    RISK_CATEGORIES,
    STATUS_NEW_RISK,
    STATUS_RESOLVED,
    STATUS_RISK_DECREASED,
    STATUS_RISK_INCREASED,
    STATUS_STABLE,
    empty_predict_result,
)
from engines.predictive.score import compute_change_risk, compute_security_debt
from engines.predictive.whatif import run_predictive_what_if

__all__ = [
    "PREDICTIVE_VERSION",
    "DISCLAIMER",
    "PredictiveRisk",
    "PredictiveBuildError",
    "RISK_CATEGORIES",
    "DETECTOR_CATEGORIES",
    "CONF_HIGH",
    "CONF_MEDIUM",
    "CONF_LOW",
    "CONF_UNKNOWN",
    "HORIZON_IMMEDIATE",
    "HORIZON_NEAR_TERM",
    "HORIZON_LONGER_TERM",
    "STATUS_RISK_INCREASED",
    "STATUS_RISK_DECREASED",
    "STATUS_STABLE",
    "STATUS_RESOLVED",
    "STATUS_NEW_RISK",
    "MODE_ARCHITECTURE",
    "MODE_AGENT",
    "MODE_MCP",
    "MODE_PR",
    "MODE_WHAT_IF",
    "MODE_DEFAULT",
    "empty_predict_result",
    "build_predictive_risk",
    "try_build_predictive_risk",
    "risk_to_dict",
    "run_all_detectors",
    "run_predict",
    "run_predictive_what_if",
    "compare_risk_sets",
    "apply_comparison_statuses",
    "compute_change_risk",
    "compute_security_debt",
    "load_memory_regressions",
    "historical_evidence_from_memory",
    "render_predictive_markdown",
    "render_predictive_html_section",
    "write_predictive_report",
    "format_verified_section",
    "format_predictive_section",
    "format_improvements_section",
    "format_github_check_text",
    "format_github_pr_predictive_block",
    "merge_predictive_into_summary_lines",
]
