"""Predictive Security Intelligence — schema, categories, and empty factories.

Core principle: OBSERVED CHANGE → SECURITY EFFECT → RISK SIGNAL →
HISTORICAL/STRUCTURAL EVIDENCE → PREDICTIVE RISK.

Never pattern→guess→future CVE. Prefer UNKNOWN over inventing history.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

PREDICTIVE_VERSION = "1.0.0"
TOOL_NAME = "axguard"
UNKNOWN = "UNKNOWN"

# ---------------------------------------------------------------------------
# Risk categories
# ---------------------------------------------------------------------------
CAT_ATTACK_SURFACE_EXPANSION = "ATTACK_SURFACE_EXPANSION"
CAT_PRIVILEGE_EXPANSION = "PRIVILEGE_EXPANSION"
CAT_TRUST_BOUNDARY_EXPANSION = "TRUST_BOUNDARY_EXPANSION"
CAT_AUTHORIZATION_DRIFT = "AUTHORIZATION_DRIFT"
CAT_TENANT_ISOLATION_RISK = "TENANT_ISOLATION_RISK"
CAT_SENSITIVE_DATA_FLOW = "SENSITIVE_DATA_FLOW"
CAT_EXTERNAL_INTEGRATION_RISK = "EXTERNAL_INTEGRATION_RISK"
CAT_DEPENDENCY_RISK = "DEPENDENCY_RISK"
CAT_CLOUD_PRIVILEGE_RISK = "CLOUD_PRIVILEGE_RISK"
CAT_SECRET_MANAGEMENT_RISK = "SECRET_MANAGEMENT_RISK"
CAT_AI_AGENT_PRIVILEGE_RISK = "AI_AGENT_PRIVILEGE_RISK"
CAT_MCP_TRUST_RISK = "MCP_TRUST_RISK"
CAT_TOOL_PERMISSION_RISK = "TOOL_PERMISSION_RISK"
CAT_SECURITY_CONTROL_COMPLEXITY = "SECURITY_CONTROL_COMPLEXITY"
CAT_SECURITY_DEBT = "SECURITY_DEBT"
CAT_REGRESSION_RISK = "REGRESSION_RISK"
CAT_ARCHITECTURE_DRIFT = "ARCHITECTURE_DRIFT"
CAT_API_EXPOSURE_RISK = "API_EXPOSURE_RISK"
CAT_NETWORK_EXPOSURE_RISK = "NETWORK_EXPOSURE_RISK"

RISK_CATEGORIES = frozenset(
    {
        CAT_ATTACK_SURFACE_EXPANSION,
        CAT_PRIVILEGE_EXPANSION,
        CAT_TRUST_BOUNDARY_EXPANSION,
        CAT_AUTHORIZATION_DRIFT,
        CAT_TENANT_ISOLATION_RISK,
        CAT_SENSITIVE_DATA_FLOW,
        CAT_EXTERNAL_INTEGRATION_RISK,
        CAT_DEPENDENCY_RISK,
        CAT_CLOUD_PRIVILEGE_RISK,
        CAT_SECRET_MANAGEMENT_RISK,
        CAT_AI_AGENT_PRIVILEGE_RISK,
        CAT_MCP_TRUST_RISK,
        CAT_TOOL_PERMISSION_RISK,
        CAT_SECURITY_CONTROL_COMPLEXITY,
        CAT_SECURITY_DEBT,
        CAT_REGRESSION_RISK,
        CAT_ARCHITECTURE_DRIFT,
        CAT_API_EXPOSURE_RISK,
        CAT_NETWORK_EXPOSURE_RISK,
    }
)

# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------
CONF_HIGH = "HIGH"
CONF_MEDIUM = "MEDIUM"
CONF_LOW = "LOW"
CONF_UNKNOWN = "UNKNOWN"

CONFIDENCE_LEVELS = frozenset({CONF_HIGH, CONF_MEDIUM, CONF_LOW, CONF_UNKNOWN})

# ---------------------------------------------------------------------------
# Time horizon
# ---------------------------------------------------------------------------
HORIZON_IMMEDIATE = "IMMEDIATE"
HORIZON_NEAR_TERM = "NEAR_TERM"
HORIZON_LONGER_TERM = "LONGER_TERM"

TIME_HORIZONS = frozenset(
    {HORIZON_IMMEDIATE, HORIZON_NEAR_TERM, HORIZON_LONGER_TERM}
)

# ---------------------------------------------------------------------------
# Risk change status (previous vs new)
# ---------------------------------------------------------------------------
STATUS_RISK_INCREASED = "RISK_INCREASED"
STATUS_RISK_DECREASED = "RISK_DECREASED"
STATUS_STABLE = "STABLE"
STATUS_RESOLVED = "RESOLVED"
STATUS_NEW_RISK = "NEW_RISK"

RISK_CHANGE_STATUSES = frozenset(
    {
        STATUS_RISK_INCREASED,
        STATUS_RISK_DECREASED,
        STATUS_STABLE,
        STATUS_RESOLVED,
        STATUS_NEW_RISK,
    }
)

# ---------------------------------------------------------------------------
# Pipeline modes
# ---------------------------------------------------------------------------
MODE_ARCHITECTURE = "architecture"
MODE_AGENT = "agent"
MODE_MCP = "mcp"
MODE_PR = "pr"
MODE_WHAT_IF = "what-if"
MODE_DEFAULT = "default"

PREDICT_MODES = frozenset(
    {
        MODE_ARCHITECTURE,
        MODE_AGENT,
        MODE_MCP,
        MODE_PR,
        MODE_WHAT_IF,
        MODE_DEFAULT,
    }
)

DISCLAIMER = (
    "Predictive Security signal — derived from observed structural change and "
    "supporting evidence. Not a confirmed vulnerability or exploitability claim. "
    "Do not interpret as a future CVE prediction."
)


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


@dataclass
class PredictiveRisk:
    """Forward-looking risk signal grounded in observed change + evidence."""

    risk_id: str
    category: str
    title: str
    trigger_change: dict[str, Any]
    supporting_evidence: list[dict[str, Any]]
    security_effect: str
    risk_signal: str
    confidence: str = CONF_UNKNOWN
    time_horizon: str = HORIZON_NEAR_TERM
    change_status: str = STATUS_NEW_RISK
    historical_evidence: list[dict[str, Any]] = field(default_factory=list)
    structural_evidence: list[dict[str, Any]] = field(default_factory=list)
    score_factors: list[dict[str, Any]] = field(default_factory=list)
    debt_factors: list[dict[str, Any]] = field(default_factory=list)
    change_risk_score: float | None = None
    related_paths: list[str] = field(default_factory=list)
    related_entities: list[str] = field(default_factory=list)
    status: str = "PREDICTIVE"
    disclaimer: str = DISCLAIMER
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def empty_predict_result(
    *,
    target: str = UNKNOWN,
    mode: str = MODE_DEFAULT,
) -> dict[str, Any]:
    return {
        "schema_version": PREDICTIVE_VERSION,
        "tool": TOOL_NAME,
        "kind": "predictive_security",
        "target": target,
        "mode": mode,
        "generated_at": utc_now(),
        "status": "PREDICTIVE",
        "risks": [],
        "comparisons": [],
        "scores": {},
        "debt": {},
        "what_if": None,
        "memory": {},
        "summary": {
            "risk_count": 0,
            "by_category": {},
            "by_confidence": {},
            "by_change_status": {},
            "by_horizon": {},
        },
        "disclaimer": DISCLAIMER,
    }


def new_risk_id(prefix: str = "pred") -> str:
    return f"{prefix}-{uuid4().hex[:12]}"
