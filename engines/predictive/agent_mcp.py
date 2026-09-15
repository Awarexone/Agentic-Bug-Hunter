"""AI agent / MCP / tool-permission predictive detectors."""

from __future__ import annotations

from typing import Any

from engines.predictive.model import risk_to_dict, try_build_predictive_risk
from engines.predictive.schema import (
    CAT_AI_AGENT_PRIVILEGE_RISK,
    CAT_MCP_TRUST_RISK,
    CAT_TOOL_PERMISSION_RISK,
    CONF_HIGH,
    CONF_LOW,
    CONF_MEDIUM,
    HORIZON_IMMEDIATE,
    HORIZON_NEAR_TERM,
    STATUS_NEW_RISK,
    STATUS_RISK_INCREASED,
    STATUS_STABLE,
)


def _ai_counts(ag: dict[str, Any]) -> dict[str, int]:
    nodes = list((ag.get("graph") or {}).get("nodes") or [])
    agents = sum(1 for n in nodes if n.get("type") in {"ai_component", "AIAgent"})
    tools = sum(1 for n in nodes if n.get("type") in {"tool", "AITool"})
    mcp = sum(
        1
        for n in nodes
        if n.get("type") in {"MCPServer", "mcp_server"}
        or "mcp" in str(n.get("id") or "").lower()
        or "mcp" in str(n.get("kind") or "").lower()
    )
    # Twin entities if attack-graph sparse
    return {"agents": agents, "tools": tools, "mcp": mcp}


def _twin_ai_counts(twin: dict[str, Any]) -> dict[str, int]:
    entities = twin.get("entities") or []
    agents = sum(1 for e in entities if e.get("type") in {"AIAgent", "AIModel"})
    tools = sum(1 for e in entities if e.get("type") in {"AITool"})
    mcp = sum(1 for e in entities if e.get("type") in {"MCPServer"})
    return {"agents": agents, "tools": tools, "mcp": mcp}


def _privileged_tool_invokes(ag: dict[str, Any]) -> list[dict[str, Any]]:
    edges = list((ag.get("graph") or {}).get("edges") or [])
    nodes = {str(n.get("id")): n for n in (ag.get("graph") or {}).get("nodes") or []}
    out: list[dict[str, Any]] = []
    for e in edges:
        if str(e.get("type") or "") != "invokes":
            continue
        src = nodes.get(str(e.get("from"))) or {}
        dst = nodes.get(str(e.get("to"))) or {}
        if src.get("type") not in {"ai_component", "AIAgent"}:
            continue
        dst_id = str(dst.get("id") or e.get("to") or "").lower()
        kind = str(dst.get("kind") or dst.get("permission") or "").lower()
        if any(
            k in dst_id or k in kind
            for k in ("shell", "fs", "exec", "write", "admin", "network", "secret")
        ):
            out.append({"edge": e, "tool": dst.get("id"), "agent": src.get("id")})
    return out


def detect_agent_mcp_risks(
    *,
    attack_graph: dict[str, Any] | None = None,
    twin: dict[str, Any] | None = None,
    base_attack_graph: dict[str, Any] | None = None,
    base_twin: dict[str, Any] | None = None,
    memory_regressions: dict[str, Any] | None = None,
    mode: str = "default",
) -> list[dict[str, Any]]:
    del memory_regressions, mode
    ag = attack_graph or {}
    tw = twin or {}
    cur = _ai_counts(ag)
    twin_cur = _twin_ai_counts(tw)
    # Prefer max of graph + twin observed counts
    agents = max(cur["agents"], twin_cur["agents"])
    tools = max(cur["tools"], twin_cur["tools"])
    mcp = max(cur["mcp"], twin_cur["mcp"])

    base_ag = base_attack_graph or {}
    base_tw = base_twin or {}
    base = None
    if base_ag or base_tw:
        b = _ai_counts(base_ag)
        bt = _twin_ai_counts(base_tw)
        base = {
            "agents": max(b["agents"], bt["agents"]),
            "tools": max(b["tools"], bt["tools"]),
            "mcp": max(b["mcp"], bt["mcp"]),
        }

    risks: list[dict[str, Any]] = []
    if agents == 0 and tools == 0 and mcp == 0:
        return risks

    if base is not None and agents > base["agents"]:
        risk = try_build_predictive_risk(
            category=CAT_AI_AGENT_PRIVILEGE_RISK,
            title=f"{agents - base['agents']} new AI agent component(s)",
            trigger_change={
                "kind": "ai_agent_delta",
                "observation": "AI agent/component count increased",
                "before": base["agents"],
                "after": agents,
            },
            supporting_evidence=[
                {"source": "attack_graph|twin", "before": base["agents"], "after": agents}
            ],
            security_effect="Autonomous agents expand instruction-injection and tool-abuse surface",
            risk_signal="AI agent privilege surface expanding",
            confidence=CONF_HIGH if agents - base["agents"] >= 2 else CONF_MEDIUM,
            time_horizon=HORIZON_IMMEDIATE,
            change_status=STATUS_RISK_INCREASED,
        )
        if risk:
            risks.append(risk_to_dict(risk))
    elif agents:
        risk = try_build_predictive_risk(
            category=CAT_AI_AGENT_PRIVILEGE_RISK,
            title=f"{agents} AI agent component(s) observed",
            trigger_change={
                "kind": "ai_agent_snapshot",
                "observation": "AI agents present",
                "value": agents,
            },
            supporting_evidence=[{"source": "attack_graph|twin", "agents": agents, "tools": tools}],
            security_effect="Agents concentrate tool-mediated privilege",
            risk_signal="AI agent privilege surface present",
            confidence=CONF_LOW if base is None else CONF_MEDIUM,
            time_horizon=HORIZON_NEAR_TERM,
            change_status=STATUS_STABLE,
        )
        if risk:
            risks.append(risk_to_dict(risk))

    if base is not None and mcp > base["mcp"]:
        risk = try_build_predictive_risk(
            category=CAT_MCP_TRUST_RISK,
            title=f"{mcp - base['mcp']} new MCP server/trust edge(s)",
            trigger_change={
                "kind": "mcp_delta",
                "observation": "MCP-related nodes increased",
                "before": base["mcp"],
                "after": mcp,
            },
            supporting_evidence=[{"source": "attack_graph|twin", "before": base["mcp"], "after": mcp}],
            security_effect="MCP trust boundaries admit third-party tool capability into agents",
            risk_signal="MCP trust surface expanding",
            confidence=CONF_MEDIUM,
            time_horizon=HORIZON_NEAR_TERM,
            change_status=STATUS_RISK_INCREASED,
        )
        if risk:
            risks.append(risk_to_dict(risk))
    elif mcp:
        risk = try_build_predictive_risk(
            category=CAT_MCP_TRUST_RISK,
            title=f"{mcp} MCP-related node(s) observed",
            trigger_change={
                "kind": "mcp_snapshot",
                "observation": "MCP nodes present",
                "value": mcp,
            },
            supporting_evidence=[{"source": "attack_graph|twin", "mcp": mcp}],
            security_effect="MCP servers extend agent tool trust",
            risk_signal="MCP trust surface present",
            confidence=CONF_LOW if base is None else CONF_MEDIUM,
            time_horizon=HORIZON_NEAR_TERM,
            change_status=STATUS_STABLE,
        )
        if risk:
            risks.append(risk_to_dict(risk))

    privileged = _privileged_tool_invokes(ag)
    if privileged:
        risk = try_build_predictive_risk(
            category=CAT_TOOL_PERMISSION_RISK,
            title=f"{len(privileged)} privileged tool invoke edge(s)",
            trigger_change={
                "kind": "tool_permission_invokes",
                "observation": "agent invokes high-capability tools",
                "count": len(privileged),
            },
            supporting_evidence=[
                {"source": "attack_graph.edges", "sample": privileged[:5]}
            ],
            security_effect="High-capability tools amplify prompt-injection impact",
            risk_signal="Tool permission risk from observed invoke edges",
            confidence=CONF_HIGH if len(privileged) >= 2 else CONF_MEDIUM,
            time_horizon=HORIZON_IMMEDIATE,
            change_status=STATUS_NEW_RISK if base is not None else STATUS_STABLE,
            related_entities=[
                str(p.get("tool") or p.get("agent")) for p in privileged[:8]
            ],
        )
        if risk:
            risks.append(risk_to_dict(risk))
    elif tools and base is not None and tools > base["tools"]:
        risk = try_build_predictive_risk(
            category=CAT_TOOL_PERMISSION_RISK,
            title=f"{tools - base['tools']} new AI tool(s)",
            trigger_change={
                "kind": "tool_count_delta",
                "observation": "AI tool count increased",
                "before": base["tools"],
                "after": tools,
            },
            supporting_evidence=[
                {"source": "attack_graph|twin", "before": base["tools"], "after": tools}
            ],
            security_effect="More tools increase permission-boundary complexity",
            risk_signal="Tool permission surface expanding",
            confidence=CONF_MEDIUM,
            time_horizon=HORIZON_NEAR_TERM,
            change_status=STATUS_RISK_INCREASED,
        )
        if risk:
            risks.append(risk_to_dict(risk))

    return risks
