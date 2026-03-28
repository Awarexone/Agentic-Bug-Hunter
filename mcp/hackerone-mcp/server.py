#!/usr/bin/env python3
"""
HackerOne MCP Server — public endpoints only (no auth required).

Provides three tools:
  - search_disclosed_reports: Search Hacktivity for disclosed reports
  - get_program_stats: Bounty ranges, response times, resolved counts
  - get_program_policy: Safe harbor, response SLA, excluded vuln classes

This is a lightweight wrapper around HackerOne's public GraphQL API.
Authenticated endpoints (submit_report, private scope) are deferred.

Usage (standalone test):
    python3 mcp/hackerone-mcp/server.py search "ssrf" --limit 5
    python3 mcp/hackerone-mcp/server.py stats "example-corp"
    python3 mcp/hackerone-mcp/server.py policy "example-corp"

MCP integration:
    Add to .claude/settings.json mcpServers — see config.json.
"""

from __future__ import annotations

import json
import ssl
import sys
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone


# ─── SSL context ─────────────────────────────────────────────────────────────
_SSL_CTX = ssl.create_default_context()
try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE

H1_GRAPHQL = "https://hackerone.com/graphql"
DEFAULT_TIMEOUT = 15


class HackerOneAPIError(Exception):
    """Raised on API failures (rate limit, timeout, bad response)."""
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


def _graphql_request(query: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Execute a GraphQL request against HackerOne's public API."""
    payload = json.dumps({"query": query}).encode("utf-8")
    req = urllib.request.Request(
        H1_GRAPHQL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "claude-bug-bounty/2.1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(body)
            if "errors" in data:
                raise HackerOneAPIError(
                    f"GraphQL errors: {data['errors']}",
                    status_code=200,
                )
            return data
    except urllib.error.HTTPError as e:
        raise HackerOneAPIError(
            f"HTTP {e.code}: {e.reason}",
            status_code=e.code,
        )
    except urllib.error.URLError as e:
        raise HackerOneAPIError(f"Network error: {e.reason}")
    except json.JSONDecodeError as e:
        raise HackerOneAPIError(f"Invalid JSON response: {e}")


# ─── Tool: search_disclosed_reports ──────────────────────────────────────────

def search_disclosed_reports(
    keyword: str = "",
    program: str = "",
    limit: int = 10,
) -> list[dict]:
    """Search HackerOne Hacktivity for disclosed reports.

    Args:
        keyword: Search term (vuln type, tech, etc.)
        program: HackerOne program handle (e.g. "shopify")
        limit: Max results (1-25)

    Returns:
        List of disclosed report summaries.
    """
    limit = max(1, min(25, limit))

    where_clauses = ['disclosed_at: { _is_null: false }']
    if keyword:
        safe_keyword = keyword.replace('"', '\\"')
        where_clauses.append(
            f'report: {{ title: {{ _icontains: "{safe_keyword}" }} }}'
        )
    if program:
        safe_program = program.replace('"', '\\"')
        where_clauses.append(
            f'team: {{ handle: {{ _eq: "{safe_program}" }} }}'
        )

    where = ", ".join(where_clauses)

    query = f"""{{
      hacktivity(
        first: {limit},
        order_by: {{ field: popular, direction: DESC }},
        where: {{ {where} }}
      ) {{
        nodes {{
          ... on HacktivityDocument {{
            report {{
              title
              severity_rating
              disclosed_at
              url
              substate
            }}
            team {{
              handle
              name
            }}
          }}
        }}
      }}
    }}"""

    data = _graphql_request(query)
    nodes = (data.get("data") or {}).get("hacktivity", {}).get("nodes", [])

    results = []
    for node in nodes:
        report = node.get("report")
        if not report:
            continue
        team = node.get("team") or {}
        results.append({
            "title": report.get("title", ""),
            "severity": (report.get("severity_rating") or "unknown").upper(),
            "disclosed_at": (report.get("disclosed_at") or "")[:10],
            "url": report.get("url", ""),
            "state": report.get("substate", ""),
            "program": team.get("handle", ""),
            "program_name": team.get("name", ""),
        })

    return results


# ─── Tool: get_program_stats ────────────────────────────────────────────────

def get_program_stats(program: str) -> dict:
    """Get public statistics for a HackerOne program.

    Args:
        program: HackerOne program handle (e.g. "shopify")

    Returns:
        Dict with bounty info, response times, resolved counts.
    """
    safe_program = program.replace('"', '\\"')
    query = f"""{{
      team(handle: "{safe_program}") {{
        name
        handle
        url
        offers_bounties
        base_bounty
        average_bounty_lower_amount
        average_bounty_upper_amount
        resolved_report_count
        launched_at
        state
      }}
    }}"""

    data = _graphql_request(query)
    team = (data.get("data") or {}).get("team")
    if not team:
        return {"error": f"Program '{program}' not found", "program": program}

    return {
        "program": team.get("handle", ""),
        "name": team.get("name", ""),
        "url": team.get("url", ""),
        "offers_bounties": team.get("offers_bounties", False),
        "base_bounty": team.get("base_bounty"),
        "avg_bounty_lower": team.get("average_bounty_lower_amount"),
        "avg_bounty_upper": team.get("average_bounty_upper_amount"),
        "resolved_reports": team.get("resolved_report_count"),
        "launched_at": (team.get("launched_at") or "")[:10],
        "state": team.get("state", ""),
    }


# ─── Tool: get_program_policy ────────────────────────────────────────────────

def get_program_policy(program: str) -> dict:
    """Get the public policy for a HackerOne program.

    Args:
        program: HackerOne program handle (e.g. "shopify")

    Returns:
        Dict with safe harbor status, response SLAs, excluded vuln classes.
    """
    safe_program = program.replace('"', '\\"')
    query = f"""{{
      team(handle: "{safe_program}") {{
        name
        handle
        policy
        offers_bounties
        structured_scopes(first: 50, archived: false) {{
          nodes {{
            asset_type
            asset_identifier
            eligible_for_bounty
            eligible_for_submission
            instruction
          }}
        }}
      }}
    }}"""

    data = _graphql_request(query)
    team = (data.get("data") or {}).get("team")
    if not team:
        return {"error": f"Program '{program}' not found", "program": program}

    scopes = []
    scope_nodes = (team.get("structured_scopes") or {}).get("nodes", [])
    for s in scope_nodes:
        scopes.append({
            "type": s.get("asset_type", ""),
            "identifier": s.get("asset_identifier", ""),
            "bounty_eligible": s.get("eligible_for_bounty", False),
            "submission_eligible": s.get("eligible_for_submission", True),
            "instruction": s.get("instruction", ""),
        })

    return {
        "program": team.get("handle", ""),
        "name": team.get("name", ""),
        "offers_bounties": team.get("offers_bounties", False),
        "policy_text": team.get("policy", ""),
        "scopes": scopes,
    }


# ─── MCP Server (JSON-RPC 2.0 over stdio) ────────────────────────────────────

_MCP_TOOLS = [
    {
        "name": "search_disclosed_reports",
        "description": "Search HackerOne Hacktivity for publicly disclosed bug bounty reports by keyword and/or program.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keyword": {"type": "string",  "description": "Search term (vuln type, tech, CVE, etc.)"},
                "program": {"type": "string",  "description": "HackerOne program handle (e.g. 'shopify')"},
                "limit":   {"type": "integer", "description": "Max results (1-25, default 10)"},
            },
        },
    },
    {
        "name": "get_program_stats",
        "description": "Get public statistics for a HackerOne program: bounty ranges, response times, resolved report count.",
        "inputSchema": {
            "type": "object",
            "required": ["program"],
            "properties": {
                "program": {"type": "string", "description": "HackerOne program handle (e.g. 'shopify')"},
            },
        },
    },
    {
        "name": "get_program_policy",
        "description": "Get the public policy for a HackerOne program: safe harbor, scope, excluded vuln classes.",
        "inputSchema": {
            "type": "object",
            "required": ["program"],
            "properties": {
                "program": {"type": "string", "description": "HackerOne program handle (e.g. 'shopify')"},
            },
        },
    },
]


def _dispatch(name: str, args: dict):
    if name == "search_disclosed_reports":
        return search_disclosed_reports(
            keyword=args.get("keyword", ""),
            program=args.get("program", ""),
            limit=args.get("limit", 10),
        )
    elif name == "get_program_stats":
        return get_program_stats(args["program"])
    elif name == "get_program_policy":
        return get_program_policy(args["program"])
    else:
        raise ValueError(f"Unknown tool: {name}")


def mcp_server():
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue

        msg_id = msg.get("id")
        method = msg.get("method", "")

        if method.startswith("notifications/"):
            continue

        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "hackerone-mcp", "version": "1.0.0"},
                },
            }
        elif method == "tools/list":
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": _MCP_TOOLS},
            }
        elif method == "tools/call":
            params = msg.get("params", {})
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})
            try:
                result = _dispatch(tool_name, tool_args)
                response = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]},
                }
            except Exception as e:
                response = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Error: {e}"}],
                        "isError": True,
                    },
                }
        else:
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }

        print(json.dumps(response), flush=True)


# ─── CLI interface ───────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        mcp_server()
        return

    cmd = sys.argv[1]

    try:
        if cmd == "search":
            keyword = sys.argv[2] if len(sys.argv) > 2 else ""
            program = ""
            limit = 10
            i = 3
            while i < len(sys.argv):
                if sys.argv[i] == "--program" and i + 1 < len(sys.argv):
                    program = sys.argv[i + 1]
                    i += 2
                elif sys.argv[i] == "--limit" and i + 1 < len(sys.argv):
                    limit = int(sys.argv[i + 1])
                    i += 2
                else:
                    i += 1
            results = search_disclosed_reports(keyword=keyword, program=program, limit=limit)
            print(json.dumps(results, indent=2))

        elif cmd == "stats":
            program = sys.argv[2] if len(sys.argv) > 2 else ""
            if not program:
                print("Error: program handle required")
                sys.exit(1)
            result = get_program_stats(program)
            print(json.dumps(result, indent=2))

        elif cmd == "policy":
            program = sys.argv[2] if len(sys.argv) > 2 else ""
            if not program:
                print("Error: program handle required")
                sys.exit(1)
            result = get_program_policy(program)
            print(json.dumps(result, indent=2))

        else:
            print(f"Unknown command: {cmd}")
            sys.exit(1)

    except HackerOneAPIError as e:
        print(json.dumps({"error": str(e), "status_code": e.status_code}))
        sys.exit(1)


if __name__ == "__main__":
    main()
