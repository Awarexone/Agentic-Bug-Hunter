#!/usr/bin/env python3
"""
Caido MCP Server — proxy history, request inspection, replay, findings, and PoC export.

Provides seven tools:
  - get_proxy_history: List recent requests from Caido proxy (filterable)
  - get_request:       Full request + response for a specific ID
  - search_requests:   Search proxy history by host or path keyword
  - export_for_report: Format a request/response as a PoC block for report writing
  - replay_request:    Send a modified copy of a captured request and return the response
  - get_findings:      List findings/issues logged in Caido
  - add_note:          Annotate a request with a note (visible in Caido UI)

Requires Caido running locally with an API key configured.
Default: http://127.0.0.1:8080

Usage (standalone test):
    python3 mcp/caido-mcp/server.py history --host example.com --limit 20
    python3 mcp/caido-mcp/server.py get <request_id>
    python3 mcp/caido-mcp/server.py search example.com --limit 10
    python3 mcp/caido-mcp/server.py export <request_id>
    python3 mcp/caido-mcp/server.py replay <request_id> [--header "Name: Value"] [--body '{"id":2}'] [--path /new/path]
    python3 mcp/caido-mcp/server.py findings [--limit 50]
    python3 mcp/caido-mcp/server.py note <request_id> "Possible IDOR — returns victim data"

MCP integration:
    Add to .claude/settings.json mcpServers — see config.json.
    Set CAIDO_API_KEY and (optionally) CAIDO_URL in your environment.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime


# ─── Config ──────────────────────────────────────────────────────────────────

CAIDO_URL = os.environ.get("CAIDO_URL", "http://127.0.0.1:8080").rstrip("/")
CAIDO_API_KEY = os.environ.get("CAIDO_API_KEY", "")
GRAPHQL_ENDPOINT = f"{CAIDO_URL}/graphql"
DEFAULT_TIMEOUT = 10

# SSL context — Caido runs on localhost HTTP so no cert needed,
# but handle HTTPS setups gracefully.
_SSL_CTX = ssl.create_default_context()
try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE


class CaidoAPIError(Exception):
    """Raised on API failures (auth, timeout, bad response, schema mismatch)."""
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


def _graphql(query: str, variables: dict | None = None) -> dict:
    """Execute a GraphQL request against the local Caido instance."""
    if not CAIDO_API_KEY:
        raise CaidoAPIError(
            "CAIDO_API_KEY not set. Export it: export CAIDO_API_KEY=your-key-here"
        )

    payload = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    req = urllib.request.Request(
        GRAPHQL_ENDPOINT,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {CAIDO_API_KEY}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT, context=_SSL_CTX) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(body)
            if "errors" in data:
                raise CaidoAPIError(f"GraphQL errors: {data['errors']}")
            return data
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise CaidoAPIError("Unauthorized — check CAIDO_API_KEY", status_code=401)
        raise CaidoAPIError(f"HTTP {e.code}: {e.reason}", status_code=e.code)
    except urllib.error.URLError as e:
        raise CaidoAPIError(
            f"Cannot reach Caido at {CAIDO_URL}. Is it running? ({e.reason})"
        )
    except json.JSONDecodeError as e:
        raise CaidoAPIError(f"Invalid JSON response: {e}")


# ─── Tool: get_proxy_history ──────────────────────────────────────────────────

def get_proxy_history(
    host: str = "",
    method: str = "",
    status: int | None = None,
    limit: int = 50,
) -> list[dict]:
    """List recent requests from Caido proxy history.

    Args:
        host:   Filter by hostname (partial match, e.g. "example.com")
        method: Filter by HTTP method (e.g. "POST")
        status: Filter by response status code (e.g. 200)
        limit:  Max results (1-200, default 50)

    Returns:
        List of request summaries (id, method, host, path, status, created_at).
    """
    limit = max(1, min(200, limit))

    # Build filter conditions
    filter_parts = []
    if host:
        filter_parts.append(f'host: {{ contains: "{_esc(host)}" }}')
    if method:
        filter_parts.append(f'method: {{ eq: "{_esc(method.upper())}" }}')
    if status is not None:
        filter_parts.append(f'response: {{ statusCode: {{ eq: {int(status)} }} }}')

    filter_block = ""
    if filter_parts:
        filter_block = f', filter: {{ {", ".join(filter_parts)} }}'

    query = f"""
    query {{
      requests(first: {limit}{filter_block}) {{
        edges {{
          node {{
            id
            host
            port
            path
            query
            method
            createdAt
            response {{
              statusCode
              roundtripTime
            }}
          }}
        }}
        pageInfo {{
          hasNextPage
          endCursor
        }}
      }}
    }}
    """

    data = _graphql(query)
    edges = (data.get("data") or {}).get("requests", {}).get("edges", [])

    results = []
    for edge in edges:
        node = edge.get("node") or {}
        resp = node.get("response") or {}
        path = node.get("path", "/")
        qs = node.get("query", "")
        full_path = f"{path}?{qs}" if qs else path
        results.append({
            "id": node.get("id", ""),
            "method": node.get("method", ""),
            "host": node.get("host", ""),
            "port": node.get("port"),
            "path": full_path,
            "status": resp.get("statusCode"),
            "roundtrip_ms": resp.get("roundtripTime"),
            "created_at": _fmt_time(node.get("createdAt")),
        })

    return results


# ─── Tool: get_request ────────────────────────────────────────────────────────

def get_request(request_id: str) -> dict:
    """Get full request and response details for a specific Caido request ID.

    Args:
        request_id: Caido request ID (from get_proxy_history)

    Returns:
        Dict with full request headers/body and response headers/body.
    """
    query = """
    query GetRequest($id: ID!) {
      request(id: $id) {
        id
        host
        port
        path
        query
        method
        httpVersion
        headers {
          name
          value
        }
        body {
          toText
        }
        createdAt
        response {
          statusCode
          httpVersion
          headers {
            name
            value
          }
          body {
            toText
          }
          roundtripTime
        }
      }
    }
    """

    data = _graphql(query, {"id": request_id})
    req = (data.get("data") or {}).get("request")
    if not req:
        return {"error": f"Request '{request_id}' not found"}

    resp = req.get("response") or {}
    path = req.get("path", "/")
    qs = req.get("query", "")
    full_path = f"{path}?{qs}" if qs else path

    return {
        "id": req.get("id"),
        "request": {
            "method": req.get("method"),
            "host": req.get("host"),
            "port": req.get("port"),
            "path": full_path,
            "http_version": req.get("httpVersion", "HTTP/1.1"),
            "headers": req.get("headers", []),
            "body": (req.get("body") or {}).get("toText", ""),
            "created_at": _fmt_time(req.get("createdAt")),
        },
        "response": {
            "status": resp.get("statusCode"),
            "http_version": resp.get("httpVersion", "HTTP/1.1"),
            "headers": resp.get("headers", []),
            "body": (resp.get("body") or {}).get("toText", ""),
            "roundtrip_ms": resp.get("roundtripTime"),
        },
    }


# ─── Tool: search_requests ────────────────────────────────────────────────────

def search_requests(keyword: str, limit: int = 25) -> list[dict]:
    """Search Caido proxy history by host or path keyword.

    Args:
        keyword: Search term matched against host + path (case-insensitive)
        limit:   Max results (1-100, default 25)

    Returns:
        List of matching request summaries.
    """
    limit = max(1, min(100, limit))

    # Caido filter supports OR across host and path via separate filters.
    # We run host search — callers can also filter by path if needed.
    query = f"""
    query {{
      requests(first: {limit}, filter: {{ host: {{ contains: "{_esc(keyword)}" }} }}) {{
        edges {{
          node {{
            id
            host
            port
            path
            query
            method
            createdAt
            response {{
              statusCode
            }}
          }}
        }}
      }}
    }}
    """

    data = _graphql(query)
    edges = (data.get("data") or {}).get("requests", {}).get("edges", [])

    results = []
    for edge in edges:
        node = edge.get("node") or {}
        resp = node.get("response") or {}
        path = node.get("path", "/")
        qs = node.get("query", "")
        full_path = f"{path}?{qs}" if qs else path
        results.append({
            "id": node.get("id", ""),
            "method": node.get("method", ""),
            "host": node.get("host", ""),
            "port": node.get("port"),
            "path": full_path,
            "status": resp.get("statusCode"),
            "created_at": _fmt_time(node.get("createdAt")),
        })

    return results


# ─── Tool: export_for_report ──────────────────────────────────────────────────

def export_for_report(request_id: str) -> str:
    """Format a Caido request/response as a PoC block for bug bounty reports.

    Produces a clean HTTP request + response block suitable for pasting directly
    into the 'Steps to Reproduce' section of an H1, Bugcrowd, or Intigriti report.

    Args:
        request_id: Caido request ID

    Returns:
        Formatted string with REQUEST and RESPONSE blocks.
    """
    result = get_request(request_id)
    if "error" in result:
        return f"Error: {result['error']}"

    req = result["request"]
    resp = result["response"]

    # ── REQUEST block ──
    host_header = req["host"]
    if req.get("port") and req["port"] not in (80, 443):
        host_header = f"{req['host']}:{req['port']}"

    req_lines = [f"{req['method']} {req['path']} {req['http_version']}"]

    # Add Host header first if not already in headers
    header_names = {h["name"].lower() for h in req.get("headers", [])}
    if "host" not in header_names:
        req_lines.append(f"Host: {host_header}")

    for h in req.get("headers", []):
        req_lines.append(f"{h['name']}: {h['value']}")

    if req.get("body"):
        req_lines.append("")
        req_lines.append(req["body"])

    # ── RESPONSE block ──
    resp_lines = [f"{resp.get('http_version', 'HTTP/1.1')} {resp.get('status', '')}"]
    for h in resp.get("headers", []):
        resp_lines.append(f"{h['name']}: {h['value']}")
    if resp.get("body"):
        resp_lines.append("")
        resp_lines.append(resp["body"])

    output = [
        f"### Request (Caido ID: {request_id})",
        "```http",
        "\n".join(req_lines),
        "```",
        "",
        "### Response",
        "```http",
        "\n".join(resp_lines),
        "```",
    ]

    if resp.get("roundtrip_ms") is not None:
        output.append(f"\n_Round-trip: {resp['roundtrip_ms']}ms_")

    return "\n".join(output)


# ─── Tool: replay_request ────────────────────────────────────────────────────

def replay_request(
    request_id: str,
    overrides: dict | None = None,
) -> dict:
    """Send a modified copy of a captured request through Caido and return the response.

    Useful for PoC verification: swap an ID, change an auth header, or modify the
    body to confirm a finding fires with different parameters.

    Args:
        request_id: Caido request ID to replay (from get_proxy_history)
        overrides:  Optional dict of fields to change before sending:
                      method  — HTTP method (e.g. "POST")
                      path    — URL path (e.g. "/api/v1/user/2")
                      headers — list of {"name": str, "value": str} to add/replace
                      body    — request body string to replace

    Returns:
        Dict with the replay response (status, headers, body, roundtrip_ms)
        plus the original request_id and any overrides applied.

    Note:
        Uses Caido's replay mutation (v0.40+). If this returns a schema error,
        check the available mutations in Caido's GraphQL playground at
        http://127.0.0.1:8080/graphql.
    """
    overrides = overrides or {}

    # Build the overrides input block for GraphQL
    override_parts = []
    if "method" in overrides:
        override_parts.append(f'method: "{_esc(overrides["method"].upper())}"')
    if "path" in overrides:
        override_parts.append(f'path: "{_esc(overrides["path"])}"')
    if "body" in overrides:
        override_parts.append(f'body: "{_esc(overrides["body"])}"')
    if "headers" in overrides:
        header_inputs = ", ".join(
            f'{{ name: "{_esc(h["name"])}", value: "{_esc(h["value"])}" }}'
            for h in overrides["headers"]
        )
        override_parts.append(f"headers: [{header_inputs}]")

    overrides_block = ""
    if override_parts:
        overrides_block = f', overrides: {{ {", ".join(override_parts)} }}'

    mutation = f"""
    mutation {{
      replayRequest(requestId: "{_esc(request_id)}"{overrides_block}) {{
        response {{
          statusCode
          httpVersion
          headers {{
            name
            value
          }}
          body {{
            toText
          }}
          roundtripTime
        }}
      }}
    }}
    """

    data = _graphql(mutation)
    resp_data = (data.get("data") or {}).get("replayRequest", {}).get("response")
    if not resp_data:
        return {
            "error": "replayRequest returned no response — check Caido version or request ID",
            "request_id": request_id,
        }

    return {
        "request_id": request_id,
        "overrides_applied": overrides,
        "response": {
            "status": resp_data.get("statusCode"),
            "http_version": resp_data.get("httpVersion", "HTTP/1.1"),
            "headers": resp_data.get("headers", []),
            "body": (resp_data.get("body") or {}).get("toText", ""),
            "roundtrip_ms": resp_data.get("roundtripTime"),
        },
    }


# ─── Tool: get_findings ───────────────────────────────────────────────────────

def get_findings(limit: int = 50) -> list[dict]:
    """List findings logged in Caido.

    Caido's Findings tab stores issues you've manually flagged or that were
    auto-detected. This pulls them all so Claude can see what's already been
    identified and avoid duplicating work.

    Args:
        limit: Max results (1-200, default 50)

    Returns:
        List of findings with id, title, severity, description, and linked request.
    """
    limit = max(1, min(200, limit))

    query = f"""
    query {{
      findings(first: {limit}) {{
        edges {{
          node {{
            id
            title
            description
            severity
            createdAt
            request {{
              id
              host
              path
              method
            }}
          }}
        }}
      }}
    }}
    """

    data = _graphql(query)
    edges = (data.get("data") or {}).get("findings", {}).get("edges", [])

    results = []
    for edge in edges:
        node = edge.get("node") or {}
        req = node.get("request") or {}
        results.append({
            "id": node.get("id", ""),
            "title": node.get("title", ""),
            "severity": node.get("severity", ""),
            "description": node.get("description", ""),
            "created_at": _fmt_time(node.get("createdAt")),
            "request": {
                "id": req.get("id", ""),
                "method": req.get("method", ""),
                "host": req.get("host", ""),
                "path": req.get("path", ""),
            } if req else None,
        })

    return results


# ─── Tool: add_note ───────────────────────────────────────────────────────────

def add_note(request_id: str, content: str) -> dict:
    """Annotate a request in Caido with a note (visible in the Caido UI).

    Use this to flag interesting requests during a hunt so they're marked
    in the proxy history for later review or report writing.

    Args:
        request_id: Caido request ID to annotate
        content:    Note text (e.g. "Possible IDOR — returns victim PII when ID incremented")

    Returns:
        Dict with the created note id and content, or an error.
    """
    mutation = f"""
    mutation {{
      createRequestNote(requestId: "{_esc(request_id)}", content: "{_esc(content)}") {{
        note {{
          id
          content
          createdAt
        }}
      }}
    }}
    """

    data = _graphql(mutation)
    note = (data.get("data") or {}).get("createRequestNote", {}).get("note")
    if not note:
        return {
            "error": "createRequestNote returned no note — check Caido version or request ID",
            "request_id": request_id,
        }

    return {
        "request_id": request_id,
        "note": {
            "id": note.get("id", ""),
            "content": note.get("content", ""),
            "created_at": _fmt_time(note.get("createdAt")),
        },
    }


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _esc(s: str) -> str:
    """Escape a string for safe inclusion in a GraphQL string literal."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _fmt_time(value) -> str:
    """Format a createdAt value — handles both ISO strings and Unix timestamps."""
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        try:
            # Caido returns milliseconds — divide to get seconds
            ts = value / 1000 if value > 1e10 else value
            return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%S")
        except Exception:
            return str(value)
    return str(value)[:19]


# ─── MCP Server (JSON-RPC 2.0 over stdio) ────────────────────────────────────

_MCP_TOOLS = [
    {
        "name": "get_proxy_history",
        "description": "List recent requests from Caido proxy history, filterable by host, method, and status code.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host":   {"type": "string",  "description": "Filter by hostname (partial match)"},
                "method": {"type": "string",  "description": "Filter by HTTP method (GET, POST, etc.)"},
                "status": {"type": "integer", "description": "Filter by response status code"},
                "limit":  {"type": "integer", "description": "Max results (default 50)"},
            },
        },
    },
    {
        "name": "get_request",
        "description": "Get full request and response details (headers, body) for a specific Caido request ID.",
        "inputSchema": {
            "type": "object",
            "required": ["request_id"],
            "properties": {
                "request_id": {"type": "string", "description": "Caido request ID"},
            },
        },
    },
    {
        "name": "search_requests",
        "description": "Search Caido proxy history by host keyword.",
        "inputSchema": {
            "type": "object",
            "required": ["keyword"],
            "properties": {
                "keyword": {"type": "string",  "description": "Search term matched against host"},
                "limit":   {"type": "integer", "description": "Max results (default 25)"},
            },
        },
    },
    {
        "name": "export_for_report",
        "description": "Format a Caido request/response as a ready-to-paste HTTP PoC block for bug bounty reports.",
        "inputSchema": {
            "type": "object",
            "required": ["request_id"],
            "properties": {
                "request_id": {"type": "string", "description": "Caido request ID"},
            },
        },
    },
    {
        "name": "replay_request",
        "description": "Resend a captured request through Caido, optionally with modified method, path, headers, or body. Use for PoC verification.",
        "inputSchema": {
            "type": "object",
            "required": ["request_id"],
            "properties": {
                "request_id": {"type": "string", "description": "Caido request ID to replay"},
                "overrides": {
                    "type": "object",
                    "description": "Fields to change before sending",
                    "properties": {
                        "method":  {"type": "string", "description": "HTTP method override"},
                        "path":    {"type": "string", "description": "URL path override"},
                        "body":    {"type": "string", "description": "Request body override"},
                        "headers": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name":  {"type": "string"},
                                    "value": {"type": "string"},
                                },
                            },
                        },
                    },
                },
            },
        },
    },
    {
        "name": "get_findings",
        "description": "List findings logged in Caido's Findings tab.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max results (default 50)"},
            },
        },
    },
    {
        "name": "add_note",
        "description": "Annotate a request in Caido with a note, visible in the Caido UI.",
        "inputSchema": {
            "type": "object",
            "required": ["request_id", "content"],
            "properties": {
                "request_id": {"type": "string", "description": "Caido request ID to annotate"},
                "content":    {"type": "string", "description": "Note text"},
            },
        },
    },
]


def _dispatch(name: str, args: dict):
    """Dispatch a tool call by name."""
    if name == "get_proxy_history":
        return get_proxy_history(
            host=args.get("host", ""),
            method=args.get("method", ""),
            status=args.get("status"),
            limit=args.get("limit", 50),
        )
    elif name == "get_request":
        return get_request(args["request_id"])
    elif name == "search_requests":
        return search_requests(args["keyword"], limit=args.get("limit", 25))
    elif name == "export_for_report":
        return export_for_report(args["request_id"])
    elif name == "replay_request":
        return replay_request(args["request_id"], overrides=args.get("overrides"))
    elif name == "get_findings":
        return get_findings(limit=args.get("limit", 50))
    elif name == "add_note":
        return add_note(args["request_id"], args["content"])
    else:
        raise ValueError(f"Unknown tool: {name}")


def mcp_server():
    """Run as an MCP server over stdio (JSON-RPC 2.0). Called when no CLI args given."""
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

        # Notifications have no id and need no response
        if method.startswith("notifications/"):
            continue

        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "caido-mcp", "version": "1.0.0"},
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
                text = json.dumps(result, indent=2) if not isinstance(result, str) else result
                response = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": text}]},
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


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args:
        # No args — run as MCP server over stdio (used by Claude Code)
        mcp_server()
        return

    cmd = args[0]

    try:
        if cmd == "history":
            host = _flag(args, "--host")
            method = _flag(args, "--method")
            status_raw = _flag(args, "--status")
            limit_raw = _flag(args, "--limit")
            status = int(status_raw) if status_raw else None
            limit = int(limit_raw) if limit_raw else 50
            results = get_proxy_history(host=host or "", method=method or "", status=status, limit=limit)
            print(json.dumps(results, indent=2))

        elif cmd == "get":
            if len(args) < 2:
                print("Error: request ID required")
                sys.exit(1)
            result = get_request(args[1])
            print(json.dumps(result, indent=2))

        elif cmd == "search":
            if len(args) < 2:
                print("Error: keyword required")
                sys.exit(1)
            limit_raw = _flag(args, "--limit")
            limit = int(limit_raw) if limit_raw else 25
            results = search_requests(args[1], limit=limit)
            print(json.dumps(results, indent=2))

        elif cmd == "export":
            if len(args) < 2:
                print("Error: request ID required")
                sys.exit(1)
            print(export_for_report(args[1]))

        elif cmd == "replay":
            if len(args) < 2:
                print("Error: request ID required")
                sys.exit(1)
            request_id = args[1]
            overrides = {}
            raw_header = _flag(args, "--header")
            if raw_header:
                # Parse "Name: Value" format
                if ": " in raw_header:
                    name, value = raw_header.split(": ", 1)
                    overrides["headers"] = [{"name": name.strip(), "value": value.strip()}]
            raw_body = _flag(args, "--body")
            if raw_body:
                overrides["body"] = raw_body
            raw_path = _flag(args, "--path")
            if raw_path:
                overrides["path"] = raw_path
            raw_method = _flag(args, "--method")
            if raw_method:
                overrides["method"] = raw_method
            result = replay_request(request_id, overrides=overrides or None)
            print(json.dumps(result, indent=2))

        elif cmd == "findings":
            limit_raw = _flag(args, "--limit")
            limit = int(limit_raw) if limit_raw else 50
            results = get_findings(limit=limit)
            print(json.dumps(results, indent=2))

        elif cmd == "note":
            if len(args) < 3:
                print("Error: request ID and note text required")
                sys.exit(1)
            result = add_note(args[1], args[2])
            print(json.dumps(result, indent=2))

        else:
            print(f"Unknown command: {cmd}")
            sys.exit(1)

    except CaidoAPIError as e:
        print(json.dumps({"error": str(e), "status_code": e.status_code}))
        sys.exit(1)


def _flag(args: list[str], name: str) -> str | None:
    """Extract --flag value from args list."""
    try:
        idx = args.index(name)
        return args[idx + 1] if idx + 1 < len(args) else None
    except ValueError:
        return None


if __name__ == "__main__":
    main()
