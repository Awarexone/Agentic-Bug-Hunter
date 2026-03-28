# Caido MCP Integration

Connect Claude Bug Bounty to Caido's local GraphQL API for live proxy traffic visibility.

## What You Get

With Caido MCP connected, the tool can:

- **Read proxy history** — every request/response you've captured through Caido
- **Filter traffic** — by host, method, or response status code
- **Search requests** — find all traffic to a specific domain or path
- **Export PoC blocks** — format any request/response directly into report-ready HTTP blocks

## Tools

| Tool | Command | Description |
|---|---|---|
| `get_proxy_history` | `history` | List recent proxy requests (filterable) |
| `get_request` | `get <id>` | Full request + response for a specific ID |
| `search_requests` | `search <keyword>` | Search by host keyword |
| `export_for_report` | `export <id>` | Format request/response as PoC block |
| `replay_request` | `replay <id>` | Resend a request with optional overrides (swap IDs, headers, body) |
| `get_findings` | `findings` | List findings logged in Caido |
| `add_note` | `note <id> <text>` | Annotate a request with a note (visible in Caido UI) |

## Setup (5 minutes)

### Step 1: Generate a Caido API Key

1. Open Caido and go to **Settings → API Keys**
2. Click **Generate Key**
3. Copy the key — it won't be shown again

### Step 2: Set Environment Variable

```bash
export CAIDO_API_KEY="your-api-key-here"
```

Add to your `~/.zshrc` for persistence:

```bash
echo 'export CAIDO_API_KEY="your-api-key-here"' >> ~/.zshrc
```

If Caido is running on a non-default port, also set:

```bash
export CAIDO_URL="http://127.0.0.1:8080"   # default — change if needed
```

### Step 3: Add to Claude Code Settings

Copy the MCP config into your Claude Code settings:

```bash
claude config edit
```

Add the `caido` entry from `config.json` in this directory to your `mcpServers` section.

### Step 4: Verify Connection

Start Caido and browse your target, then test from the repo root:

```bash
python3 mcp/caido-mcp/server.py history --limit 5
```

You should see a JSON list of recent proxy requests.

## Usage Examples

```bash
# Recent traffic to a target
python3 mcp/caido-mcp/server.py history --host example.com --limit 20

# Only POST requests
python3 mcp/caido-mcp/server.py history --host example.com --method POST

# Only 200 responses
python3 mcp/caido-mcp/server.py history --host example.com --status 200

# Full request + response for a specific ID
python3 mcp/caido-mcp/server.py get abc123

# Export a PoC block for a report
python3 mcp/caido-mcp/server.py export abc123

# Replay a request as-is (confirm it still works)
python3 mcp/caido-mcp/server.py replay abc123

# Replay with a different user ID in the path (IDOR test)
python3 mcp/caido-mcp/server.py replay abc123 --path /api/v1/user/2

# Replay with a different auth header (cross-account test)
python3 mcp/caido-mcp/server.py replay abc123 --header "Authorization: Bearer <victim-token>"

# Replay with a modified body
python3 mcp/caido-mcp/server.py replay abc123 --body '{"user_id": 2}'

# List all findings logged in Caido
python3 mcp/caido-mcp/server.py findings

# Annotate a request with a note
python3 mcp/caido-mcp/server.py note abc123 "Possible IDOR — returns victim PII when ID incremented"
```

## Example PoC Output

`export_for_report` produces report-ready HTTP blocks:

```
### Request (Caido ID: abc123)
```http
GET /api/v1/user/456/profile HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJ...
```

### Response
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"id":456,"email":"victim@example.com","phone":"555-1234"}
```

_Round-trip: 142ms_
```

Paste this directly into the **Steps to Reproduce** section of your report.

## Without Caido

All commands work without Caido MCP. The tool falls back to:

- `curl` for HTTP requests (provide auth headers manually)
- Manual request/response pasting for PoC sections

## Troubleshooting

| Problem | Fix |
|---|---|
| `CAIDO_API_KEY not set` | `export CAIDO_API_KEY=your-key` |
| `Cannot reach Caido` | Verify Caido is running; check `CAIDO_URL` matches the port in Settings |
| `Unauthorized` | Regenerate the API key in Caido Settings → API Keys |
| `GraphQL errors` | Caido version may have a different schema — open an issue with the error |
| Empty results | Browse the target in Caido first — history only contains captured traffic |
