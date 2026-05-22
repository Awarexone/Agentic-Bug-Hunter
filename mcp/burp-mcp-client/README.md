# Burp Suite MCP Integration

Connect Claude Bug Bounty to Burp Suite via PortSwigger's official [MCP Server extension](https://github.com/PortSwigger/mcp-server).

## How It Works

Burp Suite runs the MCP Server extension, which exposes an **SSE server** at `http://127.0.0.1:9876`. Since most MCP clients (Claude Code, OpenCode) only support stdio, a **Java proxy jar** (bundled with the extension) bridges the two.

```
OpenCode/Claude ←stdio→ mcp-proxy-all.jar ←SSE→ Burp Suite :9876
```

No API key needed — the proxy connects locally to Burp.

## What You Get

With Burp MCP connected, the tool can:

- **Read proxy history** — every request/response captured through Burp
- **Filter traffic** — by host, method, status code, content type
- **Send/replay requests** — through Burp with proper auth cookies
- **Generate Collaborator payloads** — for OOB testing (SSRF, XXE, blind injection)
- **Access Scanner findings** — from Burp's active/passive scanner

## Setup (5 minutes)

### Step 1: Build and install the Burp MCP extension

```bash
git clone https://github.com/PortSwigger/mcp-server.git
cd mcp-server
./gradlew embedProxyJar
# Output: build/libs/burp-mcp-all.jar
```

In Burp Suite: **Extensions → Add → Java → select `burp-mcp-all.jar`**

### Step 2: Extract the proxy jar

In Burp Suite: **MCP tab → Extract proxy jar** — save `mcp-proxy-all.jar` somewhere permanent (e.g. `~/.local/share/burp-mcp/mcp-proxy-all.jar`).

### Step 3: Verify Burp SSE server is running

The extension listens on `http://127.0.0.1:9876` by default. Confirm in the **MCP tab** that the server is enabled.

### Step 4: Configure your MCP client

**Claude Code** — add to `~/.claude/settings.json`:
```json
{
  "mcpServers": {
    "burp": {
      "command": "java",
      "args": ["-jar", "/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
    }
  }
}
```

**OpenCode** — merge into `opencode.json` (project root) or `~/.config/opencode/config.json`:
```json
{
  "mcp": {
    "burp": {
      "type": "local",
      "enabled": true,
      "command": ["java", "-jar", "/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
    }
  }
}
```

See `config.json` (Claude Code) and `opencode-config.json` (OpenCode) in this directory for ready-to-copy snippets.

### Step 5: Verify connection

Start Burp Suite with the extension loaded, then in Claude Code or OpenCode:

```
hunt target.com
```

If Burp MCP is connected, the agent will pull from your proxy history automatically.

## Without Burp

All commands work without Burp MCP. The tool falls back to:

- `curl` for HTTP requests (provide auth headers manually)
- Manual request/response pasting for validation
- `webhook.site` or Interactsh for OOB testing instead of Collaborator

## Troubleshooting

| Problem | Fix |
|---|---|
| "Burp MCP not connected" | Check Burp is running with the extension loaded and SSE server enabled |
| "Connection refused on 9876" | Check the MCP tab in Burp — toggle the server off/on |
| "java not found" | Ensure Java is in your PATH: `java --version` |
| "No proxy history" | Browse the target through Burp first — the MCP server only sees captured traffic |
| Port conflict | Change the port in Burp's MCP tab and update `--sse-url` accordingly |
