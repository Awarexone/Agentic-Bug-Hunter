# Burp Suite MCP Integration

Connect Claude Bug Bounty to PortSwigger's official Burp Suite MCP server for live HTTP traffic visibility.

## What You Get

With Burp MCP connected, the tool can:

- **Read proxy history** — every request/response you've made through Burp
- **Filter traffic** — by endpoint, method, status code, content type
- **Send requests** — through Burp with proper auth cookies
- **Generate Collaborator payloads** — for OOB testing (SSRF, XXE, blind injection)
- **Access Scanner findings** — from Burp's active/passive scanner
- **Read/write project state** — Burp project files

## Setup (5 minutes)

### Step 1: Install Burp MCP Server

Download the official MCP server from PortSwigger:

```bash
# Option A: From PortSwigger's releases
# Download burp-mcp-server.jar from https://portswigger.net/burp/releases

# Option B: If available via package manager
# brew install portswigger/tap/burp-mcp-server
```

### Step 2: Enable Burp API

1. Open Burp Suite Professional
2. Go to **Settings → Suite → REST API**
3. Enable the API on port `1337`
4. Copy the API key

### Step 3: Set Environment Variable

```bash
export BURP_API_KEY="your-api-key-here"
```

Add to your `~/.zshrc` or `~/.bashrc` for persistence.

### Step 4: Add to Claude Code Settings

Copy the MCP server config into your Claude Code settings:

```bash
# Edit your Claude Code settings
claude config edit
```

Add the `burp` entry from `config.json` in this directory to your `mcpServers` section.

Alternatively, copy the full config:

```bash
# If you don't have other MCP servers configured:
cp config.json ~/.claude/settings.json
```

### Step 5: Verify Connection

Start Burp Suite, then in Claude Code:

```
/hunt target.com
```

If Burp MCP is connected, you'll see: "I see you've been browsing target.com. Here's what I notice in the traffic..."

## Without Burp

All commands work without Burp MCP. The tool falls back to:

- `curl` for HTTP requests (you provide auth headers manually)
- Manual request/response pasting for validation
- `webhook.site` or Interactsh for OOB testing instead of Collaborator

## Troubleshooting

| Problem | Fix |
|---|---|
| "Burp MCP not connected" | Check Burp is running with API enabled on port 1337 |
| "Connection refused" | Verify `BURP_API_URL` matches Burp's REST API address |
| "Unauthorized" | Check `BURP_API_KEY` environment variable is set |
| "No proxy history" | Browse the target in Burp first — proxy history is what you've captured |
