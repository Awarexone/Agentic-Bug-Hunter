# Caido MCP Integration

Connect Claude Bug Bounty to [Caido](https://caido.io) — the lightweight web security auditing toolkit — via the community [`caido-mcp-server`](https://github.com/c0tton-fluff/caido-mcp-server).

Caido is a Burp Suite alternative built in Rust. If you already use Caido as your daily proxy, this integration gives the hunting agent live visibility into your traffic the same way the Burp MCP client does.

## What You Get

With Caido MCP connected, the tool can:

- **Read proxy history** — every request/response captured by Caido
- **Send requests via Replay** — get status, headers, body returned inline
- **Send requests in parallel** — up to 50 per batch (BAC sweeps, parameter fuzzing, endpoint sweeps)
- **Access fuzzing sessions, results, and payloads**
- **Search/filter traffic** — by host, method, status, content type
- **Read project state** — projects, scopes, sitemaps

The MCP server auto-redacts `Authorization`, `Cookie`, `Set-Cookie`, and API-key headers from anything it returns to the model, so credentials don't leak into the LLM context.

## Setup (5 minutes)

### Step 1: Install the Caido MCP server

```bash
curl -fsSL https://raw.githubusercontent.com/c0tton-fluff/caido-mcp-server/main/install.sh | bash
```

Or build from source — see the [project README](https://github.com/c0tton-fluff/caido-mcp-server).

### Step 2: Generate a Personal Access Token in Caido

1. Open Caido (desktop or CLI build)
2. Go to **Settings → Developer → Personal Access Tokens**
3. Create a new token and copy it

### Step 3: Set environment variables

```bash
export CAIDO_URL="http://127.0.0.1:8080"
export CAIDO_PAT="your-personal-access-token"
```

Add to your `~/.zshrc` or `~/.bashrc` for persistence.

> Prefer OAuth? Run `CAIDO_URL=http://localhost:8080 caido-mcp-server login` once — the token is cached at `~/.caido-mcp/token.json` and you can drop the `CAIDO_PAT` env var.

### Step 4: Add to Claude Code settings

Copy the `caido` entry from `config.json` in this directory into your `~/.claude/settings.json` under `mcpServers`. If you have no other MCP servers configured:

```bash
cp config.json ~/.claude/settings.json
```

### Step 5: Verify connection

Start Caido, then in Claude Code:

```
/hunt target.com
```

If Caido MCP is connected, the agent will pull from your proxy history and reference traffic you've already captured.

## Burp + Caido side-by-side

You can run both MCP servers at the same time. The hunting agent will use whichever has traffic for the current target. Most users pick one — leave the other entry out of `mcpServers` to avoid duplicate tool surfaces.

## Without Caido

All commands work without the Caido MCP. The tool falls back to:

- `curl` for HTTP requests (you provide auth headers manually)
- Manual request/response pasting for validation
- `webhook.site` or Interactsh for OOB testing

## Troubleshooting

| Problem | Fix |
|---|---|
| "Caido MCP not connected" | Check Caido is running and `CAIDO_URL` is reachable (`curl $CAIDO_URL/health`) |
| "Unauthorized" | Verify `CAIDO_PAT` is set and not expired, or re-run `caido-mcp-server login` |
| "No proxy history" | Browse the target through Caido first — proxy history is what you've captured |
| "Too many requests" | The MCP server caps parallel batches at 50; reduce batch size in your prompt |
