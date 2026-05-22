#!/bin/bash
# Bug Bounty Hunter — install skills for Claude Code or OpenCode

set -e

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

# Detect which AI assistant to install for
detect_mode() {
    if command -v claude >/dev/null 2>&1; then
        echo "claude"
    elif command -v opencode >/dev/null 2>&1; then
        echo "opencode"
    else
        echo "claude"
    fi
}

MODE="${1}"
case "$MODE" in
    --claude)
        MODE="claude"
        ;;
    --opencode)
        MODE="opencode"
        ;;
    --both)
        MODE="both"
        ;;
    *)
        MODE=$(detect_mode)
        echo "Auto-detected mode: $MODE"
        echo ""
        ;;
esac

# Claude Code installation
if [[ "$MODE" == "claude" ]] || [[ "$MODE" == "both" ]]; then
    echo "Installing for Claude Code..."
    echo ""

    INSTALL_DIR="${HOME}/.claude/skills"
    mkdir -p "${INSTALL_DIR}"

    # Copy skills
    for skill_dir in "${REPO_ROOT}/skills/"*/; do
        skill_name=$(basename "$skill_dir")
        mkdir -p "${INSTALL_DIR}/${skill_name}"
        cp "${skill_dir}SKILL.md" "${INSTALL_DIR}/${skill_name}/SKILL.md"
        echo "✓ Installed skill: ${skill_name}"
    done

    # Copy commands
    COMMANDS_DIR="${HOME}/.claude/commands"
    mkdir -p "${COMMANDS_DIR}"

    for cmd_file in "${REPO_ROOT}/commands/"*.md; do
        cmd_name=$(basename "$cmd_file")
        cp "$cmd_file" "${COMMANDS_DIR}/${cmd_name}"
        echo "✓ Installed command: ${cmd_name}"
    done

    echo ""
    echo "✓ Claude Code installation complete!"
    echo "  Skills: ${INSTALL_DIR}"
    echo "  Commands: ${COMMANDS_DIR}"
    echo ""

    # Offer Burp MCP setup
    echo "─────────────────────────────────────────────"
    echo "Optional: Burp Suite MCP Integration"
    echo "─────────────────────────────────────────────"
    echo ""
    echo "Connect to PortSwigger's Burp MCP server for live HTTP traffic visibility."
    echo "See mcp/burp-mcp-client/README.md for setup instructions."
    echo ""
    read -p "Set up Burp MCP now? (y/N): " setup_burp
    if [[ "$setup_burp" =~ ^[Yy]$ ]]; then
        echo ""
        echo "To connect Burp MCP, add this to your Claude Code settings:"
        echo ""
        echo "  claude config edit"
        echo ""
        echo "Then add to the mcpServers section:"
        echo '    "burp": {'
        echo '      "command": "java",'
        echo '      "args": ["-jar", "/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]'
        echo '    }'
        echo ""
        echo "Replace /path/to/mcp-proxy-all.jar with the jar extracted from:"
        echo "  Burp Suite > Extensions > MCP tab > Extract proxy jar"
        echo ""
        echo "See mcp/burp-mcp-client/README.md for full setup instructions."
        echo ""
    fi

    echo "Start hunting:"
    echo "  claude"
    echo "  /recon target.com"
    echo "  /hunt target.com"
    echo ""
fi

# OpenCode installation
if [[ "$MODE" == "opencode" ]] || [[ "$MODE" == "both" ]]; then
    echo "Installing for OpenCode..."
    echo ""

    SKILLS_DIR="${REPO_ROOT}/.opencode/skills"
    COMMANDS_DIR="${REPO_ROOT}/.opencode/commands"
    mkdir -p "${SKILLS_DIR}"
    mkdir -p "${COMMANDS_DIR}"

    # Symlink domain skills
    for skill_dir in "${REPO_ROOT}/skills/"*/; do
        skill_name=$(basename "$skill_dir")
        rm -rf "${SKILLS_DIR}/${skill_name}"
        ln -s "../../skills/${skill_name}" "${SKILLS_DIR}/${skill_name}"
        echo "✓ Linked skill: ${skill_name}"
    done

    # Copy commands to .opencode/commands/
    for cmd_file in "${REPO_ROOT}/commands/"*.md; do
        cmd_name=$(basename "$cmd_file")
        cp "$cmd_file" "${COMMANDS_DIR}/${cmd_name}"
        echo "✓ Copied command: ${cmd_name}"
    done

    echo ""
    echo "✓ OpenCode installation complete!"
    echo "  Skills: ${SKILLS_DIR}"
    echo "  Commands: ${COMMANDS_DIR}"
    echo ""

    # ── MCP setup ────────────────────────────────────────────────────────
    echo "─────────────────────────────────────────────"
    echo "Optional: MCP Server Integration"
    echo "─────────────────────────────────────────────"
    echo ""
    echo "MCP servers give OpenCode live proxy traffic visibility."
    echo "Config will be written to: ${REPO_ROOT}/opencode.json"
    echo ""

    read -p "Add Burp Suite MCP? (y/N): " add_burp
    read -p "Add Caido MCP?       (y/N): " add_caido
    read -p "Add HackerOne MCP?   (y/N): " add_h1

    if [[ "$add_burp" =~ ^[Yy]$ ]] || [[ "$add_caido" =~ ^[Yy]$ ]] || [[ "$add_h1" =~ ^[Yy]$ ]]; then
        python3 - "${REPO_ROOT}/opencode.json" "$add_burp" "$add_caido" "$add_h1" <<'PYEOF'
import json, os, sys

config_path = sys.argv[1]
add_burp  = sys.argv[2].lower() in ("y", "yes")
add_caido = sys.argv[3].lower() in ("y", "yes")
add_h1    = sys.argv[4].lower() in ("y", "yes")

existing = {}
if os.path.exists(config_path):
    with open(config_path) as f:
        try:
            existing = json.load(f)
        except json.JSONDecodeError:
            existing = {}

existing.setdefault("$schema", "https://opencode.ai/config.json")
mcp = existing.setdefault("mcp", {})

if add_burp:
    mcp["burp"] = {
        "type": "local",
        "command": ["java", "-jar", "/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"],
        "enabled": True
    }

if add_caido:
    mcp["caido"] = {
        "type": "local",
        "command": ["npx", "-y", "@caido/mcp-server"],
        "enabled": True,
        "environment": {
            "CAIDO_API_KEY": "{env:CAIDO_API_KEY}",
            "CAIDO_URL":     "{env:CAIDO_URL}"
        }
    }

if add_h1:
    mcp["hackerone"] = {
        "type": "local",
        "command": ["python3", "mcp/hackerone-mcp/server.py"],
        "enabled": True
    }

with open(config_path, "w") as f:
    json.dump(existing, f, indent=2)
    f.write("\n")

print("✓ opencode.json written:", config_path)
PYEOF

        if [[ "$add_burp" =~ ^[Yy]$ ]]; then
            echo ""
            echo "  Burp — replace /path/to/mcp-proxy-all.jar in opencode.json with the jar"
            echo "  extracted from: Burp Suite > Extensions > MCP tab > Extract proxy jar"
        fi
        if [[ "$add_caido" =~ ^[Yy]$ ]]; then
            echo ""
            echo "  Caido — set your credentials:"
            echo "    export CAIDO_API_KEY=\"your-personal-access-token\""
            echo "    export CAIDO_URL=\"http://127.0.0.1:8080\""
        fi
        if [[ "$add_h1" =~ ^[Yy]$ ]]; then
            echo ""
            echo "  HackerOne MCP: public API only — no key needed."
        fi
        echo ""
        echo "  See mcp/*/README.md for full setup details."
    fi

    echo ""
    echo "Next steps:"
    echo "  1. Open this project in OpenCode"
    echo "  2. The plugin will auto-load from .opencode/"
    echo "  3. See OPENCODE.md for usage"
    echo ""
    echo "Start hunting:"
    echo "  opencode"
    echo "  > recon target.com"
    echo "  > hunt target.com"
    echo ""
fi
