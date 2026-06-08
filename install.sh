#!/bin/bash
# Claude Bug Bounty — install skills, commands, and agents for multiple harnesses.

set -euo pipefail

AGENT="${BBHUNT_AGENT:-claude}"
SCOPE="global"
SETUP_BURP="ask"

usage() {
    cat <<'EOF'
Usage: ./install.sh [--agent claude|opencode|pi|codex|agents|all] [--global|--project]

Defaults:
  ./install.sh                 Install for Claude Code globally

Examples:
  ./install.sh --agent opencode Install OpenCode skills + commands globally
  ./install.sh --agent pi       Install Pi skills + prompt templates globally
  ./install.sh --agent agents   Install shared Agent Skills to ~/.agents/skills
  ./install.sh --agent all      Install every supported global target
  ./install.sh --agent opencode --project
                               Install into .opencode/ for this repo

Options:
  --no-burp                    Skip Claude Code Burp MCP setup prompt
  --yes-burp                   Print Claude Code Burp MCP setup instructions
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --agent)
            shift
            AGENT="${1:?--agent requires a value}"
            ;;
        --agent=*)
            AGENT="${1#*=}"
            ;;
        --all)
            AGENT="all"
            ;;
        --global)
            SCOPE="global"
            ;;
        --project)
            SCOPE="project"
            ;;
        --no-burp)
            SETUP_BURP="no"
            ;;
        --yes-burp)
            SETUP_BURP="yes"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

copy_tree_items() {
    local src_glob="$1"
    local dest_dir="$2"
    local label="$3"
    local item name

    mkdir -p "$dest_dir"
    for item in $src_glob; do
        [ -e "$item" ] || continue
        name=$(basename "$item")
        rm -rf "$dest_dir/$name"
        mkdir -p "$dest_dir/$name"
        cp -R "$item"/. "$dest_dir/$name/"
        echo "✓ Installed $label: $name"
    done
}

copy_files() {
    local src_glob="$1"
    local dest_dir="$2"
    local label="$3"
    local item name

    mkdir -p "$dest_dir"
    for item in $src_glob; do
        [ -f "$item" ] || continue
        name=$(basename "$item")
        cp "$item" "$dest_dir/$name"
        echo "✓ Installed $label: $name"
    done
}

install_claude() {
    local root
    if [ "$SCOPE" = "project" ]; then
        root=".claude"
    else
        root="$HOME/.claude"
    fi

    echo "Installing Claude Bug Bounty for Claude Code ($SCOPE)..."
    copy_tree_items "skills/*" "$root/skills" "skill"
    copy_files "commands/*.md" "$root/commands" "command"
    copy_files "agents/*.md" "$root/agents" "agent"
    echo "Done: $root"

    if [ "$SETUP_BURP" = "ask" ]; then
        echo ""
        echo "─────────────────────────────────────────────"
        echo "Optional: Burp Suite MCP Integration"
        echo "─────────────────────────────────────────────"
        echo ""
        echo "Connect to PortSwigger's Burp MCP server for live HTTP traffic visibility."
        echo "See mcp/burp-mcp-client/README.md for setup instructions."
        echo ""
        read -r -p "Set up Burp MCP now? (y/N): " setup_burp
        case "$setup_burp" in
            [Yy]*) SETUP_BURP="yes" ;;
            *) SETUP_BURP="no" ;;
        esac
    fi

    if [ "$SETUP_BURP" = "yes" ]; then
        echo ""
        echo "To connect Burp MCP, add this to your Claude Code settings:"
        echo ""
        echo "  claude config edit"
        echo ""
        echo "Then add to the mcpServers section:"
        grep -A 10 '"burp"' mcp/burp-mcp-client/config.json || true
        echo ""
        echo "And set your Burp API key:"
        echo "  export BURP_API_KEY=\"your-api-key-here\""
    fi

    echo ""
    echo "Start hunting:"
    echo "  claude"
    echo "  /recon target.com"
    echo "  /hunt target.com"
}

install_opencode() {
    local root
    if [ "$SCOPE" = "project" ]; then
        root=".opencode"
    else
        root="${OPENCODE_CONFIG_DIR:-$HOME/.config/opencode}"
    fi

    echo "Installing Claude Bug Bounty for OpenCode ($SCOPE)..."
    copy_tree_items "skills/*" "$root/skills" "skill"
    copy_files "commands/*.md" "$root/commands" "command"
    copy_files "agents/*.md" "$root/agents" "agent"
    echo "Done: $root"
    echo ""
    echo "OpenCode also reads AGENTS.md from the project root. Keep this repo's AGENTS.md committed for portable project instructions."
    echo "Start hunting:"
    echo "  opencode"
    echo "  /recon target.com"
}

install_pi() {
    local root
    if [ "$SCOPE" = "project" ]; then
        root=".pi"
    else
        root="$HOME/.pi/agent"
    fi

    echo "Installing Claude Bug Bounty for Pi Agent ($SCOPE)..."
    copy_tree_items "skills/*" "$root/skills" "skill"
    copy_files "commands/*.md" "$root/prompts" "prompt"
    echo "Done: $root"
    echo ""
    echo "Pi exposes skills as /skill:<name> and command prompts as /<command>."
    echo "Start hunting:"
    echo "  pi"
    echo "  /recon target.com"
}

install_codex() {
    local root
    if [ "$SCOPE" = "project" ]; then
        root=".codex"
    else
        root="${CODEX_HOME:-$HOME/.codex}"
    fi

    echo "Installing Claude Bug Bounty for Codex-style Agent Skills ($SCOPE)..."
    copy_tree_items "skills/*" "$root/skills" "skill"
    copy_files "commands/*.md" "$root/commands" "command"
    echo "Done: $root"
}

install_agents() {
    local root
    if [ "$SCOPE" = "project" ]; then
        root=".agents"
    else
        root="$HOME/.agents"
    fi

    echo "Installing shared Agent Skills ($SCOPE)..."
    copy_tree_items "skills/*" "$root/skills" "skill"
    echo "Done: $root"
    echo "OpenCode and Pi both discover .agents/skills or ~/.agents/skills."
}

case "$AGENT" in
    claude)
        install_claude
        ;;
    opencode)
        SETUP_BURP="no"
        install_opencode
        ;;
    pi)
        SETUP_BURP="no"
        install_pi
        ;;
    codex)
        SETUP_BURP="no"
        install_codex
        ;;
    agents|generic)
        SETUP_BURP="no"
        install_agents
        ;;
    all)
        SETUP_BURP="no"
        install_claude
        install_opencode
        install_pi
        install_codex
        install_agents
        ;;
    *)
        echo "Unsupported agent: $AGENT" >&2
        usage >&2
        exit 2
        ;;
esac
