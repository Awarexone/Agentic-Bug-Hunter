#!/bin/bash
# Bug Bounty Hunter — uninstall skills/commands for Claude Code or OpenCode

set -e

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
detect_mode() {
    if command -v claude >/dev/null 2>&1; then
        echo "claude"
    elif command -v opencode >/dev/null 2>&1; then
        echo "opencode"
    else
        echo "claude"
    fi
}

removed=0
skipped=0

remove_file() {
    local path="$1"
    if [ -e "$path" ] || [ -L "$path" ]; then
        rm -rf "$path"
        echo "✓ Removed: $path"
        removed=$((removed + 1))
    else
        echo "  (not found, skipping): $path"
        skipped=$((skipped + 1))
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Mode selection
# ─────────────────────────────────────────────────────────────────────────────
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

# ─────────────────────────────────────────────────────────────────────────────
# Claude Code uninstall
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$MODE" == "claude" ]] || [[ "$MODE" == "both" ]]; then
    echo "Uninstalling from Claude Code..."
    echo ""

    INSTALL_DIR="${HOME}/.claude/skills"
    COMMANDS_DIR="${HOME}/.claude/commands"

    # Remove installed skills
    for skill_dir in "${REPO_ROOT}/skills/"*/; do
        skill_name=$(basename "$skill_dir")
        remove_file "${INSTALL_DIR}/${skill_name}"
    done

    # Remove installed commands
    for cmd_file in "${REPO_ROOT}/commands/"*.md; do
        cmd_name=$(basename "$cmd_file")
        remove_file "${COMMANDS_DIR}/${cmd_name}"
    done

    # Clean up empty parent dirs (only if we created them and they're now empty)
    for dir in "${INSTALL_DIR}" "${COMMANDS_DIR}"; do
        if [ -d "$dir" ] && [ -z "$(ls -A "$dir")" ]; then
            rmdir "$dir"
            echo "  (removed empty dir): $dir"
        fi
    done

    echo ""
    echo "✓ Claude Code uninstall complete."
    echo ""
fi

# ─────────────────────────────────────────────────────────────────────────────
# OpenCode uninstall
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$MODE" == "opencode" ]] || [[ "$MODE" == "both" ]]; then
    echo "Uninstalling from OpenCode..."
    echo ""

    SKILLS_DIR="${REPO_ROOT}/.opencode/skills"
    COMMANDS_DIR="${REPO_ROOT}/.opencode/commands"

    # Remove symlinked skills
    for skill_dir in "${REPO_ROOT}/skills/"*/; do
        skill_name=$(basename "$skill_dir")
        remove_file "${SKILLS_DIR}/${skill_name}"
    done

    # Remove copied commands
    for cmd_file in "${REPO_ROOT}/commands/"*.md; do
        cmd_name=$(basename "$cmd_file")
        remove_file "${COMMANDS_DIR}/${cmd_name}"
    done

    # Clean up empty parent dirs
    for dir in "${SKILLS_DIR}" "${COMMANDS_DIR}"; do
        if [ -d "$dir" ] && [ -z "$(ls -A "$dir")" ]; then
            rmdir "$dir"
            echo "  (removed empty dir): $dir"
        fi
    done

    # Remove MCP entries from opencode.json
    OPENCODE_JSON="${REPO_ROOT}/opencode.json"
    if [ -f "$OPENCODE_JSON" ]; then
        python3 - "$OPENCODE_JSON" <<'PYEOF'
import json, os, sys

path = sys.argv[1]
try:
    with open(path) as f:
        config = json.load(f)
except (json.JSONDecodeError, FileNotFoundError):
    sys.exit(0)

mcp = config.get("mcp", {})
known = {"burp", "caido", "hackerone"}
removed = [k for k in list(mcp) if k in known]
for k in removed:
    del mcp[k]

if removed:
    if not mcp:
        config.pop("mcp", None)
    # Remove $schema if config is now empty (just the schema key)
    if set(config.keys()) <= {"$schema"}:
        config.pop("$schema", None)
    with open(path, "w") as f:
        if config:
            json.dump(config, f, indent=2)
            f.write("\n")
        # If config is empty, remove the file entirely
    if not config:
        os.remove(path)
        print("✓ opencode.json removed (was empty)")
    else:
        print("✓ Removed MCP entries from opencode.json:", ", ".join(removed))
else:
    print("  (no managed MCP entries found in opencode.json)")
PYEOF
        removed=$((removed + 1))
    else
        echo "  (not found, skipping): ${OPENCODE_JSON}"
        skipped=$((skipped + 1))
    fi

    echo ""
    echo "✓ OpenCode uninstall complete."
    echo ""
fi

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo "─────────────────────────────────────────────"
echo "Summary: ${removed} item(s) removed, ${skipped} already absent."
echo "─────────────────────────────────────────────"
echo ""
echo "Your recon/, memory/, tools/, and wordlists/ directories are untouched."
echo "To reinstall at any time: ./install.sh"
echo ""
