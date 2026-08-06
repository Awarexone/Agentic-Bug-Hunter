#!/bin/bash
# BugHunter — remove installed skills, commands, agents, and standalone launcher.

set -euo pipefail

AGENT="${BBHUNT_AGENT:-claude}"
SCOPE="global"
ASSUME_YES="no"
PURGE_CONFIG="no"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<'EOF'
Usage: ./uninstall.sh [--agent claude|opencode|pi|codex|agents|standalone|all] [--global|--project] [options]

Examples:
  ./uninstall.sh --agent standalone
  ./uninstall.sh --agent codex --global
  ./uninstall.sh --agent all --yes
  ./uninstall.sh --agent standalone --purge-config

Options:
  --global          Remove global installation (default)
  --project         Remove project-local installation
  --purge-config    Also remove ~/.bughunter/config.json
  -y, --yes         Skip confirmation
  -h, --help        Show this help

The BugHunter configuration is preserved unless --purge-config is supplied.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --agent)
            shift
            AGENT="${1:?--agent requires a value}"
            ;;
        --agent=*) AGENT="${1#*=}" ;;
        --all) AGENT="all" ;;
        --claude) AGENT="claude" ;;
        --opencode) AGENT="opencode" ;;
        --both) AGENT="claude-opencode" ;;
        --global) SCOPE="global" ;;
        --project) SCOPE="project" ;;
        --purge-config) PURGE_CONFIG="yes" ;;
        -y|--yes) ASSUME_YES="yes" ;;
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

case "$AGENT" in
    claude|opencode|claude-opencode|pi|codex|agents|generic|standalone|engine|all) ;;
    *)
        echo "Unsupported agent: $AGENT" >&2
        usage >&2
        exit 2
        ;;
esac

if [ "$SCOPE" = "project" ] && [[ "$AGENT" == "standalone" || "$AGENT" == "engine" ]]; then
    echo "Standalone BugHunter is a global command; --project is not applicable." >&2
    exit 2
fi

if [ "$ASSUME_YES" != "yes" ]; then
    echo "This will uninstall BugHunter components for: $AGENT ($SCOPE)."
    if [ "$PURGE_CONFIG" = "yes" ]; then
        echo "The saved provider/model configuration will also be removed."
    else
        echo "The saved provider/model configuration will be preserved."
    fi
    read -r -p "Continue? (y/N): " answer
    case "$answer" in
        [Yy]|[Yy][Ee][Ss]) ;;
        *) echo "Cancelled."; exit 0 ;;
    esac
fi

removed=0

remove_path() {
    local path="$1"
    local label="$2"
    if [ -e "$path" ] || [ -L "$path" ]; then
        rm -rf -- "$path"
        echo "✓ Removed $label: $path"
        removed=$((removed + 1))
    fi
}

remove_tree_items() {
    local src_glob="$1"
    local dest_dir="$2"
    local label="$3"
    local item name
    for item in $src_glob; do
        [ -e "$item" ] || continue
        name="$(basename "$item")"
        remove_path "$dest_dir/$name" "$label"
    done
}

remove_files() {
    local src_glob="$1"
    local dest_dir="$2"
    local label="$3"
    local item name
    for item in $src_glob; do
        [ -f "$item" ] || continue
        name="$(basename "$item")"
        remove_path "$dest_dir/$name" "$label"
    done
}

uninstall_claude() {
    local root="${1:-}"
    if [ -z "$root" ]; then
        if [ "$SCOPE" = "project" ]; then root="$SCRIPT_DIR/.claude"; else root="$HOME/.claude"; fi
    fi
    remove_tree_items "$SCRIPT_DIR/skills/*" "$root/skills" "Claude skill"
    remove_files "$SCRIPT_DIR/commands/*.md" "$root/commands" "Claude command"
    remove_files "$SCRIPT_DIR/agents/*.md" "$root/agents" "Claude agent"
}

uninstall_opencode() {
    local root
    if [ "$SCOPE" = "project" ]; then
        root="$SCRIPT_DIR/.opencode"
    else
        root="${OPENCODE_CONFIG_DIR:-$HOME/.config/opencode}"
    fi
    remove_tree_items "$SCRIPT_DIR/skills/*" "$root/skills" "OpenCode skill"
    remove_files "$SCRIPT_DIR/commands/*.md" "$root/commands" "OpenCode command"
    remove_files "$SCRIPT_DIR/agents/*.md" "$root/agents" "OpenCode agent"
}

uninstall_pi() {
    local root
    if [ "$SCOPE" = "project" ]; then root="$SCRIPT_DIR/.pi"; else root="$HOME/.pi/agent"; fi
    remove_tree_items "$SCRIPT_DIR/skills/*" "$root/skills" "Pi skill"
    remove_files "$SCRIPT_DIR/commands/*.md" "$root/prompts" "Pi prompt"
}

uninstall_codex() {
    local root
    if [ "$SCOPE" = "project" ]; then root="$SCRIPT_DIR/.codex"; else root="${CODEX_HOME:-$HOME/.codex}"; fi
    remove_tree_items "$SCRIPT_DIR/skills/*" "$root/skills" "Codex skill"
    remove_files "$SCRIPT_DIR/commands/*.md" "$root/commands" "Codex command"
}

uninstall_agents() {
    local root
    if [ "$SCOPE" = "project" ]; then root="$SCRIPT_DIR/.agents"; else root="$HOME/.agents"; fi
    remove_tree_items "$SCRIPT_DIR/skills/*" "$root/skills" "shared skill"
}

is_managed_bughunter() {
    local path="$1"
    if [ -L "$path" ]; then
        [ "$(basename "$(readlink "$path")")" = "engine.py" ]
    elif [ -f "$path" ]; then
        grep -q "Standalone BugHunter CLI" "$path" 2>/dev/null
    else
        return 1
    fi
}

remove_standalone_path() {
    local target="$1"
    local -a remove_cmd=()
    [ -e "$target" ] || [ -L "$target" ] || return 0

    if ! is_managed_bughunter "$target"; then
        echo "! Preserved unrelated command: $target"
        return 0
    fi

    if [ ! -w "$(dirname "$target")" ]; then
        if command -v sudo >/dev/null 2>&1 && [[ "$target" == /usr/local/* ]]; then
            remove_cmd=(sudo)
        else
            echo "! Cannot remove $target (directory is not writable)" >&2
            return 1
        fi
    fi

    "${remove_cmd[@]}" rm -f -- "$target"
    echo "✓ Removed standalone command: $target"
    removed=$((removed + 1))
}

uninstall_standalone() {
    local active candidate
    local -a candidates=()
    if [ -n "${BBHUNTER_BIN_DIR:-}" ]; then
        # Explicit override is intentionally exclusive, which also makes
        # packaging/integration tests unable to touch a real installation.
        candidates+=("$BBHUNTER_BIN_DIR/bughunter")
    else
        active="$(command -v bughunter 2>/dev/null || true)"
        [ -n "$active" ] && candidates+=("$active")
        candidates+=("/usr/local/bin/bughunter" "$HOME/.local/bin/bughunter")
    fi

    for candidate in "${candidates[@]}"; do
        # Skip duplicate paths without requiring associative arrays (bash 3.2).
        case " ${seen_standalone_paths:-} " in
            *" $candidate "*) continue ;;
        esac
        seen_standalone_paths="${seen_standalone_paths:-} $candidate"
        remove_standalone_path "$candidate"
    done
}

case "$AGENT" in
    claude) uninstall_claude ;;
    opencode) uninstall_opencode ;;
    claude-opencode) uninstall_claude; uninstall_opencode ;;
    pi) uninstall_pi ;;
    codex) uninstall_codex ;;
    agents|generic) uninstall_agents ;;
    standalone|engine) uninstall_standalone ;;
    all)
        uninstall_claude
        uninstall_opencode
        uninstall_pi
        uninstall_codex
        uninstall_agents
        uninstall_standalone
        ;;
esac

if [ "$PURGE_CONFIG" = "yes" ]; then
    remove_path "$HOME/.bughunter/config.json" "BugHunter configuration"
    if [ -d "$HOME/.bughunter" ] && [ -z "$(find "$HOME/.bughunter" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
        rmdir "$HOME/.bughunter"
    fi
else
    echo "Preserved configuration: $HOME/.bughunter/config.json"
fi

if [ "$removed" -eq 0 ]; then
    echo "No managed BugHunter installation found for the selected target."
else
    echo "Done. Removed $removed managed item(s)."
fi
