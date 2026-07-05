#!/bin/bash
# =============================================================================
# Bug Bounty Tool Uninstaller
# Removes all tools that install_tools.sh installed
# Usage: ./uninstall_tools.sh [--yes] [--with-templates]
#
#   --yes              Skip the confirmation prompt
#   --with-templates   Also remove nuclei templates (skipped by default)
# =============================================================================

set -euo pipefail

SKIP_CONFIRM=false
REMOVE_TEMPLATES=false
for arg in "$@"; do
    case "$arg" in
        --yes|-y)           SKIP_CONFIRM=true ;;
        --with-templates)   REMOVE_TEMPLATES=true ;;
    esac
done

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }

removed=0
skipped=0
failed=0

# Remove a file or symlink, trying sudo if needed
remove_path() {
    local path="$1"
    if [ -e "$path" ] || [ -L "$path" ]; then
        if rm -f "$path" 2>/dev/null || sudo rm -f "$path" 2>/dev/null; then
            log_ok "Removed: $path"
            removed=$((removed + 1))
        else
            log_err "Failed to remove: $path"
            failed=$((failed + 1))
        fi
    else
        echo "  (not found): $path"
        skipped=$((skipped + 1))
    fi
}

BREW_TOOLS=(nmap subfinder httpx nuclei ffuf amass)
GO_TOOL_NAMES=(gau dalfox subjack)
GOPATH="${GOPATH:-$HOME/go}"

# ─────────────────────────────────────────────────────────────────────────────
echo "============================================="
echo "  Bug Bounty Tool Uninstaller"
echo "============================================="
echo ""
echo "The following will be removed:"
echo ""
echo "  Homebrew : ${BREW_TOOLS[*]}"
echo "  Go bins  : ${GO_TOOL_NAMES[*]}   (from $GOPATH/bin/)"
echo "  Binaries : sisakulint, cicd_scanner"
if [ "$REMOVE_TEMPLATES" = true ]; then
    echo "  Templates: nuclei templates"
else
    log_warn "Nuclei templates will NOT be removed (pass --with-templates to include)"
fi
echo ""

if [ "$SKIP_CONFIRM" = false ]; then
    read -p "Continue? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
    echo ""
fi

# ─────────────────────────────────────────────────────────────────────────────
# Homebrew tools
# ─────────────────────────────────────────────────────────────────────────────
echo "[*] Removing Homebrew tools..."
if ! command -v brew &>/dev/null; then
    log_warn "Homebrew not found — skipping brew removals"
    skipped=$((skipped + ${#BREW_TOOLS[@]}))
else
    for tool in "${BREW_TOOLS[@]}"; do
        if brew list --formula "$tool" &>/dev/null 2>&1; then
            if brew uninstall --ignore-dependencies "$tool" 2>/dev/null; then
                log_ok "$tool uninstalled"
                removed=$((removed + 1))
            else
                log_err "$tool failed to uninstall (may be a dependency of another formula)"
                failed=$((failed + 1))
            fi
        else
            echo "  (not installed via brew): $tool"
            skipped=$((skipped + 1))
        fi
    done
fi

# ─────────────────────────────────────────────────────────────────────────────
# Go tool binaries
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "[*] Removing Go tool binaries..."
for tool in "${GO_TOOL_NAMES[@]}"; do
    remove_path "$GOPATH/bin/$tool"
done

# ─────────────────────────────────────────────────────────────────────────────
# sisakulint — binary download
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "[*] Removing sisakulint..."
remove_path "/usr/local/bin/sisakulint"

# ─────────────────────────────────────────────────────────────────────────────
# cicd_scanner — both possible install locations
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "[*] Removing cicd_scanner..."
remove_path "/usr/local/bin/cicd_scanner"
remove_path "$HOME/bin/cicd_scanner"

# ─────────────────────────────────────────────────────────────────────────────
# Nuclei templates (opt-in via --with-templates)
# ─────────────────────────────────────────────────────────────────────────────
echo ""
if [ "$REMOVE_TEMPLATES" = true ]; then
    echo "[*] Removing nuclei templates..."
    # nuclei writes templates to ~/nuclei-templates by default
    NUCLEI_TEMPLATES_DIR="$HOME/nuclei-templates"
    if [ -d "$NUCLEI_TEMPLATES_DIR" ]; then
        rm -rf "$NUCLEI_TEMPLATES_DIR"
        log_ok "Removed nuclei templates: $NUCLEI_TEMPLATES_DIR"
        removed=$((removed + 1))
    else
        echo "  (not found): $NUCLEI_TEMPLATES_DIR"
        skipped=$((skipped + 1))
    fi
else
    log_warn "Nuclei templates kept. To remove: rm -rf ~/nuclei-templates"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Verification pass — confirm nothing remains
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "============================================="
echo "[*] Verification"
echo "============================================="

ALL_TOOLS=(subfinder httpx nuclei ffuf nmap amass gau dalfox subjack sisakulint)
STILL_PRESENT=0

for tool in "${ALL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log_warn "$tool still present at: $(which "$tool")"
        STILL_PRESENT=$((STILL_PRESENT + 1))
    else
        log_ok "$tool: removed"
    fi
done

if [ "$STILL_PRESENT" -gt 0 ]; then
    echo ""
    log_warn "$STILL_PRESENT tool(s) still present — they may have been installed"
    log_warn "outside of install_tools.sh (e.g. system package manager, manual)."
fi

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "============================================="
echo "  Removed : $removed"
echo "  Skipped : $skipped (not found / not installed)"
[ "$failed" -gt 0 ] && echo "  Failed  : $failed (check errors above)"
echo "============================================="
echo ""
echo "Your recon/, memory/, and tools/ source files are untouched."
echo "To reinstall at any time: ./install_tools.sh"
echo ""
