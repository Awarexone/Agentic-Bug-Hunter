#!/bin/bash
# =============================================================================
# Bug Bounty Tool Installer
# Installs all required tools via Homebrew and Go
# Usage: ./install_tools.sh
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }

echo "============================================="
echo "  Bug Bounty Tool Installer"
echo "============================================="

# Check for Homebrew
if ! command -v brew &>/dev/null; then
    log_warn "Homebrew not found. Installing..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Check for Go (needed for some tools)
if ! command -v go &>/dev/null; then
    log_warn "Go not found. Installing via Homebrew..."
    brew install go
fi

# Tools to install via Homebrew
BREW_TOOLS=(
    "nmap"
    "subfinder"
    "httpx"
    "nuclei"
    "ffuf"
    "amass"
)

echo ""
echo "[*] Installing tools via Homebrew..."
for tool in "${BREW_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log_ok "$tool already installed ($(command -v "$tool"))"
    else
        echo "    Installing $tool..."
        if brew install "$tool" 2>/dev/null; then
            log_ok "$tool installed successfully"
        else
            log_err "$tool failed to install via brew, trying alternative..."
        fi
    fi
done

# Tools to install via Go
echo ""
echo "[*] Installing tools via Go..."

GO_TOOLS=(
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/haccer/subjack@latest"
)

GO_TOOL_NAMES=(
    "gau"
    "dalfox"
    "subjack"
)

for i in "${!GO_TOOLS[@]}"; do
    tool_name="${GO_TOOL_NAMES[$i]}"
    tool_path="${GO_TOOLS[$i]}"
    if command -v "$tool_name" &>/dev/null; then
        log_ok "$tool_name already installed"
    else
        echo "    Installing $tool_name..."
        if go install "$tool_path" 2>/dev/null; then
            log_ok "$tool_name installed successfully"
        else
            log_err "$tool_name failed to install"
        fi
    fi
done

# Update nuclei templates
echo ""
echo "[*] Updating nuclei templates..."
if command -v nuclei &>/dev/null; then
    nuclei -update-templates 2>/dev/null || true
    log_ok "Nuclei templates updated"
fi

# Ensure Go bin is in PATH
GOPATH="${GOPATH:-$HOME/go}"
if [[ ":$PATH:" != *":$GOPATH/bin:"* ]]; then
    log_warn "Add Go bin to your PATH:"
    echo "    export PATH=\$PATH:$GOPATH/bin"
    echo "    # Add to ~/.zshrc for persistence"
fi

# Verification
echo ""
echo "============================================="
echo "[*] Installation Verification"
echo "============================================="

ALL_TOOLS=(subfinder httpx nuclei ffuf nmap amass gau dalfox subjack)
INSTALLED=0
MISSING=0

for tool in "${ALL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log_ok "$tool: $(which "$tool")"
        ((INSTALLED++))
    else
        log_err "$tool: NOT FOUND"
        ((MISSING++))
    fi
done

echo ""
echo "============================================="
echo "  Installed: $INSTALLED / ${#ALL_TOOLS[@]}"
[ "$MISSING" -gt 0 ] && echo "  Missing: $MISSING (check errors above)"
echo "============================================="
