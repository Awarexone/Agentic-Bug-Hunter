#!/bin/bash
# =============================================================================
# Bug Bounty Tool Installer
# Installs all required tools via Homebrew and Go
# Usage: ./install_tools.sh [--with-cicd-scanner] [--with-credential-attack]
# =============================================================================

set -euo pipefail

INSTALL_CICD_SCANNER=false
INSTALL_CREDENTIAL_ATTACK=false
for arg in "$@"; do
    case "$arg" in
        --with-cicd-scanner) INSTALL_CICD_SCANNER=true ;;
        --with-credential-attack) INSTALL_CREDENTIAL_ATTACK=true ;;
    esac
done

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

# Ensure Go bin is in PATH early so go install binaries are visible
GOPATH="$(go env GOPATH 2>/dev/null || true)"
GOPATH="${GOPATH:-$HOME/go}"
if [[ ":$PATH:" != *":$GOPATH/bin:"* ]]; then
    export PATH="$PATH:$GOPATH/bin"
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

# sisakulint — GitHub Actions SAST (binary download)
echo ""
echo "[*] Installing sisakulint..."
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    armv6l)  ARCH="armv6" ;;
esac
SISAKULINT_LATEST=$(curl -sI https://github.com/sisaku-security/sisakulint/releases/latest \
    | awk -F'/tag/v' '/[Ll]ocation:/ {print $2; exit}' \
    | tr -d '\r')
SISAKULINT_LATEST="${SISAKULINT_LATEST#v}"
SISAKULINT_CURRENT=""
if command -v sisakulint &>/dev/null; then
    SISAKULINT_CURRENT=$(sisakulint -version 2>&1 | awk '/[0-9]+\.[0-9]+\.[0-9]+/ {print $0; exit}')
fi
if [ -n "$SISAKULINT_CURRENT" ] && [ "$SISAKULINT_CURRENT" = "$SISAKULINT_LATEST" ]; then
    log_ok "sisakulint v${SISAKULINT_CURRENT} already up to date ($(command -v sisakulint))"
elif [ -n "$SISAKULINT_LATEST" ]; then
    [ -n "$SISAKULINT_CURRENT" ] && echo "    Upgrading sisakulint v${SISAKULINT_CURRENT} → v${SISAKULINT_LATEST}..."
    SISAKULINT_URL="https://github.com/sisaku-security/sisakulint/releases/download/v${SISAKULINT_LATEST}/sisakulint_${SISAKULINT_LATEST}_${OS}_${ARCH}.tar.gz"
    echo "    Downloading sisakulint v${SISAKULINT_LATEST} (${OS}/${ARCH})..."
    if curl -sL "$SISAKULINT_URL" -o /tmp/sisakulint.tar.gz && \
       tar -xzf /tmp/sisakulint.tar.gz -C /tmp/ && \
       { mv /tmp/sisakulint /usr/local/bin/sisakulint 2>/dev/null || \
         sudo mv /tmp/sisakulint /usr/local/bin/sisakulint; }; then
        rm -f /tmp/sisakulint.tar.gz
        log_ok "sisakulint v${SISAKULINT_LATEST} installed"
    else
        rm -f /tmp/sisakulint.tar.gz /tmp/sisakulint
        log_err "sisakulint failed to install. Download manually from:"
        log_err "  https://github.com/sisaku-security/sisakulint/releases"
    fi
else
    if command -v sisakulint &>/dev/null; then
        log_warn "Could not fetch latest version — keeping sisakulint v${SISAKULINT_CURRENT}"
    else
        log_err "Could not fetch latest sisakulint version. Download manually from:"
        log_err "  https://github.com/sisaku-security/sisakulint/releases"
    fi
fi

# cicd_scanner — sisakulint wrapper script (optional: --with-cicd-scanner)
if [ "$INSTALL_CICD_SCANNER" = true ]; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    CICD_SCANNER_SRC="$SCRIPT_DIR/tools/cicd_scanner.sh"
    if [ -f "$CICD_SCANNER_SRC" ]; then
        INSTALL_DIR="/usr/local/bin"
        if cp "$CICD_SCANNER_SRC" "$INSTALL_DIR/cicd_scanner" 2>/dev/null || \
           sudo cp "$CICD_SCANNER_SRC" "$INSTALL_DIR/cicd_scanner"; then
            chmod +x "$INSTALL_DIR/cicd_scanner" 2>/dev/null || sudo chmod +x "$INSTALL_DIR/cicd_scanner"
            log_ok "cicd_scanner installed to $INSTALL_DIR/cicd_scanner"
        else
            mkdir -p "$HOME/bin"
            cp "$CICD_SCANNER_SRC" "$HOME/bin/cicd_scanner"
            chmod +x "$HOME/bin/cicd_scanner"
            log_ok "cicd_scanner installed to ~/bin/cicd_scanner"
            if [[ ":$PATH:" != *":$HOME/bin:"* ]]; then
                log_warn "Add ~/bin to your PATH: export PATH=\$HOME/bin:\$PATH"
            fi
        fi
    fi
else
    log_warn "cicd_scanner skipped (use --with-cicd-scanner to install)"
fi

# Credential-attack tools (optional: --with-credential-attack)
# Default off — adds ~500MB and pulls ~8 Python/Go deps.
if [ "$INSTALL_CREDENTIAL_ATTACK" = true ]; then
    echo ""
    echo "[*] Installing credential-attack tools..."

    log_warn "First run may take 10–20 min: brew auto-update + downloads ~500MB."
    log_warn "Output below comes from brew/pipx/go/curl directly — slow lines are normal."

    # --- Homebrew (theHarvester moved here: PyPI package has no CLI entry-point) ---
    BREW_CRED_TOOLS=("hashcat" "theharvester")
    for tool in "${BREW_CRED_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null || command -v "theHarvester" &>/dev/null; then
            log_ok "$tool already installed"
        else
            echo "    [*] Installing $tool via brew..."
            if brew install "$tool"; then
                log_ok "$tool installed"
            else
                log_err "$tool failed to install via brew"
            fi
        fi
    done

    # --- pipx (isolated Python venvs) ---
    if ! command -v pipx &>/dev/null; then
        echo "    [*] Installing pipx via brew..."
        brew install pipx && pipx ensurepath
        log_warn "pipx installed — restart shell or 'source ~/.zshrc' for PATH"
    fi
    PIPX_CRED_TOOLS=("cewler" "cupp" "trevorspray")
    for tool in "${PIPX_CRED_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_ok "$tool already installed"
        else
            echo "    [*] Installing $tool via pipx..."
            if pipx install "$tool"; then
                log_ok "$tool installed"
            else
                log_warn "$tool: pipx install failed — try manually"
            fi
        fi
    done

    # --- Go (kerbrute — not in brew) ---
    if command -v kerbrute &>/dev/null; then
        log_ok "kerbrute already installed"
    else
        echo "    [*] Installing kerbrute via go..."
        if go install github.com/ropnop/kerbrute@latest; then
            log_ok "kerbrute installed"
        else
            log_err "kerbrute failed to install"
        fi
    fi

    # --- Git clone (tools without brew/pip packages) ---
    EXT_DIR="${HOME}/.local/share/bug-bounty/credential-attack"
    mkdir -p "$EXT_DIR"
    GIT_TOOLS=(
        "https://github.com/LandGrey/pydictor.git"
        "https://github.com/urbanadventurer/username-anarchy.git"
        "https://github.com/knavesec/CredMaster.git"
    )
    for repo in "${GIT_TOOLS[@]}"; do
        name=$(basename "$repo" .git)
        if [ -d "$EXT_DIR/$name" ]; then
            echo "    [*] Updating $name (git pull)..."
            if (cd "$EXT_DIR/$name" && git pull --quiet); then
                log_ok "$name updated at $EXT_DIR/$name"
            else
                log_warn "$name: git pull failed"
            fi
        else
            echo "    [*] Cloning $name..."
            if git clone --quiet "$repo" "$EXT_DIR/$name"; then
                log_ok "$name cloned to $EXT_DIR/$name"
            else
                log_err "$name: git clone failed"
            fi
        fi
    done

    # --- CrossLinked via pipx (avoids PEP 668 pip3 --user breakage on macOS + Python 3.13) ---
    echo "    [*] Installing CrossLinked via pipx..."
    if _have pipx && pipx install crosslinked --quiet 2>/dev/null; then
        log_ok "CrossLinked installed via pipx"
    elif _have pipx && pipx upgrade crosslinked --quiet 2>/dev/null; then
        log_ok "CrossLinked upgraded via pipx"
    else
        log_warn "CrossLinked pipx install failed — run 'pipx install crosslinked' manually"
    fi

    # --- SecLists hint (not auto-installed; ~750MB) ---
    if [ ! -d "/usr/share/seclists" ] && [ ! -d "$HOME/SecLists" ]; then
        log_warn "SecLists not found. Clone with:"
        log_warn "  git clone https://github.com/danielmiessler/SecLists.git ~/SecLists"
    fi

    # --- Hashcat rules ---
    RULES_DIR="$EXT_DIR/rules"
    mkdir -p "$RULES_DIR"
    if [ -f "$RULES_DIR/OneRuleToRuleThemAll.rule" ]; then
        log_ok "OneRuleToRuleThemAll.rule already present"
    else
        echo "    [*] Downloading OneRuleToRuleThemAll.rule..."
        if curl -fsSL https://raw.githubusercontent.com/NotSoSecure/password_cracking_rules/master/OneRuleToRuleThemAll.rule \
            -o "$RULES_DIR/OneRuleToRuleThemAll.rule"; then
            log_ok "OneRuleToRuleThemAll.rule downloaded to $RULES_DIR"
        else
            log_warn "OneRuleToRuleThemAll.rule download failed"
        fi
    fi
else
    log_warn "credential-attack tools skipped (use --with-credential-attack to install)"
fi

# Update nuclei templates
echo ""
echo "[*] Updating nuclei templates..."
if command -v nuclei &>/dev/null; then
    nuclei -update-templates 2>/dev/null || true
    log_ok "Nuclei templates updated"
fi

# Ensure Go bin is in PATH
if [[ ":$PATH:" != *":$GOPATH/bin:"* ]]; then
    log_warn "Add Go bin to your PATH:"
    echo "    export PATH=\$PATH:$GOPATH/bin"
    echo "    # Add to ~/.zshrc"
fi

# Verification
echo ""
echo "============================================="
echo "[*] Installation Verification"
echo "============================================="

ALL_TOOLS=(subfinder httpx nuclei ffuf nmap amass gau dalfox subjack sisakulint)
if [ "$INSTALL_CREDENTIAL_ATTACK" = true ]; then
    ALL_TOOLS+=(hashcat theHarvester cewler cupp trevorspray kerbrute)
fi
INSTALLED=0
MISSING=0

for tool in "${ALL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log_ok "$tool: $(which "$tool")"
        ((++INSTALLED))
    else
        log_err "$tool: NOT FOUND"
        ((++MISSING))
    fi
 done

echo ""
echo "============================================="
echo "  Installed: $INSTALLED / ${#ALL_TOOLS[@]}"
[ "$MISSING" -gt 0 ] && echo "  Missing: $MISSING (check errors above)"
echo "============================================="
