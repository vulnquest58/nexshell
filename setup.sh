#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════╗
# ║  NexShell — Elite Reverse Shell Commander               ║
# ║  Setup Script                                           ║
# ║  Author: vulnquest58                                    ║
# ╚══════════════════════════════════════════════════════════╝

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

INSTALL_DIR="/usr/local/bin"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$INSTALL_DIR/nexshell"
MODULES_DEST="$INSTALL_DIR/.nexshell_modules"

banner() {
    echo -e "${PURPLE}"
    echo '   ███╗   ██╗███████╗██╗  ██╗███████╗██╗  ██╗███████╗██╗     ██╗'
    echo '   ████╗  ██║██╔════╝╚██╗██╔╝██╔════╝██║  ██║██╔════╝██║     ██║'
    echo '   ██╔██╗ ██║█████╗   ╚███╔╝ ███████╗███████║█████╗  ██║     ██║'
    echo '   ██║╚██╗██║██╔══╝   ██╔██╗ ╚════██║██╔══██║██╔══╝  ██║     ██║'
    echo '   ██║ ╚████║███████╗██╔╝ ██╗███████║██║  ██║███████╗███████╗███████╗'
    echo "   ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝"
    echo -e "${CYAN}              Nexus of Shell Operations  ·  Elite Reverse Shell Commander${NC}"
    echo ""
}

info()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[-]${NC} $1"; exit 1; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }

# ── Detect OS ────────────────────────────────────────────────────────────────
detect_os() {
    case "$(uname -s)" in
        Linux*)   echo "linux"  ;;
        Darwin*)  echo "macos"  ;;
        CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
        FreeBSD*) echo "bsd"    ;;
        *)        echo "unknown" ;;
    esac
}

# ── Check Python ─────────────────────────────────────────────────────────────
check_python() {
    if command -v python3 &>/dev/null; then
        PYTHON=$(command -v python3)
        VER=$($PYTHON -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        MAJOR=$(echo $VER | cut -d. -f1)
        MINOR=$(echo $VER | cut -d. -f2)
        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 6 ]; then
            success "Python $VER found at $PYTHON"
            return 0
        fi
    fi
    error "Python 3.6+ required. Please install it first."
}

# ── Install (Linux/macOS) ─────────────────────────────────────────────────────
install_unix() {
    info "Installing NexShell to $INSTALL_DIR..."

    # Check write permissions
    if [ ! -w "$INSTALL_DIR" ]; then
        warn "Need sudo to write to $INSTALL_DIR"
        SUDO="sudo"
    else
        SUDO=""
    fi

    # Copy modules directory
    $SUDO mkdir -p "$MODULES_DEST"
    $SUDO cp -r "$REPO_DIR/modules/" "$MODULES_DEST/"
    $SUDO cp -r "$REPO_DIR/payloads/" "$MODULES_DEST/" 2>/dev/null || true

    # Create wrapper script
    $SUDO tee "$BINARY" > /dev/null << EOF
#!/usr/bin/env bash
# NexShell wrapper
cd "$MODULES_DEST"
exec python3 "$MODULES_DEST/nexshell.py" "\$@"
EOF

    # Copy main script
    $SUDO cp "$REPO_DIR/nexshell.py" "$MODULES_DEST/nexshell.py"
    $SUDO chmod +x "$BINARY"
    $SUDO chmod +x "$MODULES_DEST/nexshell.py"

    success "NexShell installed to $BINARY"
    echo ""
    info "Run: ${CYAN}nexshell${NC}"
    info "Run: ${CYAN}nexshell --help${NC}"
    info "Run: ${CYAN}nexshell -a${NC}  (show all payloads)"
}

# ── Windows instructions ──────────────────────────────────────────────────────
install_windows() {
    warn "Windows detected — manual steps required:"
    echo ""
    echo "  1. Add the nexshell directory to your PATH:"
    echo "     setx PATH \"%PATH%;$(pwd)\""
    echo ""
    echo "  2. Create an alias (PowerShell):"
    echo "     New-Alias nexshell 'python3 $(pwd)/nexshell.py'"
    echo ""
    echo "  3. Or run directly:"
    echo "     python3 nexshell.py [options]"
    echo ""
    success "On Windows, use WSL2 for full PTY support"
}

# ── Uninstall ─────────────────────────────────────────────────────────────────
uninstall() {
    warn "Uninstalling NexShell..."
    if [ -w "$INSTALL_DIR" ]; then
        rm -f "$BINARY"
        rm -rf "$MODULES_DEST"
    else
        sudo rm -f "$BINARY"
        sudo rm -rf "$MODULES_DEST"
    fi
    success "NexShell uninstalled"
}

# ── Main ──────────────────────────────────────────────────────────────────────
banner

OS=$(detect_os)
info "Detected OS: $OS"

check_python

case "${1:-install}" in
    install)
        case "$OS" in
            linux|macos|bsd) install_unix    ;;
            windows)         install_windows ;;
            *)               error "Unsupported OS: $OS" ;;
        esac
        ;;
    uninstall)
        uninstall ;;
    *)
        echo "Usage: $0 [install|uninstall]"
        exit 1 ;;
esac
