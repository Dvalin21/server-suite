#!/usr/bin/env bash
# =============================================================================
# Server Suite - Bootstrap Installer
# =============================================================================
# This script prepares the environment and launches the Server Suite setup.
# Must be run as root on Ubuntu/Debian systems.
# =============================================================================

set -euo pipefail

# --- Constants ----------------------------------------------------------------
SUITE_DIR="/opt/server-suite"
SUITE_REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_MIN_VERSION="3.10"
LOG_FILE="/var/log/server-suite-install.log"
BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Helpers ------------------------------------------------------------------
log()    { echo -e "${GREEN}[+]${NC} $*" | tee -a "$LOG_FILE"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOG_FILE"; }
error()  { echo -e "${RED}[✗]${NC} $*" | tee -a "$LOG_FILE"; exit 1; }
header() { echo -e "\n${CYAN}${BOLD}$*${NC}\n"; }

# --- Root check ---------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Server Suite must be run as root. Use: sudo bash install.sh"
    fi
}

# --- OS detection -------------------------------------------------------------
check_os() {
    header "Checking Operating System"
    if [[ ! -f /etc/os-release ]]; then
        error "Cannot detect OS. /etc/os-release not found."
    fi

    source /etc/os-release
    OS_ID="${ID}"
    OS_VERSION="${VERSION_ID}"
    OS_CODENAME="${VERSION_CODENAME:-unknown}"

    case "$OS_ID" in
        ubuntu)
            case "$OS_VERSION" in
                20.04|22.04|24.04)
                    log "Detected: Ubuntu $OS_VERSION ($OS_CODENAME) ✓"
                    ;;
                *)
                    warn "Ubuntu $OS_VERSION is not officially tested. Proceeding with caution."
                    ;;
            esac
            ;;
        debian)
            case "$OS_VERSION" in
                11|12)
                    log "Detected: Debian $OS_VERSION ($OS_CODENAME) ✓"
                    ;;
                *)
                    warn "Debian $OS_VERSION is not officially tested. Proceeding with caution."
                    ;;
            esac
            ;;
        *)
            error "Unsupported OS: $OS_ID. Server Suite requires Ubuntu 20.04+ or Debian 11+."
            ;;
    esac

    export OS_ID OS_VERSION OS_CODENAME
}

# --- Internet connectivity check ----------------------------------------------
check_internet() {
    header "Checking Internet Connectivity"
    local test_hosts=("8.8.8.8" "1.1.1.1" "archive.ubuntu.com")
    local connected=false

    for host in "${test_hosts[@]}"; do
        if ping -c 1 -W 3 "$host" &>/dev/null; then
            connected=true
            break
        fi
    done

    if [[ "$connected" == false ]]; then
        error "No internet connectivity detected. Please check your network connection."
    fi

    log "Internet connectivity confirmed ✓"
}

# --- System update ------------------------------------------------------------
update_system() {
    header "Updating Package Lists"
    log "Running apt-get update..."
    apt-get update -qq 2>&1 | tee -a "$LOG_FILE" || error "Failed to update package lists."
    log "Package lists updated ✓"
}

# --- Python installation ------------------------------------------------------
install_python() {
    header "Checking Python Installation"

    local python_cmd=""
    for cmd in python3.12 python3.11 python3.10 python3; do
        if command -v "$cmd" &>/dev/null; then
            local ver
            ver=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
            local major minor
            major=$(echo "$ver" | cut -d. -f1)
            minor=$(echo "$ver" | cut -d. -f2)
            if [[ "$major" -ge 3 && "$minor" -ge 10 ]]; then
                python_cmd="$cmd"
                log "Found $cmd (version $ver) ✓"
                break
            fi
        fi
    done

    if [[ -z "$python_cmd" ]]; then
        log "Installing Python 3.11..."
        apt-get install -y python3.11 python3.11-venv python3.11-dev 2>&1 | tee -a "$LOG_FILE"
        python_cmd="python3.11"
        log "Python 3.11 installed ✓"
    fi

    # Install pip if missing
    if ! "$python_cmd" -m pip --version &>/dev/null; then
        log "Installing pip..."
        apt-get install -y python3-pip 2>&1 | tee -a "$LOG_FILE"
    fi

    export PYTHON_CMD="$python_cmd"
}

# --- Core system dependencies -------------------------------------------------
install_system_deps() {
    header "Installing System Dependencies"

    local packages=(
        curl wget git
        lsblk smartmontools hdparm nvme-cli
        dmidecode lshw net-tools iproute2
        jq bc pciutils usbutils
        apt-transport-https ca-certificates gnupg
        software-properties-common
    )

    log "Installing core packages..."
    apt-get install -y "${packages[@]}" 2>&1 | tee -a "$LOG_FILE" || error "Failed to install system dependencies."
    log "System dependencies installed ✓"
}

# --- Python virtual environment -----------------------------------------------
setup_venv() {
    header "Setting Up Python Environment"

    local venv_dir="$SUITE_DIR/venv"

    if [[ ! -d "$venv_dir" ]]; then
        log "Creating Python virtual environment..."
        "$PYTHON_CMD" -m venv "$venv_dir" 2>&1 | tee -a "$LOG_FILE" || error "Failed to create virtual environment."
    fi

    log "Activating virtual environment..."
    # shellcheck disable=SC1091
    source "$venv_dir/bin/activate"

    log "Installing Python dependencies..."
    pip install --upgrade pip --quiet
    pip install -r "$SUITE_DIR/requirements.txt" --quiet 2>&1 | tee -a "$LOG_FILE" \
        || error "Failed to install Python dependencies."

    log "Python environment ready ✓"
    export VENV_DIR="$venv_dir"
    export VENV_PYTHON="$venv_dir/bin/python"
}

# --- Copy suite files to /opt -------------------------------------------------
deploy_suite() {
    header "Deploying Server Suite"

    if [[ "$SUITE_REPO_DIR" != "$SUITE_DIR" ]]; then
        log "Deploying suite to $SUITE_DIR..."
        mkdir -p "$SUITE_DIR"
        cp -r "$SUITE_REPO_DIR"/. "$SUITE_DIR/"
        log "Files deployed to $SUITE_DIR ✓"
    else
        log "Running from install directory ✓"
    fi

    # Set permissions
    chmod 700 "$SUITE_DIR/secrets" 2>/dev/null || true
    chmod +x "$SUITE_DIR/install.sh"
    chmod +x "$SUITE_DIR/server_suite.py"

    # Create symlink for easy access
    ln -sf "$SUITE_DIR/server_suite.py" /usr/local/bin/server-suite 2>/dev/null || true
    log "Symlink created: server-suite command available ✓"
}

# --- Setup logging ------------------------------------------------------------
setup_logging() {
    mkdir -p /var/log/server-suite
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
}

# --- Banner -------------------------------------------------------------------
print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
 ____                               ____        _ _
/ ___|  ___ _ ____   _____ _ __   / ___| _   _(_) |_ ___
\___ \ / _ \ '__\ \ / / _ \ '__|  \___ \| | | | | __/ _ \
 ___) |  __/ |   \ V /  __/ |      ___) | |_| | | ||  __/
|____/ \___|_|    \_/ \___|_|     |____/ \__,_|_|\__\___|

EOF
    echo -e "${NC}"
    echo -e "${BOLD}  The All-In-One Linux Server Deployment Suite${NC}"
    echo -e "  Version 1.0.0 | Ubuntu/Debian"
    echo -e "  ─────────────────────────────────────────────\n"
}

# --- Summary ------------------------------------------------------------------
print_summary() {
    header "Bootstrap Complete"
    echo -e "${GREEN}${BOLD}Server Suite is ready!${NC}\n"
    echo -e "  Suite installed at: ${CYAN}$SUITE_DIR${NC}"
    echo -e "  Log file:           ${CYAN}$LOG_FILE${NC}"
    echo -e "  Python:             ${CYAN}$PYTHON_CMD${NC}"
    echo -e ""
    echo -e "${BOLD}  Launching setup wizard...${NC}\n"
}

# --- Main ---------------------------------------------------------------------
main() {
    setup_logging
    print_banner

    check_root
    check_os
    check_internet
    update_system
    install_python
    install_system_deps
    deploy_suite
    setup_venv
    print_summary

    # Launch the main suite
    cd "$SUITE_DIR"
    exec "$VENV_PYTHON" server_suite.py "$@"
}

main "$@"
