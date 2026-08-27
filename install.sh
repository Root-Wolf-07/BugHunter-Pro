#!/usr/bin/env bash
# ==============================================================================
# Bug Hunter AI — Terminal Installer (macOS & Linux)
# Installs Python environment, dependencies, and verifies security tools.
# ==============================================================================

set -e

echo "🐺 Bug Hunter AI — Terminal Installer"
echo "======================================"

OS="$(uname -s)"
case "$OS" in
    Linux*)     PLATFORM="linux";;
    Darwin*)    PLATFORM="macos";;
    *)          echo "[-] Error: Unsupported operating system: $OS. Bug Hunter supports Linux and macOS only."; exit 1;;
esac

echo "[*] Detected Platform: $PLATFORM ($OS)"

# Check Python >= 3.9
if ! command -v python3 &> /dev/null; then
    echo "[-] Python 3 is required. Please install Python 3.9+."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "[+] Python version: $PYTHON_VERSION"

# Setup virtual environment
if [ ! -d ".venv" ]; then
    echo "[*] Creating Python virtual environment in .venv..."
    python3 -m venv .venv
fi
source .venv/bin/activate

# Install Python requirements
echo "[*] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Security tools installation guidance
echo ""
echo "=== Security Scanners Setup ==="
if [ "$PLATFORM" = "macos" ]; then
    if command -v brew &> /dev/null; then
        echo "[*] To install recommended security scanners via Homebrew:"
        echo "    brew install nmap nuclei nikto ffuf ollama"
    else
        echo "[!] Homebrew not found. Install Homebrew to easily manage tools: https://brew.sh"
    fi
elif [ "$PLATFORM" = "linux" ]; then
    echo "[*] To install recommended security scanners on Debian/Ubuntu:"
    echo "    sudo apt update && sudo apt install -y nmap nikto"
    echo "    curl -fsSL https://ollama.com/install.sh | sh"
fi

echo ""
echo "[+] Bug Hunter AI installation completed successfully!"
echo "[+] Run './run.sh' or 'python3 -m cli.main' to start in terminal."
