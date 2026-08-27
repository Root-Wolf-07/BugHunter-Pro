#!/usr/bin/env bash
# ==============================================================================
# Bug Hunter AI — Terminal-Only Runner
# Find. Explain. Fix. Verify.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "[-] Error: python3 is required but not installed."
    exit 1
fi

# Activate virtual environment if present
if [ -d ".venv" ]; then
    source .venv/bin/activate
elif [ -d "venv" ]; then
    source venv/bin/activate
fi

# Start the interactive terminal CLI
exec python3 -m cli.main interactive "$@"
