#!/usr/bin/env bash
# Install secretgate — lean security proxy for AI coding tools.
# Usage: curl -fsSL https://raw.githubusercontent.com/secretgate/secretgate/main/install.sh | bash
set -euo pipefail

PACKAGE="secretgate"

echo "=== Installing $PACKAGE ==="
echo

# Check Python 3.11+
if ! command -v python3 &>/dev/null; then
    echo "Error: python3 not found. Install Python 3.11 or later first."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || { [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 11 ]; }; then
    echo "Error: Python 3.11+ required (found $PYTHON_VERSION)."
    exit 1
fi

echo "Found Python $PYTHON_VERSION"

# Install via pipx (preferred) or pip
if command -v pipx &>/dev/null; then
    echo "Installing with pipx..."
    pipx install "$PACKAGE"
elif command -v pip &>/dev/null && pip install --dry-run "$PACKAGE" &>/dev/null 2>&1; then
    echo "Installing with pip..."
    pip install "$PACKAGE"
else
    # pipx not available, try to install it
    echo "pipx not found. Attempting to install pipx first..."

    if command -v apt &>/dev/null; then
        sudo apt update && sudo apt install -y pipx
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y pipx
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm python-pipx
    elif command -v brew &>/dev/null; then
        brew install pipx
    else
        echo "Error: Could not install pipx automatically."
        echo "Install pipx manually: https://pipx.pypa.io/stable/installation/"
        exit 1
    fi

    pipx ensurepath
    echo "Installing with pipx..."
    pipx install "$PACKAGE"
fi

echo
# Verify
if command -v secretgate &>/dev/null; then
    echo "secretgate $(secretgate --version 2>/dev/null || echo '') installed successfully!"
else
    echo "Installed successfully, but 'secretgate' is not on PATH yet."
    echo "Run: pipx ensurepath"
    echo "Then restart your shell or run: source ~/.bashrc"
fi

echo
echo "Next steps:"
echo "  secretgate ca init      # Generate CA certificate"
echo "  secretgate ca trust     # Show trust instructions"
echo "  secretgate serve        # Start the proxy"
echo "  secretgate wrap -- claude  # Proxy a single command"
