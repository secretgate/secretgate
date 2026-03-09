#!/usr/bin/env bash
# One-time setup for secretgate forward proxy.
# Run this after installing secretgate: pip install secretgate
set -euo pipefail

echo "=== secretgate setup ==="
echo

# Check secretgate is installed
if ! command -v secretgate &>/dev/null; then
    echo "Error: secretgate not found. Install it first:"
    echo "  pip install secretgate"
    exit 1
fi

# Generate CA certificate
echo "Generating CA certificate..."
secretgate ca init
echo

# Print CA trust instructions
secretgate ca trust
echo

# Print shell config snippet
CA_PATH=$(secretgate ca path)
cat <<EOF

=== Add to your shell profile (.bashrc / .zshrc) ===

# secretgate forward proxy
alias claude-safe='secretgate wrap -- claude'
# Or always proxy all traffic:
# export https_proxy=http://localhost:8083
# export http_proxy=http://localhost:8083
# export SSL_CERT_FILE=$CA_PATH
# export NODE_EXTRA_CA_CERTS=$CA_PATH
# export no_proxy=""

=== Quick test ===

# Terminal 1:
secretgate serve --forward-proxy-port 8083 --mode audit

# Terminal 2:
secretgate wrap -- claude

EOF
