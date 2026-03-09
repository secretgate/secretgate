#!/usr/bin/env bash
# Run any command with all traffic routed through secretgate.
# Starts the proxy in the background if it's not already running.
#
# Usage:
#   ./scripts/with-secretgate.sh claude
#   ./scripts/with-secretgate.sh curl https://example.com
#   ./scripts/with-secretgate.sh bash  # interactive shell with proxy
set -euo pipefail

PROXY_PORT="${SECRETGATE_FORWARD_PROXY_PORT:-8083}"
REVERSE_PORT="${SECRETGATE_PORT:-8085}"
MODE="${SECRETGATE_MODE:-redact}"
PROXY_URL="http://localhost:${PROXY_PORT}"

# Check secretgate is installed
if ! command -v secretgate &>/dev/null; then
    echo "Error: secretgate not found. Install it first:" >&2
    echo "  pip install secretgate" >&2
    exit 1
fi

# Ensure CA exists
CA_PATH=$(secretgate ca path)
if [ ! -f "$CA_PATH" ]; then
    echo "Generating CA certificate..." >&2
    secretgate ca init >&2
fi

# Start secretgate if not already running
if ! curl -sf "${PROXY_URL}" &>/dev/null 2>&1 && ! ss -tln | grep -q ":${PROXY_PORT} " 2>/dev/null; then
    echo "Starting secretgate (port ${REVERSE_PORT}, forward proxy ${PROXY_PORT}, mode ${MODE})..." >&2
    secretgate serve --port "${REVERSE_PORT}" --forward-proxy-port "${PROXY_PORT}" --mode "${MODE}" &
    SECRETGATE_PID=$!

    # Wait for proxy to be ready
    for i in $(seq 1 30); do
        if ss -tln 2>/dev/null | grep -q ":${PROXY_PORT} "; then
            break
        fi
        sleep 0.1
    done
    echo "secretgate started (PID ${SECRETGATE_PID})" >&2

    # Clean up on exit
    trap "kill ${SECRETGATE_PID} 2>/dev/null; wait ${SECRETGATE_PID} 2>/dev/null" EXIT
fi

if [ $# -eq 0 ]; then
    echo "Usage: $0 <command> [args...]" >&2
    echo "Example: $0 claude" >&2
    exit 1
fi

# Run the command with proxy env vars
export https_proxy="${PROXY_URL}"
export http_proxy="${PROXY_URL}"
export HTTPS_PROXY="${PROXY_URL}"
export HTTP_PROXY="${PROXY_URL}"
export SSL_CERT_FILE="${CA_PATH}"
export REQUESTS_CA_BUNDLE="${CA_PATH}"
export NODE_EXTRA_CA_CERTS="${CA_PATH}"
export no_proxy=""

exec "$@"
