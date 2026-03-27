"""Generate platform-specific hardening scripts to prevent proxy bypass.

Addresses GitHub issue #33: AI tools can unset https_proxy to bypass secretgate.
Generates layered defenses: firewall rules, readonly env vars, Claude Code hooks.
"""

from __future__ import annotations

import platform
import textwrap

import structlog

logger = structlog.get_logger()


def generate_firewall_script(proxy_port: int = 8083) -> str:
    """Generate platform-specific firewall rules to force traffic through the proxy."""
    system = platform.system()

    if system == "Linux":
        return textwrap.dedent(f"""\
            #!/usr/bin/env bash
            # secretgate firewall hardening (Linux / iptables)
            # Forces all outbound HTTPS through the local proxy.
            # Run as root: sudo bash <this-script>
            set -euo pipefail

            PROXY_PORT={proxy_port}
            CURRENT_USER="${{SUDO_USER:-$(whoami)}}"
            CURRENT_UID=$(id -u "$CURRENT_USER")

            echo "[secretgate] Installing firewall rules for user $CURRENT_USER (UID $CURRENT_UID)..."

            # Allow loopback traffic (proxy itself)
            iptables -C OUTPUT -o lo -j ACCEPT 2>/dev/null || \\
                iptables -A OUTPUT -o lo -j ACCEPT

            # Drop direct outbound HTTPS for this user (must go through proxy)
            iptables -C OUTPUT -p tcp --dport 443 -m owner --uid-owner "$CURRENT_UID" -j DROP 2>/dev/null || \\
                iptables -A OUTPUT -p tcp --dport 443 -m owner --uid-owner "$CURRENT_UID" -j DROP

            echo "[secretgate] Firewall rules installed. Direct HTTPS blocked for $CURRENT_USER."
            echo "[secretgate] To remove: iptables -D OUTPUT -p tcp --dport 443 -m owner --uid-owner $CURRENT_UID -j DROP"
        """)

    elif system == "Darwin":
        return textwrap.dedent(f"""\
            #!/usr/bin/env bash
            # secretgate firewall hardening (macOS / pf)
            # Forces all outbound HTTPS through the local proxy.
            # Run as root: sudo bash <this-script>
            set -euo pipefail

            PROXY_PORT={proxy_port}
            ANCHOR_FILE="/etc/pf.anchors/secretgate"
            CURRENT_USER="${{SUDO_USER:-$(whoami)}}"

            echo "[secretgate] Installing pf anchor for user $CURRENT_USER..."

            cat > "$ANCHOR_FILE" << 'EOF'
            # secretgate: block direct HTTPS, force through proxy
            pass out proto tcp from any to 127.0.0.1 port {proxy_port}
            block out proto tcp from any to any port 443 user $CURRENT_USER
            EOF

            # Add anchor to pf.conf if not present
            if ! grep -q 'anchor "secretgate"' /etc/pf.conf; then
                echo 'anchor "secretgate"' >> /etc/pf.conf
                echo 'load anchor "secretgate" from "/etc/pf.anchors/secretgate"' >> /etc/pf.conf
            fi

            pfctl -a secretgate -f "$ANCHOR_FILE"
            pfctl -e 2>/dev/null || true

            echo "[secretgate] pf rules installed. Direct HTTPS blocked for $CURRENT_USER."
            echo "[secretgate] To remove: sudo pfctl -a secretgate -F all"
        """)

    else:
        return textwrap.dedent("""\
            # secretgate firewall hardening
            # No automatic script available for this platform.
            # Manually configure your firewall to:
            # 1. Allow traffic to 127.0.0.1:<proxy_port>
            # 2. Block direct outbound connections on port 443
        """)


def generate_readonly_env(proxy_port: int = 8083) -> str:
    """Generate shell snippet to set proxy env vars as readonly."""
    return textwrap.dedent(f"""\
        # secretgate: lock proxy environment variables (add to ~/.bashrc or ~/.zshrc)
        export https_proxy=http://localhost:{proxy_port}
        export HTTPS_PROXY=http://localhost:{proxy_port}
        export http_proxy=http://localhost:{proxy_port}
        export HTTP_PROXY=http://localhost:{proxy_port}
        readonly https_proxy HTTPS_PROXY http_proxy HTTP_PROXY
    """)


def generate_claude_hooks() -> str:
    """Generate Claude Code hooks config to detect proxy env manipulation."""
    return textwrap.dedent("""\
        {
          "hooks": {
            "pre_tool_call": [
              {
                "matcher": "Bash",
                "command": "echo \\"$CLAUDE_TOOL_INPUT\\" | grep -qiE '(unset|export)\\\\s*.*(https?_proxy|ANTHROPIC_BASE_URL|no_proxy|SSL_CERT_FILE|REQUESTS_CA_BUNDLE|NODE_EXTRA_CA_CERTS)' && echo 'BLOCKED: proxy env modification detected by secretgate' >&2 && exit 1 || exit 0"
              }
            ]
          }
        }
    """)


def print_harden_guide(proxy_port: int = 8083, output_dir: str | None = None) -> None:
    """Print a complete hardening guide with generated scripts."""
    print("=" * 60)
    print("  secretgate Hardening Guide")
    print("=" * 60)
    print()
    print("Layer 1: Firewall Rules (strongest)")
    print("-" * 40)
    print(generate_firewall_script(proxy_port))
    print()
    print("Layer 2: Readonly Environment Variables")
    print("-" * 40)
    print(generate_readonly_env(proxy_port))
    print()
    print("Layer 3: Claude Code Hooks")
    print("-" * 40)
    print(generate_claude_hooks())
    print()
    print("=" * 60)
    print("Recommendation: Use all three layers for defense-in-depth.")
    print(f"See: {_hardening_doc_url()}")
    print("=" * 60)

    if output_dir:
        from pathlib import Path

        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        fw_path = out / "firewall.sh"
        fw_path.write_text(generate_firewall_script(proxy_port))
        fw_path.chmod(0o755)

        env_path = out / "readonly-env.sh"
        env_path.write_text(generate_readonly_env(proxy_port))

        hooks_path = out / "claude-hooks.json"
        hooks_path.write_text(generate_claude_hooks())

        print(f"\nScripts written to {out}/")
        print(f"  {fw_path.name}   — run with: sudo bash {fw_path}")
        print(f"  {env_path.name}  — source in shell profile")
        print(f"  {hooks_path.name} — add to .claude/settings.json")


def _hardening_doc_url() -> str:
    return "https://github.com/secretgate/secretgate/blob/main/docs/hardening.md"
