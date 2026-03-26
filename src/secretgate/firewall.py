"""Firewall rule generation for preventing proxy bypass.

Generates OS-specific firewall rules that block direct outbound HTTPS
connections, forcing all traffic through the secretgate proxy. This is
the strongest defense against AI tools bypassing the proxy via env var
manipulation (issue #33).
"""

from __future__ import annotations

import platform
import shutil


def detect_platform() -> str:
    """Detect the platform and available firewall tool."""
    system = platform.system()
    if system == "Darwin":
        return "pf"
    elif system == "Linux":
        if shutil.which("nft"):
            return "nftables"
        elif shutil.which("iptables"):
            return "iptables"
        else:
            return "linux-unknown"
    elif system == "Windows":
        return "windows"
    return "unknown"


def generate_iptables_rules(
    proxy_port: int = 8083,
    user: str | None = None,
    domains: list[str] | None = None,
) -> str:
    """Generate iptables rules to force traffic through the proxy."""
    lines = [
        "#!/bin/bash",
        "# secretgate firewall rules (iptables)",
        "# Forces all outbound HTTPS through the local proxy",
        "",
        "set -euo pipefail",
        "",
        f"PROXY_PORT={proxy_port}",
    ]

    if user:
        lines.append(f'USER="{user}"')
        owner_match = '-m owner --uid-owner "$USER"'
    else:
        lines.append('USER="$(id -u)"')
        owner_match = '-m owner --uid-owner "$USER"'

    lines.extend([
        "",
        "# Allow traffic to the local proxy",
        "iptables -A OUTPUT -o lo -j ACCEPT",
        "",
    ])

    if domains:
        lines.append("# Block direct HTTPS to specific domains")
        for domain in domains:
            lines.extend([
                f'for ip in $(dig +short "{domain}"); do',
                f"    iptables -A OUTPUT -p tcp --dport 443 -d \"$ip\" {owner_match} -j DROP",
                "done",
            ])
    else:
        lines.extend([
            "# Block ALL direct outbound HTTPS (strongest)",
            f"iptables -A OUTPUT -p tcp --dport 443 {owner_match} -j DROP",
        ])

    lines.extend([
        "",
        'echo "secretgate firewall rules applied."',
        f'echo "All HTTPS traffic forced through localhost:{proxy_port}"',
    ])

    return "\n".join(lines) + "\n"


def generate_nftables_rules(
    proxy_port: int = 8083,
    user: str | None = None,
    domains: list[str] | None = None,
) -> str:
    """Generate nftables rules to force traffic through the proxy."""
    lines = [
        "#!/usr/sbin/nft -f",
        "# secretgate firewall rules (nftables)",
        "",
        "table inet secretgate {",
        "    chain output {",
        "        type filter hook output priority 0; policy accept;",
        "",
        "        # Allow traffic to loopback",
        "        oifname lo accept",
        "",
    ]

    skuid = f'meta skuid "{user}"' if user else 'meta skuid != 0'

    if domains:
        for domain in domains:
            lines.append(f"        # Block {domain}")
            lines.append(
                f"        tcp dport 443 {skuid} ip daddr @secretgate_blocked_{domain.replace('.', '_')} drop"
            )
    else:
        lines.append("        # Block all outbound HTTPS for user")
        lines.append(f"        tcp dport 443 {skuid} drop")

    lines.extend([
        "    }",
        "}",
    ])

    return "\n".join(lines) + "\n"


def generate_pf_rules(
    proxy_port: int = 8083,
    user: str | None = None,
) -> str:
    """Generate macOS pf rules to force traffic through the proxy."""
    user_clause = f'user "{user}"' if user else "user $USER"

    lines = [
        "# secretgate firewall rules (macOS pf)",
        "# Save to /etc/pf.anchors/secretgate",
        "",
        f"# Block direct outbound HTTPS, force through proxy on port {proxy_port}",
        f"pass out proto tcp from any to 127.0.0.1 port {proxy_port}",
        f"block out proto tcp from any to any port 443 {user_clause}",
        "",
        "# Load with:",
        '#   echo \'anchor "secretgate"\' | sudo tee -a /etc/pf.conf',
        "#   sudo pfctl -a secretgate -f /etc/pf.anchors/secretgate",
        "#   sudo pfctl -e",
    ]

    return "\n".join(lines) + "\n"


def generate_rules(
    proxy_port: int = 8083,
    user: str | None = None,
    domains: list[str] | None = None,
    tool: str | None = None,
) -> str:
    """Generate firewall rules for the detected or specified platform."""
    if tool is None:
        tool = detect_platform()

    if tool == "iptables":
        return generate_iptables_rules(proxy_port, user, domains)
    elif tool == "nftables":
        return generate_nftables_rules(proxy_port, user, domains)
    elif tool == "pf":
        return generate_pf_rules(proxy_port, user)
    elif tool == "windows":
        return (
            "# Windows firewall rules for secretgate\n"
            "# Use Windows Firewall with Advanced Security or:\n"
            f"# netsh advfirewall firewall add rule name=\"secretgate-block-https\" "
            f"dir=out action=block protocol=tcp remoteport=443\n"
            f"# netsh advfirewall firewall add rule name=\"secretgate-allow-proxy\" "
            f"dir=out action=allow protocol=tcp remoteport={proxy_port} remoteip=127.0.0.1\n"
        )
    else:
        return f"# Unsupported platform: {tool}\n# See docs/hardening.md for manual setup.\n"
