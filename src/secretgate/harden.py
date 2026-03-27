"""Generate platform-specific firewall rules to prevent proxy bypass.

Produces DROP rules that block direct outbound HTTPS connections,
forcing all traffic through the secretgate proxy. The proxy itself
provides observability (scanning, redaction, audit logging).

Addresses GitHub issue #33.
"""

from __future__ import annotations

import platform
import re


def validate_domain(domain: str) -> bool:
    """Check that a domain looks safe to embed in a shell script."""
    return bool(re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$", domain))


def generate_rules(
    proxy_port: int = 8083,
    tool: str | None = None,
    domains: list[str] | None = None,
    user: str | None = None,
) -> str:
    """Generate firewall rules for the detected or specified platform.

    Args:
        proxy_port: The forward proxy port to allow.
        tool: Firewall tool to generate for ("iptables", "nftables", "pf",
              "windows", or None for auto-detect).
        domains: If set, only block these domains instead of all port 443.
        user: OS user to restrict rules to. Defaults to current user.

    Returns:
        Shell script or config text with the firewall rules.
    """
    if tool is None:
        tool = _detect_tool()

    if domains:
        for d in domains:
            if not validate_domain(d):
                raise ValueError(f"Invalid domain: {d!r}")

    generators = {
        "iptables": _generate_iptables,
        "nftables": _generate_nftables,
        "pf": _generate_pf,
        "windows": _generate_windows,
    }
    gen = generators.get(tool)
    if gen is None:
        return (
            f"# Unsupported platform: {tool}\n# See docs/hardening.md for manual firewall setup.\n"
        )
    return gen(proxy_port=proxy_port, domains=domains, user=user)


def generate_remove(
    tool: str | None = None,
) -> str:
    """Generate commands to remove the firewall rules."""
    if tool is None:
        tool = _detect_tool()

    if tool == "iptables":
        return (
            "#!/usr/bin/env bash\n"
            "# Remove secretgate iptables rules\n"
            "set -euo pipefail\n"
            'CURRENT_UID=$(id -u "${SUDO_USER:-$(whoami)}")\n'
            "iptables -D OUTPUT -p tcp --dport 443 "
            '-m owner --uid-owner "$CURRENT_UID" -j DROP 2>/dev/null || true\n'
            'echo "[secretgate] Firewall rules removed."\n'
        )
    elif tool == "nftables":
        return (
            "#!/usr/bin/env bash\n"
            "# Remove secretgate nftables rules\n"
            "nft delete table inet secretgate 2>/dev/null || true\n"
            'echo "[secretgate] Firewall rules removed."\n'
        )
    elif tool == "pf":
        return (
            "#!/usr/bin/env bash\n"
            "# Remove secretgate pf rules\n"
            "sudo pfctl -a secretgate -F all 2>/dev/null || true\n"
            'echo "[secretgate] pf rules removed."\n'
        )
    elif tool == "windows":
        return (
            "# Remove secretgate Windows Firewall rules (run as Administrator)\n"
            "netsh advfirewall firewall delete rule "
            'name="secretgate-block-https"\n'
        )
    return f"# No removal script for: {tool}\n"


def _detect_tool() -> str:
    """Detect the best firewall tool for this platform."""
    import shutil

    system = platform.system()
    if system == "Darwin":
        return "pf"
    elif system == "Linux":
        if shutil.which("nft"):
            return "nftables"
        return "iptables"
    elif system == "Windows":
        return "windows"
    return "unknown"


def _generate_iptables(
    proxy_port: int,
    domains: list[str] | None,
    user: str | None,
) -> str:
    lines = [
        "#!/usr/bin/env bash",
        "# secretgate firewall hardening (iptables)",
        "# Forces all outbound HTTPS through the local proxy.",
        "# Run as root: sudo bash <this-script>",
        "set -euo pipefail",
        "",
    ]

    if user:
        lines.append(f'CURRENT_UID=$(id -u "{user}")')
    else:
        lines.append('CURRENT_UID=$(id -u "${SUDO_USER:-$(whoami)}")')

    lines += [
        "",
        "# Allow loopback traffic (proxy itself)",
        "iptables -C OUTPUT -o lo -j ACCEPT 2>/dev/null || \\",
        "    iptables -A OUTPUT -o lo -j ACCEPT",
        "",
    ]

    if domains:
        lines.append("# Block direct HTTPS to specific domains")
        for domain in domains:
            lines += [
                f"# {domain}",
                f'for ip in $(dig +short "{domain}" | grep -E "^[0-9]"); do',
                '    iptables -A OUTPUT -p tcp --dport 443 -d "$ip" '
                '-m owner --uid-owner "$CURRENT_UID" -j DROP',
                "done",
            ]
    else:
        lines += [
            "# Block ALL direct outbound HTTPS for this user",
            "iptables -C OUTPUT -p tcp --dport 443 "
            '-m owner --uid-owner "$CURRENT_UID" -j DROP 2>/dev/null || \\',
            '    iptables -A OUTPUT -p tcp --dport 443 -m owner --uid-owner "$CURRENT_UID" -j DROP',
        ]

    lines += [
        "",
        'echo "[secretgate] Firewall rules installed."',
        f'echo "[secretgate] All direct HTTPS blocked — traffic must go through localhost:{proxy_port}"',
        'echo "[secretgate] To remove: secretgate harden --remove"',
    ]

    return "\n".join(lines) + "\n"


def _generate_nftables(
    proxy_port: int,
    domains: list[str] | None,
    user: str | None,
) -> str:
    if user:
        skuid = f'meta skuid "{user}"'
    else:
        skuid = "meta skuid != 0"

    nft_rules = "\n".join(
        [
            "table inet secretgate {",
            "    chain output {",
            "        type filter hook output priority 0; policy accept;",
            "",
            "        # Allow loopback",
            "        oifname lo accept",
            "",
            "        # Block all direct outbound HTTPS",
            f"        tcp dport 443 {skuid} drop",
            "    }",
            "}",
        ]
    )

    lines = [
        "#!/usr/bin/env bash",
        "# secretgate firewall hardening (nftables)",
        "# Forces all outbound HTTPS through the local proxy.",
        "# Run as root: sudo bash <this-script>",
        "set -euo pipefail",
        "",
        "nft -f - <<'NFT'",
        nft_rules,
        "NFT",
        "",
        'echo "[secretgate] Firewall rules installed (nftables)."',
        f'echo "[secretgate] All direct HTTPS blocked — traffic must go through localhost:{proxy_port}"',
        'echo "[secretgate] To remove: secretgate harden --remove | sudo bash"',
    ]

    return "\n".join(lines) + "\n"


def _generate_pf(
    proxy_port: int,
    domains: list[str] | None,
    user: str | None,
) -> str:
    import getpass

    resolved_user = user or getpass.getuser()

    anchor_content = "\n".join(
        [
            f"pass out proto tcp from any to 127.0.0.1 port {proxy_port}",
            f"block out proto tcp from any to any port 443 user {resolved_user}",
        ]
    )

    lines = [
        "#!/usr/bin/env bash",
        "# secretgate firewall hardening (macOS pf)",
        "# Forces all outbound HTTPS through the local proxy.",
        "# Run as root: sudo bash <this-script>",
        "set -euo pipefail",
        "",
        'ANCHOR_FILE="/etc/pf.anchors/secretgate"',
        "",
        "# Write pf anchor rules",
        "cat > \"$ANCHOR_FILE\" <<'PF'",
        anchor_content,
        "PF",
        "",
        "# Add anchor to pf.conf if not already present",
        "if ! grep -q 'anchor \"secretgate\"' /etc/pf.conf; then",
        "    echo 'anchor \"secretgate\"' >> /etc/pf.conf",
        '    echo \'load anchor "secretgate" from "/etc/pf.anchors/secretgate"\' >> /etc/pf.conf',
        "fi",
        "",
        'pfctl -a secretgate -f "$ANCHOR_FILE"',
        "pfctl -e 2>/dev/null || true",
        "",
        'echo "[secretgate] Firewall rules installed (pf)."',
        f'echo "[secretgate] All direct HTTPS blocked for user {resolved_user} — traffic must go through localhost:{proxy_port}"',
        'echo "[secretgate] To remove: secretgate harden --remove | sudo bash"',
    ]

    return "\n".join(lines) + "\n"


def _generate_windows(
    proxy_port: int,
    domains: list[str] | None,
    user: str | None,
) -> str:
    lines = [
        "# secretgate firewall hardening (Windows Firewall)",
        "# Run in PowerShell as Administrator",
        "",
        "# Block all direct outbound HTTPS",
        "netsh advfirewall firewall add rule "
        'name="secretgate-block-https" '
        "dir=out action=block protocol=tcp remoteport=443",
        "",
        f"# Allow traffic to local proxy on port {proxy_port}",
        "netsh advfirewall firewall add rule "
        f'name="secretgate-allow-proxy" '
        f"dir=out action=allow protocol=tcp "
        f"remoteport={proxy_port} remoteip=127.0.0.1",
        "",
        "# To remove:",
        '# netsh advfirewall firewall delete rule name="secretgate-block-https"',
        '# netsh advfirewall firewall delete rule name="secretgate-allow-proxy"',
    ]

    return "\n".join(lines) + "\n"
