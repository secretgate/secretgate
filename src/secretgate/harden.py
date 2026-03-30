"""Network isolation and firewall hardening to prevent proxy bypass.

Primary approach: per-process network isolation via Linux network
namespaces (unshare + slirp4netns) or macOS sandbox-exec.  No root
required — the child process can only reach the secretgate proxy.

Fallback: ``secretgate harden`` generates platform-specific firewall
scripts (iptables/nftables/pf/Windows) for manual application.

Addresses GitHub issue #33.
"""

from __future__ import annotations

import platform
import re
import shutil


def run_in_namespace(
    command: list[str],
    env: dict[str, str],
    proxy_port: int,
) -> int | None:
    """Run a command in a network namespace with only proxy access.

    Uses ``unshare --user --net`` + ``slirp4netns`` for rootless,
    per-process network isolation.  The child can only reach the
    host proxy via the slirp4netns gateway (10.0.2.2).  Direct
    outbound HTTPS is blocked by iptables rules *inside* the
    namespace.  No sudo required.

    Returns the child process exit code, or None if namespace
    setup failed (e.g. nested namespaces on WSL2).
    """
    import subprocess

    if not shutil.which("slirp4netns"):
        raise RuntimeError(
            "slirp4netns is required for --harden but not found.\n"
            "Install it with: sudo apt install slirp4netns"
        )

    # Shell script that runs inside the namespace.
    # It waits for slirp4netns to create tap0, applies firewall
    # rules, then execs the user's command.
    ns_script = f"""\
set -e

# Wait for slirp4netns to create the tap0 interface (up to 5s)
for _i in $(seq 50); do
    if ip link show tap0 >/dev/null 2>&1; then break; fi
    sleep 0.1
done

if ! ip link show tap0 >/dev/null 2>&1; then
    echo "[secretgate] Error: network namespace setup failed (tap0 not created)" >&2
    exit 1
fi

# Firewall rules inside the namespace:
# - Allow loopback (needed for internal comms)
# - Allow proxy gateway (10.0.2.2:{proxy_port})
# - Block direct HTTPS so the child cannot bypass the proxy
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -d 10.0.2.2 -p tcp --dport {proxy_port} -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j REJECT --reject-with tcp-reset

# Run the user's command
exec "$@"
"""

    # Point proxy env vars at the slirp4netns gateway instead of localhost
    ns_env = env.copy()
    gateway_proxy = f"http://10.0.2.2:{proxy_port}"
    ns_env.update(
        {
            "https_proxy": gateway_proxy,
            "http_proxy": gateway_proxy,
            "HTTPS_PROXY": gateway_proxy,
            "HTTP_PROXY": gateway_proxy,
        }
    )

    # Start the child in a new user + network namespace.
    # Don't capture stderr — the user's command needs it.
    child = subprocess.Popen(
        [
            "unshare",
            "--user",
            "--map-root-user",
            "--net",
            "bash",
            "-c",
            ns_script,
            "--",
            *command,
        ],
        env=ns_env,
    )

    # Brief pause to let unshare set up the namespace.
    # If it fails immediately (e.g. nested namespace not supported),
    # the child will exit and we detect it before starting slirp4netns.
    import time

    time.sleep(0.2)
    if child.poll() is not None:
        return None

    # Verify the namespace exists before starting slirp4netns
    import os

    ns_path = f"/proc/{child.pid}/ns/net"
    if not os.path.exists(ns_path):
        # Process exists but namespace not ready — wait a bit more
        time.sleep(0.5)
        if child.poll() is not None or not os.path.exists(ns_path):
            return None

    # Attach slirp4netns to give the namespace network access via a TAP device.
    # The host is reachable at 10.0.2.2 (default gateway).
    slirp = subprocess.Popen(
        [
            "slirp4netns",
            "--configure",
            "--mtu=65520",
            str(child.pid),
            "tap0",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    try:
        rc = child.wait()
        if rc != 0 and slirp.poll() is not None:
            # slirp4netns exited early — namespace setup failed
            stderr_out = slirp.stderr.read().decode(errors="replace").strip()
            if "setns" in stderr_out or "Operation not permitted" in stderr_out:
                # Can't create nested namespace (e.g. already in one)
                return None
        return rc
    except KeyboardInterrupt:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
        return 130  # standard Ctrl+C exit code
    finally:
        slirp.terminate()
        try:
            slirp.wait(timeout=3)
        except subprocess.TimeoutExpired:
            slirp.kill()


def run_in_sandbox(
    command: list[str],
    env: dict[str, str],
    proxy_port: int,
) -> int:
    """Run a command in a macOS sandbox with only proxy access.

    Uses ``sandbox-exec`` with an SBPL profile that denies all network
    access except connections to localhost on the proxy port.
    No root required.

    Returns the child process exit code.
    """
    import subprocess
    import tempfile

    # Sandbox Profile Language (SBPL) — deny all network, allow only proxy
    profile = f"""\
(version 1)
(deny default)

;; Allow all non-network operations
(allow process*)
(allow file*)
(allow sysctl-read)
(allow mach*)
(allow ipc*)
(allow iokit-open)
(allow system*)
(allow signal)

;; Network: only allow connections to the local proxy
(deny network*)
(allow network* (remote ip "localhost:{proxy_port}"))
(allow network* (local ip "localhost:*"))
"""

    # Write profile to a temp file (sandbox-exec needs a file path)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".sb", prefix="secretgate-", delete=False
    ) as f:
        f.write(profile)
        profile_path = f.name

    try:
        result = subprocess.run(
            ["sandbox-exec", "-f", profile_path, *command],
            env=env,
        )
        return result.returncode
    except KeyboardInterrupt:
        return 130
    finally:
        import os

        os.unlink(profile_path)


def can_harden() -> tuple[str | None, bool]:
    """Check if per-process network isolation is available.

    Returns (method, tested) where method is "namespace", "sandbox",
    or None, and tested indicates whether this platform has been
    verified by the developers.
    """
    system = platform.system()
    if system == "Linux" and shutil.which("slirp4netns"):
        return "namespace", _is_wsl()  # only tested on WSL2 so far
    elif system == "Darwin" and shutil.which("sandbox-exec"):
        return "sandbox", False  # not yet tested on macOS
    return None, False


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


def _is_wsl() -> bool:
    """Detect if running under Windows Subsystem for Linux."""
    try:
        with open("/proc/version") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def _detect_tool() -> str:
    """Detect the best firewall tool for this platform."""
    system = platform.system()
    if system == "Darwin":
        return "pf"
    elif system == "Linux":
        # nftables is present on WSL2 but doesn't actually enforce rules
        if shutil.which("nft") and not _is_wsl():
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
