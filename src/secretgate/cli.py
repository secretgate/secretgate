"""CLI entry point — keep it simple."""

from __future__ import annotations

from pathlib import Path

import click
import structlog
import uvicorn

from secretgate import __version__


@click.group()
@click.version_option(version=__version__)
def main():
    """secretgate — security proxy for AI coding tools."""
    pass


@main.command()
@click.option("--port", "-p", default=8080, help="Port to listen on")
@click.option("--host", "-h", default="127.0.0.1", help="Host to bind to")
@click.option(
    "--mode",
    "-m",
    type=click.Choice(["redact", "block", "audit"]),
    default="redact",
    help="How to handle detected secrets",
)
@click.option("--config", "-c", type=click.Path(exists=True, path_type=Path), help="Config file")
@click.option(
    "--signatures",
    "-s",
    type=click.Path(exists=True, path_type=Path),
    help="Custom signatures YAML",
)
@click.option(
    "--log-level", default="info", type=click.Choice(["debug", "info", "warning", "error"])
)
@click.option("--log-format", default="text", type=click.Choice(["text", "json"]))
@click.option(
    "--detect-secrets",
    "use_detect_secrets",
    is_flag=True,
    help="Enable detect-secrets plugins for extra coverage",
)
@click.option(
    "--forward-proxy-port",
    "-f",
    default=None,
    type=int,
    help="Port for forward proxy (enables TLS MITM mode)",
)
@click.option(
    "--certs-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Directory for CA certs (default: ~/.secretgate/certs)",
)
@click.option(
    "--no-known-values",
    is_flag=True,
    help="Disable known-value secret scanning (env var / file harvesting)",
)
def serve(
    port: int,
    host: str,
    mode: str,
    config: Path | None,
    signatures: Path | None,
    log_level: str,
    log_format: str,
    use_detect_secrets: bool,
    forward_proxy_port: int | None,
    certs_dir: Path | None,
    no_known_values: bool,
):
    """Start the secretgate proxy server."""
    from secretgate.config import Config
    from secretgate.server import create_app

    # Configure logging
    import logging

    log_level_num = getattr(logging, log_level.upper(), logging.INFO)
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(log_level_num),
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer()
            if log_format == "text"
            else structlog.processors.JSONRenderer(),
        ],
    )

    cfg = Config.load(config)
    # CLI overrides
    cfg.port = port
    cfg.host = host
    cfg.mode = mode
    cfg.log_level = log_level
    if signatures:
        cfg.signatures_path = signatures
    if use_detect_secrets:
        cfg.use_detect_secrets = True
    if forward_proxy_port is not None:
        cfg.forward_proxy_port = forward_proxy_port
    if certs_dir is not None:
        cfg.certs_dir = certs_dir
    if no_known_values:
        cfg.enable_known_values = False

    app = create_app(cfg)
    uvicorn.run(app, host=cfg.host, port=cfg.port, log_level=log_level)


# Binary file extensions to skip when recursing directories
_BINARY_EXTENSIONS = frozenset({
    ".pyc", ".pyo", ".so", ".o", ".a", ".dylib", ".dll", ".exe",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".whl", ".egg", ".class", ".jar",
    ".db", ".sqlite", ".sqlite3",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".doc", ".docx",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
})


def _resolve_file_args(paths: tuple[str, ...]) -> list[str]:
    """Expand directories into file lists, skipping binary and hidden files."""
    result: list[str] = []
    for p in paths:
        path = Path(p)
        if path.is_file():
            result.append(str(path))
        elif path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and not any(
                    part.startswith(".") for part in child.relative_to(path).parts
                ):
                    if child.suffix.lower() not in _BINARY_EXTENSIONS:
                        result.append(str(child))
    return result


@main.command()
@click.option(
    "--detect-secrets",
    "use_detect_secrets",
    is_flag=True,
    help="Enable detect-secrets plugins for extra coverage",
)
@click.option(
    "--no-entropy",
    is_flag=True,
    help="Disable entropy-based detection (reduces false positives)",
)
@click.option(
    "--no-known-values",
    is_flag=True,
    help="Disable known-value secret scanning (env var / file harvesting)",
)
@click.argument("files", nargs=-1, type=click.Path(exists=True))
def scan(use_detect_secrets: bool, no_entropy: bool, no_known_values: bool, files: tuple[str, ...]):
    """Scan files or stdin for secrets.

    Pass file paths as arguments, or pipe text via stdin.

    \b
    Examples:
        secretgate scan .env config.yaml
        secretgate scan --no-entropy src/
        cat .env | secretgate scan
        git diff --cached | secretgate scan
    """
    import sys
    from secretgate.secrets.scanner import SecretScanner

    scanner = SecretScanner(
        use_detect_secrets=use_detect_secrets,
        enable_entropy=not no_entropy,
        enable_known_values=not no_known_values,
    )
    total_matches = []

    if files:
        resolved_files = _resolve_file_args(files)
        for filepath in resolved_files:
            try:
                with open(filepath) as f:
                    text = f.read()
            except (UnicodeDecodeError, IsADirectoryError, PermissionError):
                continue  # skip binary files and unreadable entries
            matches = scanner.scan(text)
            for m in matches:
                preview = m.value[:8] + "..." if len(m.value) > 8 else m.value
                click.echo(
                    f"  {filepath}:{m.line_number}: [{m.service}] {m.pattern_name} — {preview}"
                )
            total_matches.extend(matches)
    else:
        text = sys.stdin.read()
        matches = scanner.scan(text)
        for m in matches:
            preview = m.value[:8] + "..." if len(m.value) > 8 else m.value
            click.echo(f"  Line {m.line_number}: [{m.service}] {m.pattern_name} — {preview}")
        total_matches.extend(matches)

    if not total_matches:
        click.echo("No secrets found.")
        return

    click.echo(f"\n{len(total_matches)} secret(s) found.")
    sys.exit(1)


def _find_available_port(preferred: int, max_attempts: int = 20) -> int:
    """Return *preferred* if it's free, otherwise try successive ports."""
    import socket

    for offset in range(max_attempts):
        candidate = preferred + offset
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(0.5)
            sock.connect(("127.0.0.1", candidate))
            # Port is in use — try the next one
            sock.close()
        except (ConnectionRefusedError, OSError):
            sock.close()
            return candidate
    raise click.ClickException(
        f"Could not find an available port in range {preferred}–{preferred + max_attempts - 1}"
    )


@main.command(context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.option(
    "--forward-proxy-port",
    "-f",
    default=8083,
    type=int,
    help="Port for the forward proxy",
)
@click.option("--port", "-p", default=8085, type=int, help="Port for the reverse proxy")
@click.option(
    "--mode",
    "-m",
    type=click.Choice(["redact", "block", "audit"]),
    default="redact",
    help="How to handle detected secrets",
)
@click.option(
    "--log-file",
    type=click.Path(path_type=Path),
    default=None,
    help="Log file path (default: ~/.secretgate/wrap.log, use '-' to disable)",
)
@click.option("--verbose", "-v", is_flag=True, help="Also stream proxy logs to stderr")
@click.pass_context
def wrap(ctx, forward_proxy_port: int, port: int, mode: str, log_file: Path | None, verbose: bool):
    """Run a command with all traffic routed through secretgate.

    Starts the forward proxy in the background, sets proxy env vars,
    and runs the given command. Stops the proxy when the command exits.

    \b
    Examples:
        secretgate wrap -- claude
        secretgate wrap -- curl https://example.com
        secretgate wrap --mode audit -- bash
        secretgate wrap -- git push
    """
    import atexit
    import os
    import socket
    import subprocess
    import sys
    import time

    from secretgate.certs import CertAuthority

    # Get command from remaining args, strip leading "--"
    command = ctx.args
    if command and command[0] == "--":
        command = command[1:]

    if not command:
        click.echo("Usage: secretgate wrap -- <command> [args...]", err=True)
        click.echo("Example: secretgate wrap -- claude", err=True)
        ctx.exit(1)

    # Resolve log file path
    if log_file is None:
        log_path = Path(
            os.environ.get("SECRETGATE_LOG_FILE", str(Path.home() / ".secretgate" / "wrap.log"))
        )
    elif str(log_file) == "-":
        log_path = None  # disabled
    else:
        log_path = log_file

    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)

    # Find available ports (auto-increment if already in use)
    forward_proxy_port = _find_available_port(forward_proxy_port)
    port = _find_available_port(port)
    # Ensure the two ports don't collide
    if port == forward_proxy_port:
        port = _find_available_port(port + 1)

    # Ensure CA exists and create combined bundle
    ca = CertAuthority()
    ca.ensure_ca()
    # Use combined bundle (system CAs + secretgate CA) so tools trust both
    # the MITM cert and upstream servers
    bundle_path = ca.create_ca_bundle()
    ca_path = str(bundle_path) if bundle_path else str(ca.ca_cert_path)

    # Start secretgate in background
    proxy_url = f"http://localhost:{forward_proxy_port}"
    click.echo(
        f"Starting secretgate (port {port}, forward proxy {forward_proxy_port}, mode {mode})..."
    )

    # On Windows, create a new process group so we can kill the entire tree
    popen_kwargs = {}
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

    import shutil

    # Find the secretgate binary — prefer the same entry point that invoked us
    secretgate_bin = shutil.which("secretgate") or sys.executable
    server_cmd = (
        [secretgate_bin, "serve"]
        if secretgate_bin != sys.executable
        else [sys.executable, "-m", "secretgate", "serve"]
    )
    # Set up log file for server output
    log_fh = None
    if log_path is not None:
        log_fh = open(log_path, "a")  # noqa: SIM115

    if verbose and log_fh is not None:
        stderr_target = subprocess.PIPE
    elif log_fh is not None:
        stderr_target = log_fh
    else:
        stderr_target = subprocess.DEVNULL

    stdout_target = log_fh if log_fh is not None else subprocess.DEVNULL

    try:
        server_proc = subprocess.Popen(
            [
                *server_cmd,
                "--port",
                str(port),
                "--forward-proxy-port",
                str(forward_proxy_port),
                "--mode",
                mode,
            ],
            stdout=stdout_target,
            stderr=stderr_target,
            **popen_kwargs,
        )
    except Exception:
        if log_fh is not None:
            log_fh.close()
        raise

    # If verbose, tee stderr to both log file and terminal
    tee_thread = None
    if verbose and log_fh is not None and server_proc.stderr:
        import threading

        def _tee_stderr():
            try:
                for line in iter(server_proc.stderr.readline, b""):
                    sys.stderr.buffer.write(line)
                    sys.stderr.buffer.flush()
                    log_fh.write(line.decode("utf-8", errors="replace"))
                    log_fh.flush()
            except (ValueError, OSError):
                pass  # file closed during shutdown

        tee_thread = threading.Thread(target=_tee_stderr, daemon=True)
        tee_thread.start()

    def _cleanup_server():
        """Kill the server process — registered with atexit for robustness."""
        if server_proc.poll() is None:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()
                server_proc.wait(timeout=2)
        if log_fh is not None:
            try:
                log_fh.close()
            except (OSError, ValueError):
                pass

    atexit.register(_cleanup_server)

    # Wait for proxy to be ready
    for _ in range(50):
        # Check if the server process died early
        if server_proc.poll() is not None:
            click.echo(
                f"Error: secretgate exited unexpectedly (code {server_proc.returncode})", err=True
            )
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect(("127.0.0.1", forward_proxy_port))
            sock.close()
            break
        except (ConnectionRefusedError, OSError):
            sock.close()
            time.sleep(0.1)
    else:
        click.echo("Error: secretgate failed to start", err=True)
        _cleanup_server()
        return

    click.echo(f"secretgate running (PID {server_proc.pid})")
    if log_path is not None:
        click.echo(f"Logs: {log_path}")

    # Run the command with proxy env vars
    env = os.environ.copy()
    env.update(
        {
            "https_proxy": proxy_url,
            "http_proxy": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "HTTP_PROXY": proxy_url,
            "SSL_CERT_FILE": ca_path,
            "REQUESTS_CA_BUNDLE": ca_path,
            "NODE_EXTRA_CA_CERTS": ca_path,
            "GIT_SSL_CAINFO": ca_path,
            "no_proxy": "",
        }
    )

    try:
        result = subprocess.run(list(command), env=env)
        raise SystemExit(result.returncode)
    except KeyboardInterrupt:
        pass
    finally:
        _cleanup_server()
        click.echo("secretgate stopped.")


@main.group()
def ca():
    """Manage the secretgate CA certificate."""
    pass


@ca.command("init")
@click.option(
    "--certs-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Directory for CA certs (default: ~/.secretgate/certs)",
)
def ca_init(certs_dir: Path | None):
    """Generate a new CA certificate (if one doesn't exist)."""
    from secretgate.certs import CertAuthority

    authority = CertAuthority(certs_dir)
    authority.ensure_ca()
    bundle = authority.create_ca_bundle()
    click.echo(f"CA certificate: {authority.ca_cert_path}")
    if bundle:
        click.echo(f"CA bundle (system + secretgate): {bundle}")


@ca.command("path")
@click.option(
    "--certs-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Directory for CA certs (default: ~/.secretgate/certs)",
)
def ca_path(certs_dir: Path | None):
    """Print the path to the CA certificate."""
    from secretgate.certs import CertAuthority

    authority = CertAuthority(certs_dir)
    click.echo(authority.ca_cert_path)


@ca.command("trust")
def ca_trust():
    """Print OS-specific instructions for trusting the CA certificate."""
    import platform

    from secretgate.certs import CertAuthority

    authority = CertAuthority()
    cert_path = authority.ca_cert_path

    click.echo(f"CA certificate: {cert_path}\n")

    system = platform.system()
    if system == "Darwin":
        click.echo("macOS — add to system keychain:")
        click.echo("  sudo security add-trusted-cert -d -r trustRoot \\")
        click.echo(f"    -k /Library/Keychains/System.keychain {cert_path}")
    elif system == "Linux":
        click.echo("Ubuntu/Debian:")
        click.echo(f"  sudo cp {cert_path} /usr/local/share/ca-certificates/secretgate.crt")
        click.echo("  sudo update-ca-certificates")
        click.echo()
        click.echo("Fedora/RHEL:")
        click.echo(f"  sudo cp {cert_path} /etc/pki/ca-trust/source/anchors/secretgate.crt")
        click.echo("  sudo update-ca-trust")
    elif system == "Windows":
        click.echo("Windows (PowerShell as Administrator):")
        click.echo(
            f'  Import-Certificate -FilePath "{cert_path}" -CertStoreLocation Cert:\\LocalMachine\\Root'
        )
    else:
        click.echo(f"Add {cert_path} to your system's trusted CA store.")

    bundle_path = authority.ca_bundle_path
    click.echo()
    if system == "Windows":
        click.echo("For all tools (combined bundle — recommended, PowerShell):")
        click.echo(f'  $env:SSL_CERT_FILE="{bundle_path}"')
        click.echo(f'  $env:REQUESTS_CA_BUNDLE="{bundle_path}"')
        click.echo(f'  $env:GIT_SSL_CAINFO="{bundle_path}"')
        click.echo(f'  $env:NODE_EXTRA_CA_CERTS="{cert_path}"')
    else:
        click.echo("For all tools (combined bundle — recommended):")
        click.echo(f"  export SSL_CERT_FILE={bundle_path}")
        click.echo(f"  export REQUESTS_CA_BUNDLE={bundle_path}")
        click.echo(f"  export GIT_SSL_CAINFO={bundle_path}")
        click.echo(f"  export NODE_EXTRA_CA_CERTS={cert_path}")
        click.echo()
        click.echo("Or install the CA system-wide (no env vars needed):")


@main.group()
def firewall():
    """Generate firewall rules to prevent proxy bypass (issue #33)."""
    pass


@firewall.command("show")
@click.option(
    "--forward-proxy-port",
    "-f",
    default=8083,
    type=int,
    help="Forward proxy port",
)
@click.option("--user", "-u", default=None, help="Restrict rules to this OS user")
@click.option(
    "--domain",
    "-d",
    multiple=True,
    help="Only block specific domains (can be repeated; default: block all port 443)",
)
@click.option(
    "--tool",
    type=click.Choice(["iptables", "nftables", "pf", "auto"]),
    default="auto",
    help="Firewall tool (default: auto-detect)",
)
def firewall_show(forward_proxy_port: int, user: str | None, domain: tuple, tool: str):
    """Print firewall rules for the current platform.

    These rules block direct outbound HTTPS connections, forcing all
    traffic through the secretgate proxy. This prevents AI tools from
    bypassing the proxy by unsetting env vars.

    \b
    Examples:
        secretgate firewall show
        secretgate firewall show --tool iptables
        secretgate firewall show -d api.anthropic.com -d api.openai.com
    """
    from secretgate.firewall import generate_rules

    domains = list(domain) if domain else None
    rules = generate_rules(
        proxy_port=forward_proxy_port,
        user=user,
        domains=domains,
        tool=None if tool == "auto" else tool,
    )
    click.echo(rules)


if __name__ == "__main__":
    main()
