"""CLI entry point — keep it simple."""

from __future__ import annotations

from pathlib import Path

import click
import structlog
import uvicorn


@click.group()
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

    app = create_app(cfg)
    uvicorn.run(app, host=cfg.host, port=cfg.port, log_level=log_level)


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
@click.argument("files", nargs=-1, type=click.Path(exists=True))
def scan(use_detect_secrets: bool, no_entropy: bool, files: tuple[str, ...]):
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
    )
    total_matches = []

    if files:
        for filepath in files:
            with open(filepath) as f:
                text = f.read()
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
@click.pass_context
def wrap(ctx, forward_proxy_port: int, port: int, mode: str):
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
    import os
    import subprocess
    import time

    from secretgate.certs import CertAuthority

    # Get command from remaining args, strip leading "--"
    command = ctx.args
    if command and command[0] == "--":
        command = command[1:]

    if not command:
        click.echo("Usage: secretgate wrap -- <command> [args...]")
        click.echo("Example: secretgate wrap -- claude")
        return

    # Ensure CA exists
    ca = CertAuthority()
    ca.ensure_ca()
    ca_path = str(ca.ca_cert_path)

    # Start secretgate in background
    proxy_url = f"http://localhost:{forward_proxy_port}"
    click.echo(
        f"Starting secretgate (port {port}, forward proxy {forward_proxy_port}, mode {mode})..."
    )

    server_proc = subprocess.Popen(
        [
            "secretgate",
            "serve",
            "--port",
            str(port),
            "--forward-proxy-port",
            str(forward_proxy_port),
            "--mode",
            mode,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    # Wait for proxy to be ready
    for _ in range(50):
        import socket

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect(("127.0.0.1", forward_proxy_port))
            sock.close()
            break
        except (ConnectionRefusedError, OSError):
            time.sleep(0.1)
    else:
        click.echo("Error: secretgate failed to start", err=True)
        server_proc.kill()
        return

    click.echo(f"secretgate running (PID {server_proc.pid})")

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
            "no_proxy": "",
        }
    )

    try:
        result = subprocess.run(list(command), env=env)
        raise SystemExit(result.returncode)
    except KeyboardInterrupt:
        pass
    finally:
        server_proc.terminate()
        try:
            server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_proc.kill()
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
    click.echo(f"CA certificate: {authority.ca_cert_path}")


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

    click.echo()
    if system == "Windows":
        click.echo("For Python/httpx/requests (PowerShell):")
        click.echo(f'  $env:SSL_CERT_FILE="{cert_path}"')
        click.echo(f'  $env:REQUESTS_CA_BUNDLE="{cert_path}"')
        click.echo()
        click.echo("For Node.js (PowerShell):")
        click.echo(f'  $env:NODE_EXTRA_CA_CERTS="{cert_path}"')
    else:
        click.echo("For Python/httpx/requests:")
        click.echo(f"  export SSL_CERT_FILE={cert_path}")
        click.echo(f"  export REQUESTS_CA_BUNDLE={cert_path}")
        click.echo()
        click.echo("For Node.js:")
        click.echo(f"  export NODE_EXTRA_CA_CERTS={cert_path}")


if __name__ == "__main__":
    main()
