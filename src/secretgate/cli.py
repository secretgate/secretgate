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
@click.option("--signatures", "-s", type=click.Path(exists=True, path_type=Path), help="Custom signatures YAML")
@click.option("--log-level", default="info", type=click.Choice(["debug", "info", "warning", "error"]))
@click.option("--log-format", default="text", type=click.Choice(["text", "json"]))
@click.option("--detect-secrets", "use_detect_secrets", is_flag=True, help="Enable detect-secrets plugins for extra coverage")
def serve(
    port: int,
    host: str,
    mode: str,
    config: Path | None,
    signatures: Path | None,
    log_level: str,
    log_format: str,
    use_detect_secrets: bool,
):
    """Start the secretgate proxy server."""
    from secretgate.config import Config
    from secretgate.server import create_app

    # Configure logging
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(structlog, log_level.upper(), structlog.INFO)
        ),
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

    app = create_app(cfg)
    uvicorn.run(app, host=cfg.host, port=cfg.port, log_level=log_level)


@main.command()
@click.option("--detect-secrets", "use_detect_secrets", is_flag=True, help="Enable detect-secrets plugins for extra coverage")
def scan(use_detect_secrets: bool):
    """Scan stdin for secrets (offline mode)."""
    import sys
    from secretgate.secrets.scanner import SecretScanner

    scanner = SecretScanner(use_detect_secrets=use_detect_secrets)
    text = sys.stdin.read()
    matches = scanner.scan(text)

    if not matches:
        click.echo("No secrets found.")
        return

    for m in matches:
        # Show truncated value for safety
        preview = m.value[:8] + "..." if len(m.value) > 8 else m.value
        click.echo(f"  Line {m.line_number}: [{m.service}] {m.pattern_name} — {preview}")

    click.echo(f"\n{len(matches)} secret(s) found.")
    sys.exit(1)


if __name__ == "__main__":
    main()
