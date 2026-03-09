"""FastAPI app assembly — wire up providers, pipeline, and routes."""

from __future__ import annotations

import httpx
import structlog
from contextlib import asynccontextmanager
from dataclasses import dataclass
from fastapi import FastAPI

from secretgate import __version__
from secretgate.config import Config
from secretgate.pipeline import Pipeline
from secretgate.secrets.scanner import SecretScanner
from secretgate.steps import AuditLogStep, SecretRedactionStep
from secretgate.proxy import create_provider_router

logger = structlog.get_logger()


@dataclass
class AppState:
    """Shared state populated during lifespan, referenced by route handlers."""

    http_client: httpx.AsyncClient | None = None


def create_app(config: Config) -> FastAPI:
    """Build the FastAPI application."""
    state = AppState()

    # Build the scanner early so it can be shared with the forward proxy
    scanner = SecretScanner(
        signatures_path=config.signatures_path,
        entropy_threshold=config.entropy_threshold,
        use_detect_secrets=config.use_detect_secrets,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        state.http_client = httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=10.0))

        forward_server = None
        if config.forward_proxy_port:
            from secretgate.certs import CertAuthority
            from secretgate.forward import start_forward_proxy
            from secretgate.scan import TextScanner

            ca = CertAuthority(config.certs_dir)
            ca.ensure_ca()
            # Separate scanner for forward proxy: entropy disabled to avoid
            # false positives on code/JSON in raw HTTP bodies
            forward_scanner = SecretScanner(
                signatures_path=config.signatures_path,
                entropy_threshold=config.entropy_threshold,
                use_detect_secrets=config.use_detect_secrets,
                enable_entropy=False,
            )
            text_scanner = TextScanner(forward_scanner, mode=config.mode)
            forward_server = await start_forward_proxy(
                config.host,
                config.forward_proxy_port,
                ca,
                text_scanner,
                passthrough_domains=config.passthrough_domains,
            )

        logger.info(
            "secretgate_started",
            version=__version__,
            port=config.port,
            forward_proxy_port=config.forward_proxy_port,
            mode=config.mode,
            providers=list(config.providers.keys()),
        )
        yield
        if forward_server:
            forward_server.close()
            await forward_server.wait_closed()
        await state.http_client.aclose()
        logger.info("secretgate_stopped")

    app = FastAPI(
        title="secretgate",
        version=__version__,
        lifespan=lifespan,
    )

    pipeline = Pipeline(
        steps=[
            AuditLogStep(),
            SecretRedactionStep(scanner=scanner, mode=config.mode),
        ]
    )

    # Health check
    @app.get("/health")
    async def health():
        return {"status": "ok", "version": __version__}

    # Register provider routes (state.http_client is populated by lifespan before any request)
    for provider_config in config.providers.values():
        router = create_provider_router(provider_config, pipeline, state)
        app.include_router(router)
        logger.info(
            "provider_registered",
            name=provider_config.name,
            url=provider_config.base_url,
        )

    return app
