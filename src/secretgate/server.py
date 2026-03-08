"""FastAPI app assembly — wire up providers, pipeline, and routes."""

from __future__ import annotations

import httpx
import structlog
from fastapi import FastAPI
from contextlib import asynccontextmanager

from secretgate import __version__
from secretgate.config import Config
from secretgate.pipeline import Pipeline
from secretgate.secrets.scanner import SecretScanner
from secretgate.steps import AuditLogStep, SecretRedactionStep
from secretgate.proxy import create_provider_router

logger = structlog.get_logger()


def create_app(config: Config) -> FastAPI:
    """Build the FastAPI application."""
    http_client: httpx.AsyncClient | None = None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        nonlocal http_client
        http_client = httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=10.0))
        logger.info(
            "secretgate_started",
            version=__version__,
            port=config.port,
            mode=config.mode,
            providers=list(config.providers.keys()),
        )
        yield
        await http_client.aclose()
        logger.info("secretgate_stopped")

    app = FastAPI(
        title="secretgate",
        version=__version__,
        lifespan=lifespan,
    )

    # Build the pipeline
    scanner = SecretScanner(
        signatures_path=config.signatures_path,
        entropy_threshold=config.entropy_threshold,
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

    # Register provider routes (deferred to use the lifespan client)
    @app.on_event("startup")
    async def _mount_providers():
        for provider_config in config.providers.values():
            router = create_provider_router(provider_config, pipeline, http_client)
            app.include_router(router)
            logger.info("provider_registered", name=provider_config.name, url=provider_config.base_url)

    return app
