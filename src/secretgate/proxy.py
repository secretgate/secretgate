"""Reverse proxy core — the heart of secretgate.

For each registered provider, we mount routes that:
1. Accept the request from the AI coding tool
2. Run it through the pipeline (secret scanning, etc.)
3. Forward to the real provider API
4. Stream the response back through the pipeline
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, AsyncIterator

import httpx
import structlog
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from secretgate.config import ProviderConfig
from secretgate.forward import _AUTH_PATH_PATTERNS
from secretgate.pipeline import Pipeline, PipelineContext

if TYPE_CHECKING:
    from secretgate.server import AppState

logger = structlog.get_logger()


def create_provider_router(
    provider: ProviderConfig,
    pipeline: Pipeline,
    state: AppState,
) -> APIRouter:
    """Create a FastAPI router that proxies all requests for a provider."""
    router = APIRouter(prefix=f"/{provider.name}")

    @router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def proxy(request: Request, path: str):
        upstream_url = f"{provider.base_url.rstrip('/')}/{path}"
        if request.url.query:
            upstream_url = f"{upstream_url}?{request.url.query}"

        # Forward headers, replacing host
        headers = dict(request.headers)
        headers.pop("host", None)
        headers.pop("content-length", None)

        # For non-JSON, GET, or auth/token endpoints, pass through directly
        if (
            request.method == "GET"
            or "application/json" not in request.headers.get("content-type", "")
            or _AUTH_PATH_PATTERNS.search(f"/{path}")
        ):
            return await _passthrough(request, upstream_url, headers, state.http_client)

        # Parse JSON body
        raw_body = await request.body()
        try:
            body = json.loads(raw_body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return await _forward_raw(raw_body, upstream_url, headers, state.http_client)

        # Run request pipeline
        ctx = PipelineContext()
        result = await pipeline.run_request(body, ctx)

        if result is None:
            # Pipeline blocked the request
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": f"Request blocked by secretgate: {len(ctx.alerts)} secret(s) detected",
                        "type": "security_block",
                        "alerts": ctx.alerts,
                    }
                },
            )

        is_streaming = result.get("stream", False)
        modified_body = json.dumps(result).encode("utf-8")
        headers["content-length"] = str(len(modified_body))

        if is_streaming:
            return await _forward_streaming(
                modified_body, upstream_url, headers, state.http_client, pipeline, ctx
            )
        else:
            return await _forward_buffered(
                modified_body, upstream_url, headers, state.http_client, pipeline, ctx
            )

    return router


async def _passthrough(
    request: Request, url: str, headers: dict, client: httpx.AsyncClient
) -> StreamingResponse:
    """Pass non-JSON requests through without processing."""
    resp = await client.request(
        method=request.method,
        url=url,
        headers=headers,
        content=await request.body(),
    )
    return StreamingResponse(
        content=iter([resp.content]),
        status_code=resp.status_code,
        headers=dict(resp.headers),
    )


async def _forward_raw(
    body: bytes, url: str, headers: dict, client: httpx.AsyncClient
) -> StreamingResponse:
    """Forward unparseable body as-is."""
    resp = await client.request(method="POST", url=url, headers=headers, content=body)
    return StreamingResponse(
        content=iter([resp.content]),
        status_code=resp.status_code,
        headers=dict(resp.headers),
    )


async def _forward_buffered(
    body: bytes,
    url: str,
    headers: dict,
    client: httpx.AsyncClient,
    pipeline: Pipeline,
    ctx: PipelineContext,
) -> JSONResponse:
    """Forward request and process complete response through pipeline."""
    resp = await client.request(method="POST", url=url, headers=headers, content=body)

    try:
        resp_body = resp.json()
        processed = await pipeline.run_response(resp_body, ctx)
        return JSONResponse(content=processed, status_code=resp.status_code)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JSONResponse(content=resp.text, status_code=resp.status_code)


async def _forward_streaming(
    body: bytes,
    url: str,
    headers: dict,
    client: httpx.AsyncClient,
    pipeline: Pipeline,
    ctx: PipelineContext,
) -> StreamingResponse:
    """Forward request and process streaming response chunks through pipeline."""

    async def stream_chunks() -> AsyncIterator[bytes]:
        try:
            async with client.stream("POST", url, headers=headers, content=body) as resp:
                async for chunk in resp.aiter_bytes():
                    processed = await pipeline.run_response_chunk(chunk, ctx)
                    yield processed
        except Exception as exc:
            logger.error("streaming_error", error=str(exc), url=url)
            # Emit graceful SSE termination so clients see a clean end
            # instead of a broken pipe / hanging connection.
            error_events = (
                'event: error\ndata: {"type": "error", '
                '"error": {"type": "proxy_error", '
                '"message": "secretgate: upstream streaming error"}}'
                "\n\n"
                "data: [DONE]\n\n"
            )
            yield error_events.encode("utf-8")

    return StreamingResponse(content=stream_chunks(), media_type="text/event-stream")
