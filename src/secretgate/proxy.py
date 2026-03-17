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

# ---------------------------------------------------------------------------
# SSE helpers
# ---------------------------------------------------------------------------


def _sse_error_termination(error_msg: str) -> bytes:
    """Build SSE events that gracefully terminate a stream on error.

    Emits Anthropic-style termination events so clients like Claude Code see
    a clean end-of-stream rather than a broken connection.
    """
    events = (
        f'event: error\ndata: {json.dumps({"type": "error", "error": {"type": "stream_error", "message": error_msg}})}\n\n'
        "data: [DONE]\n\n"
    )
    return events.encode("utf-8")


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
) -> StreamingResponse | JSONResponse:
    """Forward request and process streaming response chunks through pipeline.

    Peeks at the upstream status code before committing to a streaming 200.
    If the upstream returns an error (non-2xx), the full response is read and
    returned as a proper HTTP error so clients get a real status code instead
    of a 200 wrapping an error body.  (Implements #23.)
    """

    async def stream_chunks() -> AsyncIterator[bytes]:
        async with client.stream("POST", url, headers=headers, content=body) as resp:
            # If upstream returned an error, bail out early — the caller
            # already handled this via _try_stream_or_error.
            async for chunk in resp.aiter_bytes():
                processed = await pipeline.run_response_chunk(chunk, ctx)
                yield processed

    # Open the stream, peek at the status, and decide.
    req = client.build_request("POST", url, headers=headers, content=body)
    resp = await client.send(req, stream=True)

    if resp.status_code >= 400:
        # Drain the body so the connection is released, then return a real error.
        error_body = await resp.aread()
        await resp.aclose()
        try:
            error_json = json.loads(error_body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            error_json = {"error": error_body.decode("utf-8", errors="replace")}
        logger.warning(
            "upstream_stream_error",
            status=resp.status_code,
            url=url,
        )
        return JSONResponse(content=error_json, status_code=resp.status_code)

    # Happy path — upstream is 2xx, stream through the pipeline.
    # If an error occurs mid-stream (connection drop, scanning failure, etc.),
    # emit proper SSE termination events so clients see a clean end instead of
    # hanging on a broken pipe.  (Implements #18.)
    async def stream_from_resp() -> AsyncIterator[bytes]:
        try:
            async for chunk in resp.aiter_bytes():
                processed = await pipeline.run_response_chunk(chunk, ctx)
                yield processed
        except Exception as exc:
            logger.error("mid_stream_error", error=str(exc), url=url)
            # Emit graceful SSE termination so clients (Claude Code, etc.) see
            # a clean stream end rather than a broken pipe.
            yield _sse_error_termination(str(exc))
        finally:
            await resp.aclose()

    return StreamingResponse(content=stream_from_resp(), media_type="text/event-stream")
