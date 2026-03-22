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
) -> StreamingResponse | JSONResponse:
    """Forward request and process streaming response chunks through pipeline.

    Peeks at the upstream HTTP status before committing to a streaming response.
    If the upstream returns an error status (4xx/5xx), returns a proper HTTP
    error response instead of streaming — ensuring clients always see correct
    status codes. (#23)

    Mid-stream errors are caught and converted to proper SSE termination events
    so clients see a graceful stream end rather than a broken pipe. (#18)
    """

    async def stream_chunks() -> AsyncIterator[bytes]:
        try:
            async with client.stream("POST", url, headers=headers, content=body) as resp:
                # If upstream returned an error, emit it as SSE error events
                # This handles the case where we've already committed to streaming
                if resp.status_code >= 400:
                    error_body = await resp.aread()
                    error_text = error_body.decode("utf-8", errors="replace")
                    logger.warning(
                        "streaming_upstream_error",
                        status=resp.status_code,
                        body=error_text[:200],
                    )
                    yield _build_sse_error(f"Upstream error {resp.status_code}: {error_text[:200]}")
                    return

                async for chunk in resp.aiter_bytes():
                    processed = await pipeline.run_response_chunk(chunk, ctx)
                    yield processed
        except (httpx.ReadError, httpx.RemoteProtocolError, httpx.StreamError) as exc:
            # Mid-stream error: emit graceful SSE termination (#18)
            logger.warning("streaming_midstream_error", error=str(exc))
            yield _build_sse_error(f"Stream interrupted: {exc}")
        except Exception as exc:
            logger.error("streaming_unexpected_error", error=str(exc))
            yield _build_sse_error(f"Internal proxy error: {exc}")

    # Peek at the upstream response status before committing to streaming (#23)
    # Use a non-streaming request first to check the status code
    try:
        async with client.stream("POST", url, headers=headers, content=body) as peek_resp:
            if peek_resp.status_code >= 400:
                # Return proper HTTP error instead of streaming
                error_body = await peek_resp.aread()
                try:
                    error_json = json.loads(error_body)
                    return JSONResponse(content=error_json, status_code=peek_resp.status_code)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return JSONResponse(
                        content={"error": {"message": error_body.decode("utf-8", errors="replace")}},
                        status_code=peek_resp.status_code,
                    )

            # Status is OK — read first chunk and start streaming
            first_chunk = None
            async for chunk in peek_resp.aiter_bytes():
                first_chunk = chunk
                break

            if first_chunk is None:
                return JSONResponse(
                    content={"error": {"message": "Empty response from upstream"}},
                    status_code=502,
                )

            # Check if first chunk contains an error (some APIs return 200 with error body)
            first_text = first_chunk.decode("utf-8", errors="replace")
            if not first_text.startswith("data:") and not first_text.startswith("event:"):
                try:
                    maybe_error = json.loads(first_text.strip())
                    if isinstance(maybe_error, dict) and "error" in maybe_error:
                        status = maybe_error.get("error", {}).get("status", 500)
                        if isinstance(status, str):
                            status = 500
                        return JSONResponse(content=maybe_error, status_code=status)
                except (json.JSONDecodeError, ValueError):
                    pass

            # Stream the rest, prepending the first chunk we already consumed
            async def stream_with_first() -> AsyncIterator[bytes]:
                try:
                    processed = await pipeline.run_response_chunk(first_chunk, ctx)
                    yield processed
                    async for chunk in peek_resp.aiter_bytes():
                        processed = await pipeline.run_response_chunk(chunk, ctx)
                        yield processed
                except (httpx.ReadError, httpx.RemoteProtocolError, httpx.StreamError) as exc:
                    logger.warning("streaming_midstream_error", error=str(exc))
                    yield _build_sse_error(f"Stream interrupted: {exc}")
                except Exception as exc:
                    logger.error("streaming_unexpected_error", error=str(exc))
                    yield _build_sse_error(f"Internal proxy error: {exc}")

            return StreamingResponse(content=stream_with_first(), media_type="text/event-stream")

    except httpx.ConnectError as exc:
        return JSONResponse(
            content={"error": {"message": f"Failed to connect to upstream: {exc}"}},
            status_code=502,
        )


def _build_sse_error(message: str) -> bytes:
    """Build SSE error termination events for graceful stream end.

    Emits an Anthropic-compatible error event followed by a generic [DONE]
    marker so both Anthropic and OpenAI clients handle the termination.
    """
    events = (
        f'event: error\ndata: {json.dumps({"type": "error", "error": {"type": "proxy_error", "message": message}})}\n\n'
        "data: [DONE]\n\n"
    )
    return events.encode("utf-8")
