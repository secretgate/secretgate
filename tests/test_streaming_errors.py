"""Tests for graceful error handling during streaming responses (Issue #18)."""

import json
import pytest
import httpx

from secretgate.pipeline import Pipeline, PipelineContext
from secretgate.proxy import _forward_streaming


@pytest.mark.asyncio
async def test_streaming_error_emits_graceful_termination():
    """When the upstream stream fails mid-way, the proxy should emit
    SSE error + [DONE] events instead of dropping the connection."""

    class _FakeStream:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def aiter_bytes(self):
            yield b'data: {"type": "content_block_delta"}\n\n'
            raise httpx.ReadError("connection reset")

    class _FakeClient:
        def stream(self, method, url, **kwargs):
            return _FakeStream()

    pipeline = Pipeline(steps=[])
    ctx = PipelineContext()
    body = json.dumps({"stream": True}).encode()
    headers = {"content-type": "application/json"}

    response = await _forward_streaming(
        body,
        "https://api.example.com/v1/chat",
        headers,
        _FakeClient(),
        pipeline,
        ctx,
    )

    chunks = []
    async for chunk in response.body_iterator:
        if isinstance(chunk, bytes):
            chunks.append(chunk)
        else:
            chunks.append(chunk.encode("utf-8"))

    combined = b"".join(chunks).decode("utf-8")

    assert "content_block_delta" in combined
    assert "event: error" in combined
    assert "proxy_error" in combined
    assert "[DONE]" in combined


@pytest.mark.asyncio
async def test_streaming_success_no_error_events():
    """Successful streams should NOT contain error termination events."""

    class _FakeStream:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def aiter_bytes(self):
            yield b'data: {"type": "content_block_delta"}\n\n'
            yield b'data: {"type": "message_stop"}\n\n'
            yield b"data: [DONE]\n\n"

    class _FakeClient:
        def stream(self, method, url, **kwargs):
            return _FakeStream()

    pipeline = Pipeline(steps=[])
    ctx = PipelineContext()
    body = json.dumps({"stream": True}).encode()
    headers = {"content-type": "application/json"}

    response = await _forward_streaming(
        body,
        "https://api.example.com/v1/chat",
        headers,
        _FakeClient(),
        pipeline,
        ctx,
    )

    chunks = []
    async for chunk in response.body_iterator:
        if isinstance(chunk, bytes):
            chunks.append(chunk)
        else:
            chunks.append(chunk.encode("utf-8"))

    combined = b"".join(chunks).decode("utf-8")

    assert "content_block_delta" in combined
    assert "message_stop" in combined
    assert "event: error" not in combined


@pytest.mark.asyncio
async def test_streaming_error_on_connect():
    """When the upstream connection fails immediately, the proxy should
    still emit graceful SSE termination."""

    class _FakeStream:
        async def __aenter__(self):
            raise httpx.ConnectError("connection refused")

        async def __aexit__(self, *args):
            pass

        async def aiter_bytes(self):
            yield b""  # pragma: no cover

    class _FakeClient:
        def stream(self, method, url, **kwargs):
            return _FakeStream()

    pipeline = Pipeline(steps=[])
    ctx = PipelineContext()
    body = json.dumps({"stream": True}).encode()
    headers = {"content-type": "application/json"}

    response = await _forward_streaming(
        body,
        "https://api.example.com/v1/chat",
        headers,
        _FakeClient(),
        pipeline,
        ctx,
    )

    chunks = []
    async for chunk in response.body_iterator:
        if isinstance(chunk, bytes):
            chunks.append(chunk)
        else:
            chunks.append(chunk.encode("utf-8"))

    combined = b"".join(chunks).decode("utf-8")

    assert "event: error" in combined
    assert "[DONE]" in combined
