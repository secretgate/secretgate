"""Tests for the reverse proxy (proxy.py + server.py integration)."""

from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from secretgate.config import ProviderConfig
from secretgate.pipeline import Pipeline, PipelineContext, PipelineStep
from secretgate.proxy import create_provider_router
from secretgate.server import AppState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class PassthroughStep(PipelineStep):
    """Pipeline step that passes everything through unchanged."""

    async def process_request(self, body: dict, ctx: PipelineContext) -> dict:
        return body


class RecordingStep(PipelineStep):
    """Pipeline step that records what it sees for assertions."""

    def __init__(self):
        self.requests: list[dict] = []
        self.responses: list[dict] = []

    async def process_request(self, body: dict, ctx: PipelineContext) -> dict:
        self.requests.append(body)
        return body

    async def process_response(self, body: dict, ctx: PipelineContext) -> dict:
        self.responses.append(body)
        return body


class BlockingStep(PipelineStep):
    """Pipeline step that blocks all requests."""

    async def process_request(self, body: dict, ctx: PipelineContext) -> dict | None:
        ctx.alerts.append("blocked-secret")
        return None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# A fake upstream that records requests and returns canned responses.
# We use httpx.MockTransport so we don't need a real server.


def _make_upstream_handler(responses: dict | None = None):
    """Create an httpx transport handler that records requests.

    ``responses`` maps path suffixes to (status, body) tuples.
    """
    recorded: list[httpx.Request] = []
    default_responses = responses or {}

    def handler(request: httpx.Request) -> httpx.Response:
        recorded.append(request)
        path = request.url.path

        for suffix, (status, body) in default_responses.items():
            if path.endswith(suffix):
                return httpx.Response(status, json=body)

        # Default: echo the request body back
        try:
            req_body = json.loads(request.content)
            return httpx.Response(200, json={"echo": req_body})
        except (json.JSONDecodeError, UnicodeDecodeError):
            return httpx.Response(200, content=request.content)

    return handler, recorded


@pytest.fixture
def upstream():
    """Provide an upstream handler + recorded requests list."""
    handler, recorded = _make_upstream_handler()
    return handler, recorded


@pytest.fixture
def count_tokens_upstream():
    """Upstream that responds like Anthropic's count_tokens endpoint."""
    handler, recorded = _make_upstream_handler(
        {"/v1/messages/count_tokens": (200, {"input_tokens": 42})}
    )
    return handler, recorded


def _build_app(upstream_handler, pipeline: Pipeline | None = None) -> TestClient:
    """Build a minimal FastAPI app with one 'test' provider backed by a mock transport."""
    from fastapi import FastAPI

    state = AppState()
    state.http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))

    pipe = pipeline or Pipeline(steps=[PassthroughStep()])
    provider = ProviderConfig(name="anthropic", base_url="https://api.anthropic.com")

    app = FastAPI()
    router = create_provider_router(provider, pipe, state)
    app.include_router(router)

    return TestClient(app)


# ---------------------------------------------------------------------------
# Tests: /v1/messages/count_tokens
# ---------------------------------------------------------------------------


class TestCountTokens:
    """Verify that the count_tokens endpoint is proxied correctly."""

    def test_count_tokens_forwarded(self, count_tokens_upstream):
        handler, recorded = count_tokens_upstream
        client = _build_app(handler)

        body = {
            "model": "claude-sonnet-4-20250514",
            "messages": [{"role": "user", "content": "Hello"}],
        }
        resp = client.post(
            "/anthropic/v1/messages/count_tokens",
            json=body,
        )

        assert resp.status_code == 200
        assert resp.json() == {"input_tokens": 42}

        # Verify the request reached the correct upstream path
        assert len(recorded) == 1
        assert recorded[0].url.path == "/v1/messages/count_tokens"

    def test_count_tokens_request_scanned(self, count_tokens_upstream):
        """Pipeline steps should see the count_tokens request body."""
        handler, _ = count_tokens_upstream
        recorder = RecordingStep()
        client = _build_app(handler, Pipeline(steps=[recorder]))

        body = {
            "model": "claude-sonnet-4-20250514",
            "messages": [{"role": "user", "content": "my key is AKIAIOSFODNN7EXAMPLE"}],
        }
        client.post("/anthropic/v1/messages/count_tokens", json=body)

        assert len(recorder.requests) == 1
        assert recorder.requests[0]["model"] == "claude-sonnet-4-20250514"

    def test_count_tokens_response_passed_through(self, count_tokens_upstream):
        """Pipeline response processing should run on count_tokens responses."""
        handler, _ = count_tokens_upstream
        recorder = RecordingStep()
        client = _build_app(handler, Pipeline(steps=[recorder]))

        body = {
            "model": "claude-sonnet-4-20250514",
            "messages": [{"role": "user", "content": "Hello"}],
        }
        resp = client.post("/anthropic/v1/messages/count_tokens", json=body)

        assert resp.status_code == 200
        assert len(recorder.responses) == 1
        assert recorder.responses[0] == {"input_tokens": 42}


# ---------------------------------------------------------------------------
# Tests: query string forwarding
# ---------------------------------------------------------------------------


class TestQueryStringForwarding:
    def test_query_params_forwarded_on_get(self, upstream):
        handler, recorded = upstream
        client = _build_app(handler)

        client.get("/anthropic/v1/models?limit=10&order=desc")

        assert len(recorded) == 1
        assert recorded[0].url.query == b"limit=10&order=desc"

    def test_query_params_forwarded_on_post(self, upstream):
        handler, recorded = upstream
        client = _build_app(handler)

        client.post(
            "/anthropic/v1/messages?beta=true",
            json={"model": "test", "messages": []},
        )

        assert len(recorded) == 1
        assert b"beta=true" in recorded[0].url.query

    def test_no_query_string_no_question_mark(self, upstream):
        handler, recorded = upstream
        client = _build_app(handler)

        client.get("/anthropic/v1/models")

        assert len(recorded) == 1
        assert recorded[0].url.query == b""


# ---------------------------------------------------------------------------
# Tests: general reverse proxy behaviour
# ---------------------------------------------------------------------------


class TestProxyRouting:
    def test_json_post_goes_through_pipeline(self, upstream):
        handler, recorded = upstream
        recorder = RecordingStep()
        client = _build_app(handler, Pipeline(steps=[recorder]))

        body = {"model": "test-model", "messages": [{"role": "user", "content": "hi"}]}
        resp = client.post("/anthropic/v1/messages", json=body)

        assert resp.status_code == 200
        assert len(recorder.requests) == 1
        assert recorder.requests[0]["model"] == "test-model"

    def test_get_skips_pipeline(self, upstream):
        handler, _ = upstream
        recorder = RecordingStep()
        client = _build_app(handler, Pipeline(steps=[recorder]))

        resp = client.get("/anthropic/v1/models")

        assert resp.status_code == 200
        assert len(recorder.requests) == 0  # pipeline not invoked

    def test_non_json_post_skips_pipeline(self, upstream):
        handler, recorded = upstream
        recorder = RecordingStep()
        client = _build_app(handler, Pipeline(steps=[recorder]))

        resp = client.post(
            "/anthropic/v1/something",
            content=b"plain text body",
            headers={"content-type": "text/plain"},
        )

        assert resp.status_code == 200
        assert len(recorder.requests) == 0

    def test_pipeline_block_returns_403(self, upstream):
        handler, recorded = upstream
        client = _build_app(handler, Pipeline(steps=[BlockingStep()]))

        resp = client.post(
            "/anthropic/v1/messages",
            json={"model": "test", "messages": []},
        )

        assert resp.status_code == 403
        data = resp.json()
        assert data["error"]["type"] == "security_block"
        assert len(recorded) == 0  # request never reached upstream

    def test_arbitrary_subpath_forwarded(self, upstream):
        handler, recorded = upstream
        client = _build_app(handler)

        client.post(
            "/anthropic/v1/messages/batches",
            json={"requests": []},
        )

        assert len(recorded) == 1
        assert recorded[0].url.path == "/v1/messages/batches"

    def test_auth_endpoints_skip_pipeline(self, upstream):
        handler, _ = upstream
        recorder = RecordingStep()
        client = _build_app(handler, Pipeline(steps=[recorder]))

        resp = client.post(
            "/anthropic/oauth/token",
            json={"grant_type": "authorization_code"},
        )

        assert resp.status_code == 200
        assert len(recorder.requests) == 0

    def test_unparseable_json_forwarded_raw(self, upstream):
        handler, recorded = upstream
        recorder = RecordingStep()
        client = _build_app(handler, Pipeline(steps=[recorder]))

        resp = client.post(
            "/anthropic/v1/messages",
            content=b"{invalid json",
            headers={"content-type": "application/json"},
        )

        assert resp.status_code == 200
        assert len(recorder.requests) == 0  # pipeline not invoked
        assert len(recorded) == 1  # but upstream was hit


class TestStreamDetection:
    def test_non_streaming_uses_buffered(self, upstream):
        handler, recorded = upstream
        recorder = RecordingStep()
        client = _build_app(handler, Pipeline(steps=[recorder]))

        body = {"model": "test", "messages": [], "stream": False}
        resp = client.post("/anthropic/v1/messages", json=body)

        assert resp.status_code == 200
        # Response pipeline should have run (buffered path)
        assert len(recorder.responses) == 1

    def test_streaming_request_detected(self, upstream):
        """When stream=True, the proxy should use the streaming path."""
        handler, recorded = upstream
        client = _build_app(handler)

        body = {"model": "test", "messages": [], "stream": True}
        resp = client.post("/anthropic/v1/messages", json=body)

        # The mock transport doesn't produce SSE, but the request should succeed
        assert resp.status_code == 200


class TestStreamingFirstChunkErrorDetection:
    """Issue #23: upstream errors on streaming requests should return proper HTTP status codes."""

    def test_streaming_upstream_error_returns_proper_status(self):
        """When upstream returns 429 on a streaming request, client gets 429 not 200."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                429,
                json={"error": {"type": "rate_limit_error", "message": "Too many requests"}},
            )

        client = _build_app(handler)
        body = {"model": "test", "messages": [], "stream": True}
        resp = client.post("/anthropic/v1/messages", json=body)

        assert resp.status_code == 429
        data = resp.json()
        assert data["error"]["type"] == "rate_limit_error"

    def test_streaming_upstream_401_returns_401(self):
        """Unauthorized errors are surfaced with correct status."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401,
                json={"error": {"type": "authentication_error", "message": "Invalid API key"}},
            )

        client = _build_app(handler)
        body = {"model": "test", "messages": [], "stream": True}
        resp = client.post("/anthropic/v1/messages", json=body)

        assert resp.status_code == 401
        data = resp.json()
        assert data["error"]["type"] == "authentication_error"

    def test_streaming_upstream_500_returns_500(self):
        """Server errors from upstream are surfaced properly."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                500,
                json={"error": {"type": "api_error", "message": "Internal server error"}},
            )

        client = _build_app(handler)
        body = {"model": "test", "messages": [], "stream": True}
        resp = client.post("/anthropic/v1/messages", json=body)

        assert resp.status_code == 500

    def test_streaming_upstream_non_json_error(self):
        """Non-JSON error responses are still returned with correct status."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(502, text="Bad Gateway")

        client = _build_app(handler)
        body = {"model": "test", "messages": [], "stream": True}
        resp = client.post("/anthropic/v1/messages", json=body)

        assert resp.status_code == 502

    def test_streaming_upstream_200_streams_normally(self):
        """When upstream returns 200, streaming works as before."""

        def handler(request: httpx.Request) -> httpx.Response:
            req_body = json.loads(request.content)
            return httpx.Response(200, json={"echo": req_body})

        client = _build_app(handler)
        body = {"model": "test", "messages": [], "stream": True}
        resp = client.post("/anthropic/v1/messages", json=body)

        assert resp.status_code == 200


class TestMidStreamErrorHandling:
    """Issue #18: mid-stream errors should emit clean SSE termination events."""

    def test_sse_error_termination_format(self):
        """The error termination helper produces valid SSE events."""
        from secretgate.proxy import _sse_error_termination

        result = _sse_error_termination("connection reset")
        text = result.decode("utf-8")

        assert "event: error\n" in text
        assert '"type": "stream_error"' in text
        assert "connection reset" in text
        assert "data: [DONE]" in text
