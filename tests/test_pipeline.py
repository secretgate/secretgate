"""Tests for the pipeline and steps."""

import json
import pytest

from secretgate.pipeline import Pipeline, PipelineContext
from secretgate.secrets.scanner import SecretScanner
from secretgate.steps import SecretRedactionStep, _is_thinking_sse_data


@pytest.mark.asyncio
async def test_redaction_step_redacts_openai_format():
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="redact")
    ctx = PipelineContext()

    body = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "My key is AKIAIOSFODNN7EXAMPLE"}],
    }

    result = await step.process_request(body, ctx)
    assert result is not None
    assert "AKIAIOSFODNN7EXAMPLE" not in result["messages"][0]["content"]
    assert ctx.secrets_found >= 1


@pytest.mark.asyncio
async def test_redaction_step_redacts_anthropic_format():
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="redact")
    ctx = PipelineContext()

    body = {
        "model": "claude-sonnet-4-6",
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": "My key is AKIAIOSFODNN7EXAMPLE"}],
            }
        ],
    }

    result = await step.process_request(body, ctx)
    assert result is not None
    text = result["messages"][0]["content"][0]["text"]
    assert "AKIAIOSFODNN7EXAMPLE" not in text


@pytest.mark.asyncio
async def test_block_mode_returns_none():
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="block")
    ctx = PipelineContext()

    body = {"messages": [{"role": "user", "content": "Key: AKIAIOSFODNN7EXAMPLE"}]}

    result = await step.process_request(body, ctx)
    assert result is None


@pytest.mark.asyncio
async def test_audit_mode_passes_through():
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="audit")
    ctx = PipelineContext()

    body = {"messages": [{"role": "user", "content": "Key: AKIAIOSFODNN7EXAMPLE"}]}

    result = await step.process_request(body, ctx)
    assert result is not None
    # In audit mode, the secret should NOT be redacted
    assert "AKIAIOSFODNN7EXAMPLE" in result["messages"][0]["content"]


@pytest.mark.asyncio
async def test_pipeline_runs_steps_in_order():
    scanner = SecretScanner()
    pipeline = Pipeline(steps=[SecretRedactionStep(scanner, mode="redact")])
    ctx = PipelineContext()

    body = {"messages": [{"role": "user", "content": "AKIAIOSFODNN7EXAMPLE"}]}

    result = await pipeline.run_request(body, ctx)
    assert result is not None
    assert "AKIAIOSFODNN7EXAMPLE" not in result["messages"][0]["content"]


@pytest.mark.asyncio
async def test_clean_request_passes_through():
    scanner = SecretScanner()
    pipeline = Pipeline(steps=[SecretRedactionStep(scanner, mode="redact")])
    ctx = PipelineContext()

    body = {"messages": [{"role": "user", "content": "just normal code here"}]}

    result = await pipeline.run_request(body, ctx)
    assert result == body
    assert ctx.secrets_found == 0


@pytest.mark.asyncio
async def test_thinking_block_signature_not_corrupted_by_unredact():
    """_unredact_body must not touch thinking blocks.

    Anthropic's signature covers the thinking content verbatim; if we replace
    a placeholder back to the original secret inside a thinking block, the
    signature becomes invalid on the next turn.
    """
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="redact")
    ctx = PipelineContext()

    secret = "AKIAIOSFODNN7EXAMPLE"
    fake_signature = "EqoBCkgIARAAGg4KDmFwaS5hbnRocm9waWM"

    request_body = {"messages": [{"role": "user", "content": f"My key is {secret}"}]}
    await step.process_request(request_body, ctx)
    # redactor is now populated with the secret → placeholder mapping
    redactor = ctx.metadata["redactor"]
    placeholder = list(redactor._store.keys())[0]  # e.g. REDACTED<aws-access-key:abc123>

    # Simulate: Anthropic reproduced the placeholder in its thinking and text response.
    response_body = {
        "content": [
            {
                "type": "thinking",
                "thinking": f"The user's key is {placeholder}",
                "signature": fake_signature,
            },
            {"type": "text", "text": f"I see you have {placeholder}"},
        ]
    }

    result = step._unredact_body(response_body, ctx)

    # The thinking content must be unchanged (signature covers it)
    assert result["content"][0]["thinking"] == f"The user's key is {placeholder}"
    assert result["content"][0]["signature"] == fake_signature

    # The text block SHOULD have the secret restored
    assert secret in result["content"][1]["text"]


@pytest.mark.asyncio
async def test_thinking_sse_events_not_unredacted():
    """process_response_chunk must not modify thinking-block SSE events."""
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="redact")
    ctx = PipelineContext()

    secret = "AKIAIOSFODNN7EXAMPLE"
    request_body = {"messages": [{"role": "user", "content": f"Key: {secret}"}]}
    await step.process_request(request_body, ctx)

    # Build an SSE chunk with a thinking_delta event
    redactor = ctx.metadata["redactor"]
    placeholder = list(redactor._store.keys())[0]

    thinking_event = json.dumps(
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "thinking_delta", "thinking": f"The key is {placeholder}"},
        }
    )
    text_event = json.dumps(
        {
            "type": "content_block_delta",
            "index": 1,
            "delta": {"type": "text_delta", "text": f"The key is {placeholder}"},
        }
    )

    chunk = (f"data: {thinking_event}\n\ndata: {text_event}\n\n").encode()
    result = await step.process_response_chunk(chunk, ctx)
    decoded = result.decode()

    # thinking_delta line: placeholder must NOT be replaced
    thinking_line = [line for line in decoded.splitlines() if "thinking_delta" in line][0]
    assert placeholder in thinking_line

    # text_delta line: placeholder SHOULD be replaced with the original secret
    text_line = [line for line in decoded.splitlines() if "text_delta" in line][0]
    assert secret in text_line


def test_is_thinking_sse_data():
    assert _is_thinking_sse_data(
        json.dumps(
            {"type": "content_block_start", "content_block": {"type": "thinking", "thinking": ""}}
        )
    )
    assert _is_thinking_sse_data(
        json.dumps(
            {"type": "content_block_delta", "delta": {"type": "thinking_delta", "thinking": "x"}}
        )
    )
    assert _is_thinking_sse_data(
        json.dumps(
            {"type": "content_block_delta", "delta": {"type": "signature_delta", "signature": "x"}}
        )
    )
    assert not _is_thinking_sse_data(
        json.dumps({"type": "content_block_delta", "delta": {"type": "text_delta", "text": "x"}})
    )
    assert not _is_thinking_sse_data("[DONE]")
