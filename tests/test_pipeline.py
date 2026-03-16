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


# ---------------------------------------------------------------------------
# Content-block-aware scanning tests
# ---------------------------------------------------------------------------

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


@pytest.mark.asyncio
async def test_skips_assistant_text_blocks():
    """Assistant text blocks should not be scanned — model-generated content."""
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="redact")
    ctx = PipelineContext()

    body = {
        "messages": [
            {"role": "assistant", "content": f"Here is the key: {AWS_KEY}"},
        ]
    }

    result = await step.process_request(body, ctx)
    assert result is not None
    assert ctx.secrets_found == 0
    # Content should be unchanged — not scanned, not redacted
    assert result["messages"][0]["content"] == f"Here is the key: {AWS_KEY}"


@pytest.mark.asyncio
async def test_skips_tool_use_blocks():
    """tool_use blocks (assistant) should not be scanned."""
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="redact")
    ctx = PipelineContext()

    body = {
        "messages": [
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_01",
                        "name": "write_file",
                        "input": {"path": "/tmp/test", "content": AWS_KEY},
                    }
                ],
            }
        ]
    }

    result = await step.process_request(body, ctx)
    assert result is not None
    assert ctx.secrets_found == 0


@pytest.mark.asyncio
async def test_skips_thinking_blocks():
    """Thinking blocks should not be scanned (model-internal + signatures)."""
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="redact")
    ctx = PipelineContext()

    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "thinking", "thinking": f"key: {AWS_KEY}", "signature": "sig123"},
                    {"type": "text", "text": "hello"},
                ],
            }
        ]
    }

    result = await step.process_request(body, ctx)
    assert result is not None
    assert ctx.secrets_found == 0
    # Thinking block content unchanged
    assert result["messages"][0]["content"][0]["thinking"] == f"key: {AWS_KEY}"


@pytest.mark.asyncio
async def test_scans_tool_result_string_content():
    """tool_result blocks with string content should be scanned and redacted."""
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="redact")
    ctx = PipelineContext()

    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_01",
                        "content": f"Command output: {AWS_KEY}",
                    }
                ],
            }
        ]
    }

    result = await step.process_request(body, ctx)
    assert result is not None
    assert ctx.secrets_found >= 1
    assert AWS_KEY not in result["messages"][0]["content"][0]["content"]
    assert "REDACTED<" in result["messages"][0]["content"][0]["content"]


@pytest.mark.asyncio
async def test_scans_tool_result_list_content():
    """tool_result blocks with list content (text sub-blocks) should be scanned."""
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="redact")
    ctx = PipelineContext()

    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_01",
                        "content": [
                            {"type": "text", "text": f"File contains: {AWS_KEY}"},
                        ],
                    }
                ],
            }
        ]
    }

    result = await step.process_request(body, ctx)
    assert result is not None
    assert ctx.secrets_found >= 1
    sub_block = result["messages"][0]["content"][0]["content"][0]
    assert AWS_KEY not in sub_block["text"]


@pytest.mark.asyncio
async def test_scans_system_string():
    """The system field (string form) should always be scanned."""
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="redact")
    ctx = PipelineContext()

    body = {
        "system": f"System prompt with key: {AWS_KEY}",
        "messages": [{"role": "user", "content": "hello"}],
    }

    result = await step.process_request(body, ctx)
    assert result is not None
    assert ctx.secrets_found >= 1
    assert AWS_KEY not in result["system"]
    assert "REDACTED<" in result["system"]


@pytest.mark.asyncio
async def test_scans_system_content_blocks():
    """The system field (content block list form) should always be scanned."""
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="redact")
    ctx = PipelineContext()

    body = {
        "system": [{"type": "text", "text": f"Config: {AWS_KEY}"}],
        "messages": [{"role": "user", "content": "hello"}],
    }

    result = await step.process_request(body, ctx)
    assert result is not None
    assert ctx.secrets_found >= 1
    assert AWS_KEY not in result["system"][0]["text"]


@pytest.mark.asyncio
async def test_skips_image_blocks():
    """Image blocks should not be scanned."""
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="redact")
    ctx = PipelineContext()

    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {"type": "base64", "media_type": "image/png", "data": AWS_KEY},
                    },
                ],
            }
        ]
    }

    result = await step.process_request(body, ctx)
    assert result is not None
    assert ctx.secrets_found == 0


@pytest.mark.asyncio
async def test_mixed_conversation_selective_scanning():
    """Full conversation with mixed roles/block types — only user content scanned."""
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="redact")
    ctx = PipelineContext()

    body = {
        "system": "You are a helpful assistant.",
        "messages": [
            # Earlier user turn (should be scanned)
            {"role": "user", "content": "What is 2+2?"},
            # Assistant reply (should NOT be scanned)
            {"role": "assistant", "content": f"The answer is 4. Key: {AWS_KEY}"},
            # User turn with tool result containing a secret (should be scanned)
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_01",
                        "content": f"export AWS_ACCESS_KEY_ID={AWS_KEY}",
                    },
                    {"type": "text", "text": "What does this file contain?"},
                ],
            },
        ],
    }

    result = await step.process_request(body, ctx)
    assert result is not None
    assert ctx.secrets_found >= 1

    # Assistant message should be untouched (not scanned, not redacted)
    assert AWS_KEY in result["messages"][1]["content"]

    # User tool_result should be redacted
    assert AWS_KEY not in result["messages"][2]["content"][0]["content"]
    assert "REDACTED<" in result["messages"][2]["content"][0]["content"]


@pytest.mark.asyncio
async def test_scans_document_text_source():
    """Document blocks with text source should be scanned and redacted."""
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="redact")
    ctx = PipelineContext()

    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "document",
                        "source": {"type": "text", "text": f"config: {AWS_KEY}"},
                    }
                ],
            }
        ]
    }

    result = await step.process_request(body, ctx)
    assert result is not None
    assert ctx.secrets_found >= 1
    assert AWS_KEY not in result["messages"][0]["content"][0]["source"]["text"]


@pytest.mark.asyncio
async def test_scans_document_content_source():
    """Document blocks with inline content source should be scanned."""
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="redact")
    ctx = PipelineContext()

    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "document",
                        "source": {
                            "type": "content",
                            "content": [{"type": "text", "text": f"secret: {AWS_KEY}"}],
                        },
                    }
                ],
            }
        ]
    }

    result = await step.process_request(body, ctx)
    assert result is not None
    assert ctx.secrets_found >= 1
    sub = result["messages"][0]["content"][0]["source"]["content"][0]
    assert AWS_KEY not in sub["text"]


@pytest.mark.asyncio
async def test_skips_document_base64_source():
    """Document blocks with base64 source (PDF) should not be scanned."""
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="redact")
    ctx = PipelineContext()

    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "document",
                        "source": {
                            "type": "base64",
                            "media_type": "application/pdf",
                            "data": AWS_KEY,
                        },
                    }
                ],
            }
        ]
    }

    result = await step.process_request(body, ctx)
    assert result is not None
    assert ctx.secrets_found == 0


@pytest.mark.asyncio
async def test_scans_server_tool_result():
    """Server tool result blocks (e.g. code_execution_tool_result) should be scanned."""
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="redact")
    ctx = PipelineContext()

    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "code_execution_tool_result",
                        "tool_use_id": "srvtoolu_01",
                        "content": f"Output: {AWS_KEY}",
                    }
                ],
            }
        ]
    }

    result = await step.process_request(body, ctx)
    assert result is not None
    assert ctx.secrets_found >= 1
    assert AWS_KEY not in result["messages"][0]["content"][0]["content"]


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
