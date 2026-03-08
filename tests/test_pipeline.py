"""Tests for the pipeline and steps."""

import pytest

from secretgate.pipeline import Pipeline, PipelineContext
from secretgate.secrets.scanner import SecretScanner
from secretgate.steps import SecretRedactionStep


@pytest.mark.asyncio
async def test_redaction_step_redacts_openai_format():
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="redact")
    ctx = PipelineContext()

    body = {
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": "My key is AKIAIOSFODNN7EXAMPLE"}
        ],
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
                "content": [
                    {"type": "text", "text": "My key is AKIAIOSFODNN7EXAMPLE"}
                ],
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

    body = {
        "messages": [{"role": "user", "content": "Key: AKIAIOSFODNN7EXAMPLE"}]
    }

    result = await step.process_request(body, ctx)
    assert result is None


@pytest.mark.asyncio
async def test_audit_mode_passes_through():
    scanner = SecretScanner()
    step = SecretRedactionStep(scanner, mode="audit")
    ctx = PipelineContext()

    body = {
        "messages": [{"role": "user", "content": "Key: AKIAIOSFODNN7EXAMPLE"}]
    }

    result = await step.process_request(body, ctx)
    assert result is not None
    # In audit mode, the secret should NOT be redacted
    assert "AKIAIOSFODNN7EXAMPLE" in result["messages"][0]["content"]


@pytest.mark.asyncio
async def test_pipeline_runs_steps_in_order():
    scanner = SecretScanner()
    pipeline = Pipeline(
        steps=[SecretRedactionStep(scanner, mode="redact")]
    )
    ctx = PipelineContext()

    body = {
        "messages": [{"role": "user", "content": "AKIAIOSFODNN7EXAMPLE"}]
    }

    result = await pipeline.run_request(body, ctx)
    assert result is not None
    assert "AKIAIOSFODNN7EXAMPLE" not in result["messages"][0]["content"]


@pytest.mark.asyncio
async def test_clean_request_passes_through():
    scanner = SecretScanner()
    pipeline = Pipeline(
        steps=[SecretRedactionStep(scanner, mode="redact")]
    )
    ctx = PipelineContext()

    body = {
        "messages": [{"role": "user", "content": "just normal code here"}]
    }

    result = await pipeline.run_request(body, ctx)
    assert result == body
    assert ctx.secrets_found == 0
