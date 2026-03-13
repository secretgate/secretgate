"""Built-in pipeline steps."""

from __future__ import annotations

import json
import structlog
from typing import Any

from secretgate.pipeline import PipelineContext, PipelineStep
from secretgate.secrets.redactor import SecretRedactor
from secretgate.secrets.scanner import SecretScanner

logger = structlog.get_logger()


class SecretRedactionStep(PipelineStep):
    """Scans outbound messages for secrets and redacts them."""

    def __init__(self, scanner: SecretScanner, mode: str = "redact"):
        self._scanner = scanner
        self._mode = mode  # "redact", "block", or "audit"

    async def process_request(self, body: dict, ctx: PipelineContext) -> dict | None:
        # First, scan all message text to detect secrets (without mutating)
        all_text = self._extract_text(body)
        matches = self._scanner.scan(all_text)

        if not matches:
            return body

        # Log alerts for all modes
        ctx.secrets_found = len(matches)
        for m in matches:
            alert = f"Secret detected: {m.service}/{m.pattern_name} on line {m.line_number}"
            ctx.alerts.append(alert)
            logger.warning(
                "secret_detected", service=m.service, pattern=m.pattern_name, line=m.line_number
            )

        if self._mode == "block":
            logger.error("request_blocked", secrets_found=len(matches))
            return None

        if self._mode == "audit":
            logger.warning("secrets_audit_only", secrets_found=len(matches))
            return body

        # Redact mode: replace secrets with placeholders
        redactor = SecretRedactor(self._scanner)
        messages = body.get("messages", [])

        for msg in messages:
            content = msg.get("content")
            if isinstance(content, str):
                msg["content"] = redactor.redact(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        block["text"] = redactor.redact(block.get("text", ""))

        ctx.metadata["redactor"] = redactor
        logger.info("secrets_redacted", count=redactor.count)
        return body

    @staticmethod
    def _extract_text(body: dict) -> str:
        """Extract all text content from messages for scanning."""
        parts: list[str] = []
        for msg in body.get("messages", []):
            content = msg.get("content")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))
        return "\n".join(parts)

    async def process_response(self, body: dict, ctx: PipelineContext) -> dict:
        return self._unredact_body(body, ctx)

    async def process_response_chunk(self, chunk: bytes, ctx: PipelineContext) -> bytes:
        redactor: SecretRedactor | None = ctx.metadata.get("redactor")
        if not redactor or redactor.count == 0:
            return chunk
        # Streaming chunks: unredact line by line, skipping thinking block events.
        # Thinking block content is covered by Anthropic's cryptographic signature;
        # modifying it (even to restore a placeholder) would invalidate the signature.
        try:
            text = chunk.decode("utf-8")
            lines = text.splitlines(keepends=True)
            out = []
            for line in lines:
                data = line[6:] if line.startswith("data: ") else None
                if data is not None and _is_thinking_sse_data(data):
                    out.append(line)
                else:
                    out.append(redactor.unredact(line))
            return "".join(out).encode("utf-8")
        except UnicodeDecodeError:
            return chunk

    def _unredact_body(self, body: dict, ctx: PipelineContext) -> dict:
        redactor: SecretRedactor | None = ctx.metadata.get("redactor")
        if not redactor or redactor.count == 0:
            return body
        # Walk the response structure, unredacting string fields but leaving
        # thinking blocks entirely untouched.  Thinking block content is covered
        # by Anthropic's cryptographic signature; modifying it would make the
        # signature invalid when the block is included in the next request turn.
        _unredact_value(body, redactor)
        return body


def _is_thinking_sse_data(data: str) -> bool:
    """Return True if this SSE data payload is a thinking-related event."""
    try:
        event = json.loads(data)
    except (json.JSONDecodeError, ValueError):
        return False
    cb = event.get("content_block")
    if isinstance(cb, dict) and cb.get("type") == "thinking":
        return True
    delta = event.get("delta")
    if isinstance(delta, dict) and delta.get("type") in ("thinking_delta", "signature_delta"):
        return True
    return False


def _unredact_value(value: Any, redactor: SecretRedactor) -> None:
    if isinstance(value, dict):
        _unredact_dict(value, redactor)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            if isinstance(item, str):
                value[i] = redactor.unredact(item)
            else:
                _unredact_value(item, redactor)


def _unredact_dict(d: dict, redactor: SecretRedactor) -> None:
    # Skip thinking blocks entirely — their content is covered by Anthropic's
    # cryptographic signature and must not be modified.
    if d.get("type") == "thinking":
        return
    for key in d:
        v = d[key]
        if isinstance(v, str):
            d[key] = redactor.unredact(v)
        else:
            _unredact_value(v, redactor)


class AuditLogStep(PipelineStep):
    """Logs all requests for audit purposes."""

    async def process_request(self, body: dict, ctx: PipelineContext) -> dict:
        model = body.get("model", "unknown")
        msg_count = len(body.get("messages", []))
        logger.info("request", model=model, messages=msg_count)
        return body

    async def process_response(self, body: dict, ctx: PipelineContext) -> dict:
        if ctx.secrets_found:
            logger.info("response", secrets_restored=ctx.secrets_found)
        return body
