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
        # First, scan scannable text to detect secrets (without mutating)
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

        # Redact the system field
        _redact_system(body, redactor)

        # Redact only scannable message content (user text + tool_result)
        for msg in body.get("messages", []):
            role = msg.get("role", "")
            if role != "user":
                continue
            content = msg.get("content")
            if isinstance(content, str):
                msg["content"] = redactor.redact(content)
            elif isinstance(content, list):
                _redact_user_blocks(content, redactor)

        ctx.metadata["redactor"] = redactor
        logger.info("secrets_redacted", count=redactor.count)
        return body

    @staticmethod
    def _extract_text(body: dict) -> str:
        """Extract scannable text from the request body.

        Content-block-aware extraction:
        - system field: always scanned (user-supplied)
        - user text blocks: scanned (most likely leak vector)
        - user tool_result blocks: scanned (tool output may contain secrets)
        - assistant messages: skipped (model-generated)
        - tool_use blocks: skipped (structured function calls)
        - thinking blocks: skipped (model-internal, cryptographic signatures)
        - image blocks: skipped (binary data)
        """
        parts: list[str] = []

        # System field — always user-supplied
        system = body.get("system")
        if isinstance(system, str):
            parts.append(system)
        elif isinstance(system, list):
            for block in system:
                if isinstance(block, dict) and block.get("type") == "text":
                    parts.append(block.get("text", ""))

        for msg in body.get("messages", []):
            role = msg.get("role", "")
            # Skip assistant messages entirely — model-generated content
            if role != "user":
                continue

            content = msg.get("content")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    block_type = block.get("type", "")
                    if block_type == "text":
                        parts.append(block.get("text", ""))
                    elif block_type == "tool_result":
                        _extract_tool_result_text(block, parts)
                    elif block_type == "document":
                        _extract_document_text(block, parts)
                    elif block_type.endswith("_tool_result"):
                        # Server tool result blocks (web_search_tool_result,
                        # code_execution_tool_result, etc.)
                        _extract_tool_result_text(block, parts)
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


def _extract_document_text(block: dict, parts: list[str]) -> None:
    """Extract scannable text from a document content block."""
    source = block.get("source")
    if not isinstance(source, dict):
        return
    source_type = source.get("type", "")
    if source_type == "text":
        text = source.get("text", "")
        if text:
            parts.append(text)
    elif source_type == "content":
        content = source.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for sub in content:
                if isinstance(sub, dict) and sub.get("type") == "text":
                    parts.append(sub.get("text", ""))


def _extract_tool_result_text(block: dict, parts: list[str]) -> None:
    """Extract scannable text from a tool_result content block."""
    content = block.get("content")
    if isinstance(content, str):
        parts.append(content)
    elif isinstance(content, list):
        for sub in content:
            if isinstance(sub, dict) and sub.get("type") == "text":
                parts.append(sub.get("text", ""))


def _redact_system(body: dict, redactor: SecretRedactor) -> None:
    """Redact secrets in the system field."""
    system = body.get("system")
    if isinstance(system, str):
        body["system"] = redactor.redact(system)
    elif isinstance(system, list):
        for block in system:
            if isinstance(block, dict) and block.get("type") == "text":
                block["text"] = redactor.redact(block.get("text", ""))


def _redact_user_blocks(blocks: list, redactor: SecretRedactor) -> None:
    """Redact secrets in user message content blocks."""
    for block in blocks:
        if not isinstance(block, dict):
            continue
        block_type = block.get("type", "")
        if block_type == "text":
            block["text"] = redactor.redact(block.get("text", ""))
        elif block_type == "tool_result" or block_type.endswith("_tool_result"):
            _redact_tool_result(block, redactor)
        elif block_type == "document":
            _redact_document(block, redactor)


def _redact_tool_result(block: dict, redactor: SecretRedactor) -> None:
    """Redact secrets in a tool_result or server tool result block."""
    content = block.get("content")
    if isinstance(content, str):
        block["content"] = redactor.redact(content)
    elif isinstance(content, list):
        for sub in content:
            if isinstance(sub, dict) and sub.get("type") == "text":
                sub["text"] = redactor.redact(sub.get("text", ""))


def _redact_document(block: dict, redactor: SecretRedactor) -> None:
    """Redact secrets in a document block's text content."""
    source = block.get("source")
    if not isinstance(source, dict):
        return
    source_type = source.get("type", "")
    if source_type == "text":
        if isinstance(source.get("text"), str):
            source["text"] = redactor.redact(source["text"])
    elif source_type == "content":
        # Inline content — string or list of content blocks
        content = source.get("content")
        if isinstance(content, str):
            source["content"] = redactor.redact(content)
        elif isinstance(content, list):
            for sub in content:
                if isinstance(sub, dict) and sub.get("type") == "text":
                    sub["text"] = redactor.redact(sub.get("text", ""))


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
