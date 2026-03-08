"""Built-in pipeline steps."""

from __future__ import annotations

import json
import structlog

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
            logger.warning("secret_detected", service=m.service, pattern=m.pattern_name, line=m.line_number)

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
        # Streaming chunks: attempt unredaction on decoded text
        try:
            text = chunk.decode("utf-8")
            restored = redactor.unredact(text)
            return restored.encode("utf-8")
        except UnicodeDecodeError:
            return chunk

    def _unredact_body(self, body: dict, ctx: PipelineContext) -> dict:
        redactor: SecretRedactor | None = ctx.metadata.get("redactor")
        if not redactor or redactor.count == 0:
            return body
        # Walk the response and unredact any text fields
        text = json.dumps(body)
        restored = redactor.unredact(text)
        return json.loads(restored)


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
