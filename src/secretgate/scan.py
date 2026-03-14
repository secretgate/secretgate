"""Raw text/bytes scanning adapter for the forward proxy.

Wraps the existing SecretScanner to work with raw HTTP bodies
instead of structured JSON messages.
"""

from __future__ import annotations

import json

import structlog

from secretgate.secrets.redactor import _make_placeholder
from secretgate.secrets.scanner import SecretScanner

logger = structlog.get_logger()

# Content types that should never be scanned (binary data)
_SKIP_PREFIXES = ("image/", "audio/", "video/")
_SKIP_TYPES = frozenset(
    {
        "application/octet-stream",
        "application/gzip",
        "application/zip",
        "application/x-tar",
        "application/x-bzip2",
        "application/x-xz",
        "application/pdf",
    }
)


class TextScanner:
    """Scan raw HTTP bodies for secrets using the existing SecretScanner."""

    def __init__(self, scanner: SecretScanner, mode: str = "redact"):
        self._scanner = scanner
        self._mode = mode

    def should_scan(self, content_type: str) -> bool:
        """Return True if this content type should be scanned for secrets."""
        ct = content_type.lower().split(";")[0].strip()
        if any(ct.startswith(p) for p in _SKIP_PREFIXES):
            return False
        if ct in _SKIP_TYPES:
            return False
        return True

    def scan_body(self, body: bytes, content_type: str = "text/plain") -> tuple[bytes, list[str]]:
        """Scan body bytes for secrets. Returns (possibly modified body, alerts).

        In block mode, raises BlockedError if secrets are found.
        In audit mode, returns body unchanged but with alerts.
        In redact mode, replaces secrets with [REDACTED] markers.
        """
        alerts: list[str] = []

        if not body or not self.should_scan(content_type):
            return body, alerts

        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            return body, alerts

        # For JSON bodies (LLM API requests), strip content that should not
        # be scanned: assistant messages (model-generated, already scanned on
        # input) and thinking blocks (cryptographic signatures).
        ct = content_type.lower().split(";")[0].strip()
        scannable = self._strip_model_content(text) if "json" in ct else text

        matches = self._scanner.scan(scannable)
        if not matches:
            return body, alerts

        for m in matches:
            alert = f"Secret detected: {m.service}/{m.pattern_name} on line {m.line_number}"
            alerts.append(alert)
            logger.warning(
                "forward_secret_detected",
                service=m.service,
                pattern=m.pattern_name,
                line=m.line_number,
            )

        if self._mode == "block":
            raise BlockedError(f"Request blocked: {len(matches)} secret(s) detected", alerts)

        if self._mode == "audit":
            return body, alerts

        # Redact mode: replace secrets with deterministic placeholders
        # Same format as reverse proxy: REDACTED<slug:hash12>
        # Sort by length (longest first to avoid partial replacements)
        for m in sorted(matches, key=lambda m: len(m.value), reverse=True):
            text = text.replace(m.value, _make_placeholder(m))

        return text.encode("utf-8"), alerts

    @staticmethod
    def _strip_model_content(text: str) -> str:
        """Strip content that should not be scanned from LLM API request JSON.

        Only keeps content that needs scanning:
        - The last contiguous run of user-role messages (the current turn)

        Everything else is blanked:
        - System prompt: static config (CLAUDE.md, tool defs), audit
          separately with ``secretgate scan``
        - Assistant messages: model-generated, already scanned on input
        - Earlier user messages: already scanned when originally sent
        """
        try:
            body = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return text

        if not isinstance(body, dict):
            return text

        # Blank the system prompt — it's static config that doesn't change
        # between requests and triggers false positives from tool definitions,
        # CLAUDE.md content, etc.
        system = body.get("system")
        if isinstance(system, str) and system:
            body["system"] = ""
            modified_system = True
        elif isinstance(system, list):
            for block in system:
                if isinstance(block, dict) and "text" in block and block["text"]:
                    block["text"] = ""
            modified_system = True
        else:
            modified_system = False

        messages = body.get("messages")
        if not isinstance(messages, list):
            return text

        # Find where the last user turn starts: walk backwards from the end
        # and keep user-role messages until we hit an assistant message.
        last_turn_start = len(messages)
        for i in range(len(messages) - 1, -1, -1):
            msg = messages[i]
            if isinstance(msg, dict) and msg.get("role") == "user":
                last_turn_start = i
            else:
                break

        modified = False
        for i, msg in enumerate(messages):
            if not isinstance(msg, dict):
                continue

            # Keep the last user turn — it's the new content to scan
            if i >= last_turn_start:
                # Still strip thinking blocks (signatures must never be touched)
                content = msg.get("content")
                if isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "thinking":
                            for key in ("thinking", "signature"):
                                if key in block and block[key]:
                                    block[key] = ""
                                    modified = True
                continue

            # Blank all earlier messages (already scanned in previous turns)
            content = msg.get("content")
            if isinstance(content, str) and content:
                msg["content"] = ""
                modified = True
            elif isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    for key in ("text", "thinking", "signature", "content"):
                        if key in block and isinstance(block[key], str) and block[key]:
                            block[key] = ""
                            modified = True

        return json.dumps(body) if (modified or modified_system) else text


class BlockedError(Exception):
    """Raised when a request is blocked due to secrets in block mode."""

    def __init__(self, message: str, alerts: list[str]):
        super().__init__(message)
        self.alerts = alerts
