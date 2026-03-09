"""Raw text/bytes scanning adapter for the forward proxy.

Wraps the existing SecretScanner to work with raw HTTP bodies
instead of structured JSON messages.
"""

from __future__ import annotations

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

        matches = self._scanner.scan(text)
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


class BlockedError(Exception):
    """Raised when a request is blocked due to secrets in block mode."""

    def __init__(self, message: str, alerts: list[str]):
        super().__init__(message)
        self.alerts = alerts
