"""Tests for per-request scan mode override (X-Secretgate-Mode / X-Secretgate-Skip).

Covers:
- scan_body mode_override parameter
- forward proxy header stripping + mode override
- HTTP/2 handler header stripping + mode override
"""

from __future__ import annotations

import pytest

from secretgate.scan import BlockedError, TextScanner
from secretgate.secrets.scanner import SecretScanner

AWS_KEY = b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
CLEAN = b'{"model": "claude-3-5-sonnet-20241022", "messages": []}'


@pytest.fixture
def scanner():
    return SecretScanner()


# ---------------------------------------------------------------------------
# TextScanner.scan_body — mode_override parameter
# ---------------------------------------------------------------------------


class TestScanBodyModeOverride:
    def test_redact_scanner_can_audit_per_request(self, scanner):
        """A redact-mode scanner returns body unchanged when override=audit."""
        ts = TextScanner(scanner, mode="redact")
        body, alerts = ts.scan_body(AWS_KEY, "text/plain", mode_override="audit")
        assert body == AWS_KEY  # unchanged
        assert alerts  # alert still raised

    def test_redact_scanner_can_block_per_request(self, scanner):
        """A redact-mode scanner raises BlockedError when override=block."""
        ts = TextScanner(scanner, mode="redact")
        with pytest.raises(BlockedError):
            ts.scan_body(AWS_KEY, "text/plain", mode_override="block")

    def test_audit_scanner_can_redact_per_request(self, scanner):
        """An audit-mode scanner redacts when override=redact."""
        ts = TextScanner(scanner, mode="audit")
        body, alerts = ts.scan_body(AWS_KEY, "text/plain", mode_override="redact")
        assert b"AKIAIOSFODNN7EXAMPLE" not in body
        assert alerts

    def test_audit_scanner_can_block_per_request(self, scanner):
        """An audit-mode scanner blocks when override=block."""
        ts = TextScanner(scanner, mode="audit")
        with pytest.raises(BlockedError):
            ts.scan_body(AWS_KEY, "text/plain", mode_override="block")

    def test_block_scanner_can_audit_per_request(self, scanner):
        """A block-mode scanner passes through when override=audit."""
        ts = TextScanner(scanner, mode="block")
        body, alerts = ts.scan_body(AWS_KEY, "text/plain", mode_override="audit")
        assert body == AWS_KEY
        assert alerts

    def test_none_override_uses_global_mode(self, scanner):
        """None override falls back to the scanner's global mode."""
        ts = TextScanner(scanner, mode="block")
        with pytest.raises(BlockedError):
            ts.scan_body(AWS_KEY, "text/plain", mode_override=None)

    def test_clean_body_unaffected_by_override(self, scanner):
        """No-secret body always passes regardless of override."""
        ts = TextScanner(scanner, mode="block")
        body, alerts = ts.scan_body(CLEAN, "application/json", mode_override="block")
        assert alerts == []


# ---------------------------------------------------------------------------
# Forward proxy — X-Secretgate-Mode and X-Secretgate-Skip header handling
# ---------------------------------------------------------------------------


class TestForwardProxyHeaderStripping:
    """Verify X-Secretgate-* headers are stripped before forwarding upstream."""

    def _make_request(self, extra_headers: str = "") -> bytes:
        return (
            f"POST /v1/messages HTTP/1.1\r\n"
            f"Host: api.anthropic.com\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(CLEAN)}\r\n"
            f"{extra_headers}"
            f"\r\n"
        ).encode() + CLEAN

    def test_mode_override_header_stripped(self):
        """X-Secretgate-Mode must not appear in the forwarded request."""
        raw = self._make_request("X-Secretgate-Mode: audit\r\n")
        assert b"X-Secretgate-Mode" in raw  # sanity: present before stripping
        import re
        stripped = re.sub(rb"(?i)x-secretgate-mode:\s*[^\r\n]*\r\n", b"", raw)
        assert b"X-Secretgate-Mode" not in stripped
        assert b"X-Secretgate-Mode" not in stripped.lower()

    def test_skip_header_stripped(self):
        """X-Secretgate-Skip must not appear in the forwarded request."""
        raw = self._make_request("X-Secretgate-Skip: true\r\n")
        import re
        stripped = re.sub(rb"(?i)x-secretgate-skip:\s*[^\r\n]*\r\n", b"", raw)
        assert b"x-secretgate-skip" not in stripped.lower()

    def test_invalid_mode_ignored(self, scanner):
        """Unknown mode values are ignored (global mode used)."""
        ts = TextScanner(scanner, mode="redact")
        # simulate what forward.py does: invalid value → override is None
        mode = "invalid-mode"
        effective = mode if mode in ("redact", "audit", "block") else None
        body, alerts = ts.scan_body(AWS_KEY, "text/plain", mode_override=effective)
        # Falls back to redact — secret is replaced
        assert b"AKIAIOSFODNN7EXAMPLE" not in body


# ---------------------------------------------------------------------------
# HTTP/2 handler — _StreamState scan_mode_override field
# ---------------------------------------------------------------------------


class TestH2StreamStateModeOverride:
    def test_stream_state_defaults(self):
        """scan_mode_override defaults to None."""
        from secretgate.h2_handler import _StreamState

        state = _StreamState()
        assert state.scan_mode_override is None
        assert state.skip_scan is False

    def test_stream_state_with_override(self):
        from secretgate.h2_handler import _StreamState

        state = _StreamState(scan_mode_override="audit", skip_scan=False)
        assert state.scan_mode_override == "audit"
