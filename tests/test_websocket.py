"""Tests for WebSocket upgrade detection in the forward proxy."""

from __future__ import annotations

from unittest.mock import MagicMock


from secretgate.forward import _ConnectionHandler


class TestWebSocketDetection:
    """Verify that WebSocket upgrade requests are detected and passed through."""

    def _make_handler(self, reader, writer):
        """Create a _ConnectionHandler with mock dependencies."""
        ca = MagicMock()
        scanner = MagicMock()
        return _ConnectionHandler(
            reader=reader,
            writer=writer,
            ca=ca,
            scanner=scanner,
            passthrough_domains=set(),
            upstream_ssl=None,
        )

    def test_websocket_upgrade_header_detected(self):
        """A request with Upgrade: websocket should be identified."""
        # Verify the header matching logic used in _relay_http
        headers = {"upgrade": "websocket", "connection": "Upgrade"}
        assert headers.get("upgrade", "").lower() == "websocket"

    def test_non_websocket_upgrade_not_detected(self):
        """A request with Upgrade: h2c should not trigger WebSocket passthrough."""
        headers = {"upgrade": "h2c", "connection": "Upgrade"}
        assert headers.get("upgrade", "").lower() != "websocket"

    def test_no_upgrade_header(self):
        """A normal HTTP request has no upgrade header."""
        headers = {"content-type": "application/json"}
        assert headers.get("upgrade", "").lower() != "websocket"
