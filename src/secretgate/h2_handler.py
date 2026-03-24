"""HTTP/2 relay handler for the forward proxy TLS MITM tunnel.

After ALPN negotiates h2, this handler manages HTTP/2 connections on both
the client and upstream sides, scanning request bodies through TextScanner.
"""

from __future__ import annotations

import asyncio
import re
import sys
from dataclasses import dataclass, field

import h2.config
import h2.connection
import h2.events
import structlog

from secretgate.scan import BlockedError, TextScanner

logger = structlog.get_logger()

# Match forward.py's limit
MAX_BODY_SIZE = 10 * 1024 * 1024  # 10MB

# Auth path pattern — same as forward.py (duplicated to avoid circular import)
_AUTH_PATH_PATTERNS = re.compile(
    r"(?:"
    r"/oauth(?:/|$)"
    r"|/auth(?:/|$)"
    r"|/token(?:/|$|\?)"
    r"|/authorize(?:/|$|\?)"
    r"|/\.well-known/"
    r"|/login"
    r")",
    re.IGNORECASE,
)


def _print_block_notice(message: str, alerts: list[str], host: str) -> None:
    """Print a block notice directly to stderr so it's visible to the user."""
    lines = [
        "",
        f"  [secretgate] BLOCKED request to {host}",
        f"  {message}",
    ]
    for alert in alerts:
        lines.append(f"    - {alert}")
    lines.append("")
    print("\n".join(lines), file=sys.stderr, flush=True)


@dataclass
class _StreamState:
    """Track per-stream request state."""

    request_headers: list[tuple[str, str]] = field(default_factory=list)
    request_body: bytearray = field(default_factory=bytearray)
    request_complete: bool = False
    upstream_stream_id: int | None = None
    skip_scan: bool = False


class H2ConnectionHandler:
    """Handles HTTP/2 relay between client and upstream through the MITM tunnel."""

    def __init__(
        self,
        scanner: TextScanner,
        host: str,
    ):
        self._scanner = scanner
        self._host = host
        # Client-side h2 connection (we act as server)
        self._client_conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False)
        )
        # Upstream h2 connection (we act as client)
        self._upstream_conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True)
        )
        # Stream state: client_stream_id -> _StreamState
        self._streams: dict[int, _StreamState] = {}
        # Reverse map: upstream_stream_id -> client_stream_id
        self._upstream_to_client: dict[int, int] = {}
        # Transport references
        self._client_writer: asyncio.StreamWriter | None = None
        self._upstream_writer: asyncio.StreamWriter | None = None

    async def run(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        """Main loop: relay HTTP/2 frames between client and upstream."""
        self._client_writer = client_writer
        self._upstream_writer = upstream_writer

        # Initiate h2 connections
        self._client_conn.initiate_connection()
        self._flush_client()

        self._upstream_conn.initiate_connection()
        self._flush_upstream()

        # Run both readers concurrently
        client_task = asyncio.create_task(self._read_client(client_reader))
        upstream_task = asyncio.create_task(self._read_upstream(upstream_reader))

        try:
            done, pending = await asyncio.wait(
                [client_task, upstream_task],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            # Re-raise exceptions from completed tasks
            for task in done:
                exc = task.exception()
                if exc and not isinstance(exc, (ConnectionResetError, BrokenPipeError)):
                    raise exc
        except asyncio.CancelledError:
            client_task.cancel()
            upstream_task.cancel()

    async def _read_client(self, reader: asyncio.StreamReader) -> None:
        """Read data from client and process h2 events."""
        while True:
            data = await reader.read(65536)
            if not data:
                return
            events = self._client_conn.receive_data(data)
            for event in events:
                await self._handle_client_event(event)
            self._flush_client()

    async def _read_upstream(self, reader: asyncio.StreamReader) -> None:
        """Read data from upstream and process h2 events."""
        while True:
            data = await reader.read(65536)
            if not data:
                return
            events = self._upstream_conn.receive_data(data)
            for event in events:
                await self._handle_upstream_event(event)
            self._flush_upstream()

    async def _handle_client_event(self, event: h2.events.Event) -> None:
        """Handle an h2 event from the client side."""
        if isinstance(event, h2.events.RequestReceived):
            await self._on_request_headers(event.stream_id, event.headers)

        elif isinstance(event, h2.events.DataReceived):
            await self._on_request_data(event.stream_id, event.data, event.flow_controlled_length)

        elif isinstance(event, h2.events.StreamEnded):
            await self._on_request_complete(event.stream_id)

        elif isinstance(event, h2.events.StreamReset):
            self._on_client_stream_reset(event.stream_id)

        elif isinstance(event, h2.events.WindowUpdated):
            # Client window opened — try flushing pending upstream data
            pass

        elif isinstance(event, h2.events.ConnectionTerminated):
            logger.debug("h2_client_goaway", host=self._host)
            return

    async def _handle_upstream_event(self, event: h2.events.Event) -> None:
        """Handle an h2 event from the upstream side."""
        if isinstance(event, h2.events.ResponseReceived):
            await self._on_response_headers(event.stream_id, event.headers)

        elif isinstance(event, h2.events.DataReceived):
            await self._on_response_data(event.stream_id, event.data, event.flow_controlled_length)

        elif isinstance(event, h2.events.StreamEnded):
            await self._on_response_complete(event.stream_id)

        elif isinstance(event, h2.events.StreamReset):
            self._on_upstream_stream_reset(event.stream_id)

        elif isinstance(event, h2.events.WindowUpdated):
            pass

        elif isinstance(event, h2.events.ConnectionTerminated):
            logger.debug("h2_upstream_goaway", host=self._host)
            return

    # --- Client request handling ---

    async def _on_request_headers(self, stream_id: int, headers: list[tuple[str, str]]) -> None:
        """Client sent request headers on a new stream."""
        # Decode header tuples (h2 gives us bytes or str depending on config)
        decoded = []
        for name, value in headers:
            n = name.decode("utf-8") if isinstance(name, bytes) else name
            v = value.decode("utf-8") if isinstance(value, bytes) else value
            decoded.append((n, v))

        path = ""
        for n, v in decoded:
            if n == ":path":
                path = v
                break

        skip_scan = bool(_AUTH_PATH_PATTERNS.search(path))
        if skip_scan:
            logger.debug("h2_skip_auth_path", host=self._host, path=path)

        self._streams[stream_id] = _StreamState(
            request_headers=decoded,
            skip_scan=skip_scan,
        )

    async def _on_request_data(
        self, stream_id: int, data: bytes, flow_controlled_length: int
    ) -> None:
        """Client sent request body data."""
        state = self._streams.get(stream_id)
        if state is None:
            return
        state.request_body.extend(data)
        # Acknowledge the data to keep flow control moving
        self._client_conn.acknowledge_received_data(flow_controlled_length, stream_id)
        self._flush_client()

        if len(state.request_body) > MAX_BODY_SIZE:
            logger.warning("h2_request_body_too_large", host=self._host, stream_id=stream_id)
            self._client_conn.reset_stream(stream_id)
            self._flush_client()
            del self._streams[stream_id]

    async def _on_request_complete(self, stream_id: int) -> None:
        """Client finished sending request (END_STREAM). Scan and forward."""
        state = self._streams.get(stream_id)
        if state is None:
            return
        state.request_complete = True

        body = bytes(state.request_body)
        headers = state.request_headers

        # Extract content-type for scanner
        content_type = "application/octet-stream"
        for n, v in headers:
            if n == "content-type":
                content_type = v
                break

        # Scan the request body
        scanned_body = body
        if body and not state.skip_scan:
            try:
                scanned_body, alerts = self._scanner.scan_body(body, content_type)
                for alert in alerts:
                    logger.warning("h2_forward_proxy_alert", host=self._host, alert=alert)
            except BlockedError as exc:
                for alert in exc.alerts:
                    logger.error("h2_forward_proxy_blocked", host=self._host, alert=alert)
                _print_block_notice(str(exc), exc.alerts, self._host)
                await self._send_client_error(stream_id, 403, str(exc), exc.alerts)
                return

        # Update content-length header if body changed
        new_headers = []
        for n, v in headers:
            if n == "content-length" and len(scanned_body) != len(body):
                new_headers.append((n, str(len(scanned_body))))
            else:
                new_headers.append((n, v))

        # Forward to upstream
        upstream_stream_id = self._upstream_conn.get_next_available_stream_id()
        state.upstream_stream_id = upstream_stream_id
        self._upstream_to_client[upstream_stream_id] = stream_id

        send_end_stream = len(scanned_body) == 0
        self._upstream_conn.send_headers(
            upstream_stream_id,
            new_headers,
            end_stream=send_end_stream,
        )

        if scanned_body:
            self._send_data_with_flow_control(
                self._upstream_conn, upstream_stream_id, scanned_body, end_stream=True
            )

        self._flush_upstream()

    # --- Upstream response handling ---

    async def _on_response_headers(
        self, upstream_stream_id: int, headers: list[tuple[str, str]]
    ) -> None:
        """Upstream sent response headers."""
        client_stream_id = self._upstream_to_client.get(upstream_stream_id)
        if client_stream_id is None:
            return

        # Decode header tuples
        decoded = []
        for name, value in headers:
            n = name.decode("utf-8") if isinstance(name, bytes) else name
            v = value.decode("utf-8") if isinstance(value, bytes) else value
            decoded.append((n, v))

        self._client_conn.send_headers(client_stream_id, decoded)
        self._flush_client()

    async def _on_response_data(
        self, upstream_stream_id: int, data: bytes, flow_controlled_length: int
    ) -> None:
        """Upstream sent response body data — relay to client."""
        client_stream_id = self._upstream_to_client.get(upstream_stream_id)
        if client_stream_id is None:
            return

        # Acknowledge upstream data
        self._upstream_conn.acknowledge_received_data(flow_controlled_length, upstream_stream_id)
        self._flush_upstream()

        # Forward to client
        self._send_data_with_flow_control(
            self._client_conn, client_stream_id, data, end_stream=False
        )
        self._flush_client()

    async def _on_response_complete(self, upstream_stream_id: int) -> None:
        """Upstream finished sending response (END_STREAM)."""
        client_stream_id = self._upstream_to_client.get(upstream_stream_id)
        if client_stream_id is None:
            return

        self._client_conn.end_stream(client_stream_id)
        self._flush_client()

        # Cleanup
        self._cleanup_stream(client_stream_id, upstream_stream_id)

    # --- Stream reset handling ---

    def _on_client_stream_reset(self, stream_id: int) -> None:
        """Client reset a stream — propagate to upstream."""
        state = self._streams.get(stream_id)
        if state and state.upstream_stream_id is not None:
            try:
                self._upstream_conn.reset_stream(state.upstream_stream_id)
                self._flush_upstream()
            except Exception:
                pass
            self._cleanup_stream(stream_id, state.upstream_stream_id)
        elif state:
            del self._streams[stream_id]

    def _on_upstream_stream_reset(self, upstream_stream_id: int) -> None:
        """Upstream reset a stream — propagate to client."""
        client_stream_id = self._upstream_to_client.get(upstream_stream_id)
        if client_stream_id is not None:
            try:
                self._client_conn.reset_stream(client_stream_id)
                self._flush_client()
            except Exception:
                pass
            self._cleanup_stream(client_stream_id, upstream_stream_id)

    # --- Helpers ---

    def _cleanup_stream(self, client_stream_id: int, upstream_stream_id: int) -> None:
        """Remove stream tracking state."""
        self._streams.pop(client_stream_id, None)
        self._upstream_to_client.pop(upstream_stream_id, None)

    def _send_data_with_flow_control(
        self,
        conn: h2.connection.H2Connection,
        stream_id: int,
        data: bytes,
        end_stream: bool,
    ) -> None:
        """Send data respecting h2 flow control windows."""
        offset = 0
        while offset < len(data):
            # Check both connection and stream flow control windows
            max_size = min(
                conn.local_flow_control_window(stream_id),
                conn.max_outbound_frame_size,
            )
            if max_size <= 0:
                # Window exhausted — send what we have and let the event loop
                # process WINDOW_UPDATE frames before continuing
                max_size = conn.max_outbound_frame_size
            chunk = data[offset : offset + max_size]
            is_last = (offset + len(chunk) >= len(data)) and end_stream
            conn.send_data(stream_id, chunk, end_stream=is_last)
            offset += len(chunk)

    async def _send_client_error(
        self,
        stream_id: int,
        status: int,
        message: str,
        alerts: list[str],
    ) -> None:
        """Send an error response to the client on a specific stream."""
        error_body = (
            f"[secretgate] {message}\nDetails:\n" + "\n".join(f"  - {a}" for a in alerts) + "\n"
        ).encode()

        response_headers = [
            (":status", str(status)),
            ("content-type", "text/plain"),
            ("content-length", str(len(error_body))),
        ]
        self._client_conn.send_headers(stream_id, response_headers)
        self._send_data_with_flow_control(self._client_conn, stream_id, error_body, end_stream=True)
        self._flush_client()

        # Cleanup — no upstream stream was created
        self._streams.pop(stream_id, None)

    def _flush_client(self) -> None:
        """Write pending h2 data to the client transport."""
        data = self._client_conn.data_to_send()
        if data and self._client_writer and not self._client_writer.is_closing():
            self._client_writer.write(data)

    def _flush_upstream(self) -> None:
        """Write pending h2 data to the upstream transport."""
        data = self._upstream_conn.data_to_send()
        if data and self._upstream_writer and not self._upstream_writer.is_closing():
            self._upstream_writer.write(data)
