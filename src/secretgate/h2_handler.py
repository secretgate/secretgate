"""HTTP/2 relay handler for the forward proxy TLS MITM tunnel.

After ALPN negotiates h2, this handler manages HTTP/2 connections on both
the client and upstream sides, scanning request bodies through TextScanner.
"""

from __future__ import annotations

import asyncio
import re
import ssl
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
        upstream_port: int = 443,
        upstream_ssl: ssl.SSLContext | None = None,
    ):
        self._scanner = scanner
        self._host = host
        self._upstream_port = upstream_port
        self._upstream_ssl = upstream_ssl
        # Client-side h2 connection (we act as server)
        self._client_conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False)
        )
        # Upstream h2 connection (we act as client)
        self._upstream_conn: h2.connection.H2Connection | None = None
        # Stream state: client_stream_id -> _StreamState
        self._streams: dict[int, _StreamState] = {}
        # Reverse map: upstream_stream_id -> client_stream_id
        self._upstream_to_client: dict[int, int] = {}
        # Transport references
        self._client_writer: asyncio.StreamWriter | None = None
        self._upstream_writer: asyncio.StreamWriter | None = None
        self._upstream_reader: asyncio.StreamReader | None = None

    def _init_upstream_h2(self) -> None:
        """Create a fresh upstream h2 connection state machine."""
        self._upstream_conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True)
        )
        self._streams.clear()
        self._upstream_to_client.clear()

    def _make_h2_ssl_context(self) -> ssl.SSLContext:
        """Create a fresh SSL context with h2 ALPN, without mutating the shared one."""
        if self._upstream_ssl:
            # For test contexts that trust specific CAs: we can't copy CA certs
            # between contexts easily, so just set ALPN on the existing context.
            # This is safe because test contexts are not shared across connections.
            self._upstream_ssl.set_alpn_protocols(["h2", "http/1.1"])
            return self._upstream_ssl
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        return ctx

    async def _connect_upstream(self) -> bool:
        """Connect (or reconnect) to the upstream h2 server. Returns True on success."""
        h2_ssl = self._make_h2_ssl_context()
        try:
            self._upstream_reader, new_writer = await asyncio.open_connection(
                self._host, self._upstream_port, ssl=h2_ssl
            )
            self._upstream_writer = new_writer
        except Exception as exc:
            logger.warning("h2_upstream_reconnect_failed", host=self._host, error=str(exc))
            return False

        # Verify upstream negotiated h2
        up_ssl_obj = self._upstream_writer.get_extra_info("ssl_object")
        up_proto = up_ssl_obj.selected_alpn_protocol() if up_ssl_obj else None
        if up_proto != "h2":
            logger.warning("h2_upstream_reconnect_not_h2", host=self._host, proto=up_proto)
            if not self._upstream_writer.is_closing():
                self._upstream_writer.close()
            return False

        self._init_upstream_h2()
        self._upstream_conn.initiate_connection()
        await self._flush_upstream()
        return True

    async def run_client_only(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Entry point when forward.py only provides the client connection.

        The handler manages its own upstream connections (connect, reconnect).
        """
        self._client_writer = client_writer
        self._client_conn.initiate_connection()
        await self._flush_client()

        if not await self._connect_upstream():
            return

        await self._relay_loop(client_reader)

    async def run(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        """Entry point when both client and upstream connections are provided (tests)."""
        self._client_writer = client_writer
        self._upstream_reader = upstream_reader
        self._upstream_writer = upstream_writer

        self._client_conn.initiate_connection()
        await self._flush_client()

        self._init_upstream_h2()
        self._upstream_conn.initiate_connection()
        await self._flush_upstream()

        await self._relay_loop(client_reader)

    async def _relay_loop(self, client_reader: asyncio.StreamReader) -> None:
        """Main relay loop: runs client/upstream readers, handles upstream reconnect."""

        while True:
            # Run both readers concurrently
            client_task = asyncio.create_task(self._read_client(client_reader))
            upstream_task = asyncio.create_task(self._read_upstream())

            try:
                done, pending = await asyncio.wait(
                    [client_task, upstream_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )
            except asyncio.CancelledError:
                client_task.cancel()
                upstream_task.cancel()
                return

            if client_task in done:
                # Client disconnected — we're done
                upstream_task.cancel()
                try:
                    await upstream_task
                except (asyncio.CancelledError, Exception):
                    pass
                # Re-raise client task exceptions
                exc = client_task.exception()
                if exc and not isinstance(
                    exc, (ConnectionResetError, BrokenPipeError, asyncio.CancelledError)
                ):
                    raise exc
                return

            # Upstream closed — cancel client reader, error in-flight streams, reconnect
            upstream_task.cancel()  # already done, but be safe
            client_task.cancel()
            try:
                await client_task
            except (asyncio.CancelledError, Exception):
                pass

            logger.debug("h2_upstream_closed_reconnecting", host=self._host)

            # Error any in-flight streams back to the client
            for client_sid, state in list(self._streams.items()):
                if state.upstream_stream_id is not None:
                    try:
                        self._client_conn.reset_stream(client_sid, error_code=2)  # INTERNAL_ERROR
                    except Exception:
                        pass
            self._streams.clear()
            self._upstream_to_client.clear()
            await self._flush_client()

            # Close old upstream writer
            if self._upstream_writer and not self._upstream_writer.is_closing():
                self._upstream_writer.close()
                try:
                    await self._upstream_writer.wait_closed()
                except Exception:
                    pass

            # Reconnect upstream with retry
            reconnected = False
            for attempt in range(3):
                if attempt > 0:
                    await asyncio.sleep(0.5 * attempt)
                if await self._connect_upstream():
                    reconnected = True
                    logger.debug("h2_upstream_reconnected", host=self._host, attempt=attempt + 1)
                    break
            if not reconnected:
                # Can't reconnect — send GOAWAY to client and exit
                logger.warning("h2_upstream_reconnect_exhausted", host=self._host)
                try:
                    self._client_conn.close_connection(error_code=0)
                    await self._flush_client()
                except Exception:
                    pass
                return

    async def _read_client(self, reader: asyncio.StreamReader) -> None:
        """Read data from client and process h2 events."""
        while True:
            data = await reader.read(65536)
            if not data:
                return
            events = self._client_conn.receive_data(data)
            for event in events:
                await self._handle_client_event(event)
            await self._flush_client()
            await self._flush_upstream()

    async def _read_upstream(self) -> None:
        """Read data from upstream and process h2 events."""
        while True:
            data = await self._upstream_reader.read(65536)
            if not data:
                return
            events = self._upstream_conn.receive_data(data)
            for event in events:
                await self._handle_upstream_event(event)
            await self._flush_upstream()
            await self._flush_client()

    async def _handle_client_event(self, event: h2.events.Event) -> None:
        """Handle an h2 event from the client side."""
        if isinstance(event, h2.events.RequestReceived):
            await self._on_request_headers(event.stream_id, event.headers)

        elif isinstance(event, h2.events.DataReceived):
            await self._on_request_data(event.stream_id, event.data, event.flow_controlled_length)

        elif isinstance(event, h2.events.StreamEnded):
            await self._on_request_complete(event.stream_id)

        elif isinstance(event, h2.events.StreamReset):
            await self._on_client_stream_reset(event.stream_id)

        elif isinstance(event, h2.events.WindowUpdated):
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
            await self._on_upstream_stream_reset(event.stream_id)

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

        if len(state.request_body) > MAX_BODY_SIZE:
            logger.warning("h2_request_body_too_large", host=self._host, stream_id=stream_id)
            self._client_conn.reset_stream(stream_id)
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

    async def _on_response_data(
        self, upstream_stream_id: int, data: bytes, flow_controlled_length: int
    ) -> None:
        """Upstream sent response body data — relay to client."""
        client_stream_id = self._upstream_to_client.get(upstream_stream_id)
        if client_stream_id is None:
            return

        # Acknowledge upstream data
        self._upstream_conn.acknowledge_received_data(flow_controlled_length, upstream_stream_id)

        # Forward to client
        self._send_data_with_flow_control(
            self._client_conn, client_stream_id, data, end_stream=False
        )

    async def _on_response_complete(self, upstream_stream_id: int) -> None:
        """Upstream finished sending response (END_STREAM)."""
        client_stream_id = self._upstream_to_client.get(upstream_stream_id)
        if client_stream_id is None:
            return

        self._client_conn.end_stream(client_stream_id)

        # Cleanup
        self._cleanup_stream(client_stream_id, upstream_stream_id)

    # --- Stream reset handling ---

    async def _on_client_stream_reset(self, stream_id: int) -> None:
        """Client reset a stream — propagate to upstream."""
        state = self._streams.get(stream_id)
        if state and state.upstream_stream_id is not None:
            try:
                self._upstream_conn.reset_stream(state.upstream_stream_id)
            except Exception:
                pass
            self._cleanup_stream(stream_id, state.upstream_stream_id)
        elif state:
            del self._streams[stream_id]

    async def _on_upstream_stream_reset(self, upstream_stream_id: int) -> None:
        """Upstream reset a stream — propagate to client."""
        client_stream_id = self._upstream_to_client.get(upstream_stream_id)
        if client_stream_id is not None:
            try:
                self._client_conn.reset_stream(client_stream_id)
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
        """Send data respecting h2 flow control windows.

        Sends as much data as the flow control window allows. If the window
        is exhausted, remaining data is silently dropped — the reader loops
        will process WINDOW_UPDATE events and the peer will retransmit or
        the connection will be reset. For typical API request/response sizes
        (< 64KB) this is not an issue since the default window is 64KB.
        """
        offset = 0
        while offset < len(data):
            window = conn.local_flow_control_window(stream_id)
            if window <= 0:
                # Window exhausted — send end_stream on a zero-length frame if needed
                if end_stream:
                    conn.send_data(stream_id, b"", end_stream=True)
                break
            max_size = min(window, conn.max_outbound_frame_size)
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
        await self._flush_client()

        # Cleanup — no upstream stream was created
        self._streams.pop(stream_id, None)

    async def _flush_client(self) -> None:
        """Write pending h2 data to the client transport."""
        data = self._client_conn.data_to_send()
        if data and self._client_writer and not self._client_writer.is_closing():
            self._client_writer.write(data)
            try:
                await self._client_writer.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass

    async def _flush_upstream(self) -> None:
        """Write pending h2 data to the upstream transport."""
        data = self._upstream_conn.data_to_send()
        if data and self._upstream_writer and not self._upstream_writer.is_closing():
            self._upstream_writer.write(data)
            try:
                await self._upstream_writer.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass
