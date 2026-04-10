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
import h2.exceptions
import h2.settings
import structlog

from secretgate.scan import (
    MAX_SESSION_TOKENS,
    BlockedError,
    TextScanner,
    extract_session_tokens,
)

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

# H2 flow control: default 65,535 bytes is far too small for proxying
# resource-heavy pages with many concurrent streams. Production proxies
# (nginx, envoy) use multi-MB windows. 16MB matches Go's default.
H2_WINDOW_SIZE = 16 * 1024 * 1024  # 16MB


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


@dataclass
class _QueuedRequest:
    """A scanned request waiting for an upstream stream slot."""

    client_stream_id: int
    headers: list[tuple[str, str]]
    body: bytes


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
        # Pending outbound data blocked by flow control (stream_id -> (bytes, end_stream))
        self._client_pending: dict[int, tuple[bytes, bool]] = {}
        self._upstream_pending: dict[int, tuple[bytes, bool]] = {}
        # Requests queued because upstream MAX_CONCURRENT_STREAMS was reached
        self._queued_requests: list[_QueuedRequest] = []
        # JWT tokens harvested from upstream response bodies on this connection.
        # Used as exclusions when scanning subsequent request bodies (issue #66).
        self._session_tokens: set[str] = set()

    @staticmethod
    def _apply_window_settings(conn: h2.connection.H2Connection) -> None:
        """Set large flow control windows after initiate_connection().

        The default 64KB window is far too small for proxying heavy pages.
        We increase both the per-stream initial window (via SETTINGS) and
        the connection-level window (via WINDOW_UPDATE).
        """
        conn.update_settings(
            {
                h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: H2_WINDOW_SIZE,
            }
        )
        conn.increment_flow_control_window(H2_WINDOW_SIZE - 65535)

    def _init_upstream_h2(self) -> None:
        """Create a fresh upstream h2 connection state machine."""
        self._upstream_conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True)
        )
        self._streams.clear()
        self._upstream_to_client.clear()
        self._client_pending.clear()
        self._upstream_pending.clear()
        self._queued_requests.clear()

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
        self._apply_window_settings(self._upstream_conn)
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
        self._apply_window_settings(self._client_conn)
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
        self._apply_window_settings(self._client_conn)
        await self._flush_client()

        self._init_upstream_h2()
        self._upstream_conn.initiate_connection()
        self._apply_window_settings(self._upstream_conn)
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
                exc = client_task.exception()
                if exc and not isinstance(
                    exc, (ConnectionResetError, BrokenPipeError, asyncio.CancelledError)
                ):
                    raise exc
                return

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
            try:
                events = self._client_conn.receive_data(data)
            except Exception as exc:
                logger.debug(
                    "h2_client_receive_error",
                    host=self._host,
                    error=type(exc).__name__,
                    detail=str(exc)[:200],
                )
                return
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
            try:
                events = self._upstream_conn.receive_data(data)
            except Exception as exc:
                logger.debug(
                    "h2_upstream_receive_error",
                    host=self._host,
                    error=type(exc).__name__,
                    detail=str(exc)[:200],
                )
                return
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
            # Client sent WINDOW_UPDATE — flush pending response data
            self._drain_pending(self._client_conn, self._client_pending, event.stream_id)

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
            # Upstream sent WINDOW_UPDATE — flush pending request data
            self._drain_pending(self._upstream_conn, self._upstream_pending, event.stream_id)

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

        # Extract auth token so we never redact the request's own
        # credential when it also appears in the body (issue #64).
        # Also include session tokens previously seen in upstream
        # responses on this connection (issue #66).
        exclude_values: set[str] = set(self._session_tokens)
        for n, v in headers:
            if n == "authorization" and v:
                parts = v.split(None, 1)
                exclude_values.add(parts[-1] if parts else v)
                break

        # Scan the request body
        scanned_body = body
        if body and not state.skip_scan:
            try:
                scanned_body, alerts = self._scanner.scan_body(
                    body, content_type, exclude_values=exclude_values
                )
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

        # Forward to upstream — queue if MAX_CONCURRENT_STREAMS reached
        if not self._forward_to_upstream(stream_id, new_headers, scanned_body):
            # Stream limit reached — queue for later
            self._queued_requests.append(
                _QueuedRequest(client_stream_id=stream_id, headers=new_headers, body=scanned_body)
            )
            logger.debug(
                "h2_request_queued",
                host=self._host,
                client_stream=stream_id,
                queue_depth=len(self._queued_requests),
            )

    def _forward_to_upstream(
        self, client_stream_id: int, headers: list[tuple[str, str]], body: bytes
    ) -> bool:
        """Try to forward a request to upstream. Returns False if stream limit reached."""
        try:
            upstream_stream_id = self._upstream_conn.get_next_available_stream_id()
        except h2.exceptions.NoAvailableStreamIDError:
            return False

        state = self._streams.get(client_stream_id)
        if state is None:
            return True  # stream was reset while queued — discard silently

        try:
            self._upstream_conn.send_headers(
                upstream_stream_id, headers, end_stream=(len(body) == 0)
            )
        except h2.exceptions.TooManyStreamsError:
            return False

        state.upstream_stream_id = upstream_stream_id
        self._upstream_to_client[upstream_stream_id] = client_stream_id

        if body:
            remaining, es = self._send_data_with_flow_control(
                self._upstream_conn, upstream_stream_id, body, end_stream=True
            )
            if remaining:
                self._upstream_pending[upstream_stream_id] = (remaining, es)

        return True

    def _drain_queued_requests(self) -> None:
        """Send queued requests when upstream stream slots free up."""
        while self._queued_requests:
            req = self._queued_requests[0]
            if not self._forward_to_upstream(req.client_stream_id, req.headers, req.body):
                break  # still at limit
            self._queued_requests.pop(0)

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

        try:
            self._client_conn.send_headers(client_stream_id, decoded)
        except (h2.exceptions.StreamClosedError, h2.exceptions.ProtocolError):
            logger.debug("h2_stream_closed_on_headers", stream_id=client_stream_id)
            self._cleanup_stream(client_stream_id, upstream_stream_id)

    async def _on_response_data(
        self, upstream_stream_id: int, data: bytes, flow_controlled_length: int
    ) -> None:
        """Upstream sent response body data — relay to client."""
        # Always acknowledge to keep the connection-level flow control window open,
        # even if the stream was already cleaned up (race with reset/complete).
        self._upstream_conn.acknowledge_received_data(flow_controlled_length, upstream_stream_id)

        # Harvest JWTs the upstream issues so we don't redact them when the
        # client echoes them back in a follow-up request body (issue #66).
        if data and len(self._session_tokens) < MAX_SESSION_TOKENS:
            for tok in extract_session_tokens(data):
                if len(self._session_tokens) >= MAX_SESSION_TOKENS:
                    break
                self._session_tokens.add(tok)

        client_stream_id = self._upstream_to_client.get(upstream_stream_id)
        if client_stream_id is None:
            return

        # If there's already pending data for this stream, just append
        if client_stream_id in self._client_pending:
            existing, es = self._client_pending[client_stream_id]
            self._client_pending[client_stream_id] = (existing + data, es)
            return

        # Forward to client
        remaining, es = self._send_data_with_flow_control(
            self._client_conn, client_stream_id, data, end_stream=False
        )
        if remaining:
            self._client_pending[client_stream_id] = (remaining, es)

    async def _on_response_complete(self, upstream_stream_id: int) -> None:
        """Upstream finished sending response (END_STREAM)."""
        client_stream_id = self._upstream_to_client.get(upstream_stream_id)
        if client_stream_id is None:
            return

        if client_stream_id in self._client_pending:
            # Pending data still buffered — mark end_stream for when drain completes
            data, _ = self._client_pending[client_stream_id]
            self._client_pending[client_stream_id] = (data, True)
        else:
            try:
                self._client_conn.end_stream(client_stream_id)
            except (h2.exceptions.StreamClosedError, h2.exceptions.ProtocolError):
                pass  # stream already gone
            self._cleanup_stream(client_stream_id, upstream_stream_id)

        # Upstream stream slot freed — send queued requests
        self._drain_queued_requests()

    # --- Stream reset handling ---

    async def _on_client_stream_reset(self, stream_id: int) -> None:
        """Client reset a stream — propagate to upstream."""
        # Remove from queue if it hasn't been sent yet
        self._queued_requests = [
            q for q in self._queued_requests if q.client_stream_id != stream_id
        ]
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
            self._drain_queued_requests()

    # --- Helpers ---

    def _cleanup_stream(self, client_stream_id: int, upstream_stream_id: int) -> None:
        """Remove stream tracking state."""
        self._streams.pop(client_stream_id, None)
        self._upstream_to_client.pop(upstream_stream_id, None)
        self._client_pending.pop(client_stream_id, None)
        self._upstream_pending.pop(upstream_stream_id, None)

    def _drain_pending(
        self,
        conn: h2.connection.H2Connection,
        pending: dict[int, tuple[bytes, bool]],
        stream_id: int,
    ) -> None:
        """Flush pending data after a WindowUpdated event.

        stream_id=0 is a connection-level update — try all pending streams.
        """
        targets = list(pending.keys()) if stream_id == 0 else [stream_id]
        for sid in targets:
            if sid not in pending:
                continue
            data, end_stream = pending[sid]
            remaining, es = self._send_data_with_flow_control(conn, sid, data, end_stream)
            if remaining:
                pending[sid] = (remaining, es)
            else:
                del pending[sid]
                # If this was client-side pending with end_stream, cleanup the stream
                if end_stream and pending is self._client_pending:
                    # end_stream was already sent by _send_data_with_flow_control
                    state = self._streams.get(sid)
                    if state and state.upstream_stream_id is not None:
                        self._cleanup_stream(sid, state.upstream_stream_id)

    def _send_data_with_flow_control(
        self,
        conn: h2.connection.H2Connection,
        stream_id: int,
        data: bytes,
        end_stream: bool,
    ) -> tuple[bytes, bool]:
        """Send data respecting h2 flow control windows.

        Returns (unsent_data, pending_end_stream). If unsent_data is non-empty,
        the caller must buffer it and retry when a WindowUpdated event arrives.
        Returns (b"", False) if stream was closed — caller should discard.
        """
        offset = 0
        while offset < len(data):
            try:
                window = conn.local_flow_control_window(stream_id)
            except (h2.exceptions.StreamClosedError, h2.exceptions.ProtocolError):
                return b"", False  # stream gone, discard
            if window <= 0:
                return data[offset:], end_stream
            max_size = min(window, conn.max_outbound_frame_size)
            chunk = data[offset : offset + max_size]
            is_last = (offset + len(chunk) >= len(data)) and end_stream
            try:
                conn.send_data(stream_id, chunk, end_stream=is_last)
            except (h2.exceptions.StreamClosedError, h2.exceptions.ProtocolError):
                return b"", False  # stream gone, discard
            offset += len(chunk)
        return b"", False

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
        remaining, es = self._send_data_with_flow_control(
            self._client_conn, stream_id, error_body, end_stream=True
        )
        if remaining:
            self._client_pending[stream_id] = (remaining, es)
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
