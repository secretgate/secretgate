"""Forward proxy with TLS MITM for intercepting all HTTPS traffic.

Runs as a separate asyncio server alongside the FastAPI app.
Handles HTTP CONNECT tunnels by performing TLS MITM with generated certs.
"""

from __future__ import annotations

import asyncio
import re
import ssl
import sys
from urllib.parse import urlparse

import h11
import structlog

from secretgate.certs import CertAuthority
from secretgate.h2_handler import H2ConnectionHandler
from secretgate.scan import BlockedError, TextScanner

logger = structlog.get_logger()

MAX_BUFFER_SIZE = 10 * 1024 * 1024  # 10MB

# Paths that should never be scanned — auth/token endpoints contain
# credentials (JWTs, refresh tokens) that would be redacted and break
# authentication flows like OAuth token refresh.
_AUTH_PATH_PATTERNS = re.compile(
    r"(?:"
    r"/oauth(?:/|$)"  # /oauth/ or /oauth at end
    r"|/auth(?:/|$)"  # /auth/ or /auth at end
    r"|/token(?:/|$|\?)"  # /token, /token/, /token?...
    r"|/authorize(?:/|$|\?)"  # /authorize, /authorize/, /authorize?...
    r"|/\.well-known/"  # /.well-known/openid-configuration etc.
    r"|/login"  # /login endpoints
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


def _pkt_line(data: bytes) -> bytes:
    """Encode data as a git pkt-line (4-hex-digit length prefix including itself)."""
    length = len(data) + 4
    return f"{length:04x}".encode() + data


def _build_git_receive_pack_error(body: bytes, error_msg: str) -> bytes | None:
    """Build a git receive-pack report-status error response.

    Parses the ref name from the pkt-line prefix of the request body and
    returns a valid report-status response that git will display to the user.
    Returns None if we can't parse the ref name.
    """
    # Extract ref name from the pkt-line section before PACK
    # Format: <old-sha> <new-sha> <refname>\0<capabilities>\n
    try:
        # Find the first pkt-line with a ref update
        pack_idx = body.find(b"PACK")
        if pack_idx < 0:
            return None
        pkt_section = body[:pack_idx]
        # Decode and find lines with ref names
        text = pkt_section.decode("latin-1")
        ref_name = None
        for line in text.split("\n"):
            # Skip pkt-line length prefixes (first 4 chars are hex length)
            content = line[4:] if len(line) > 4 else line
            # Strip null byte and capabilities
            content = content.split("\x00")[0].strip()
            parts = content.split()
            if len(parts) >= 3 and parts[2].startswith("refs/"):
                ref_name = parts[2]
                break
        if not ref_name:
            return None
    except Exception:
        return None

    # Build report-status response using sideband-64k (band 1 for pack data)
    # First send error message on sideband 2 (progress/error)
    err_text = f"[secretgate] {error_msg}\n".encode()
    sideband_err = _pkt_line(b"\x02" + err_text)

    # Then send report-status on sideband 1
    unpack_line = _pkt_line(b"unpack ok\n")
    ng_msg = f"ng {ref_name} secretgate: secrets detected in push\n".encode()
    ng_line = _pkt_line(ng_msg)
    flush = b"0000"
    report = unpack_line + ng_line + flush
    sideband_report = _pkt_line(b"\x01" + report)

    return sideband_err + sideband_report + flush


class ForwardProxyServer:
    """Wraps asyncio.Server with active task tracking for clean shutdown."""

    def __init__(self, server: asyncio.Server):
        self._server = server
        self._tasks: set[asyncio.Task] = set()

    @property
    def sockets(self):
        return self._server.sockets

    def is_serving(self) -> bool:
        return self._server.is_serving()

    def close(self) -> None:
        self._server.close()
        for task in self._tasks:
            task.cancel()

    async def wait_closed(self) -> None:
        await self._server.wait_closed()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)


async def start_forward_proxy(
    host: str,
    port: int,
    ca: CertAuthority,
    scanner: TextScanner,
    passthrough_domains: list[str] | None = None,
    upstream_ssl: ssl.SSLContext | None = None,
) -> ForwardProxyServer:
    """Start the forward proxy server. Returns a ForwardProxyServer for lifecycle management."""
    passthrough = set(passthrough_domains or [])
    active_tasks: set[asyncio.Task] = set()

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        handler = _ConnectionHandler(reader, writer, ca, scanner, passthrough, upstream_ssl)
        try:
            await handler.run()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass  # client disconnected — normal
        except asyncio.CancelledError:
            pass  # task cancelled during shutdown
        except Exception as exc:
            logger.debug("forward_proxy_connection_error", error=str(exc))
        finally:
            if not writer.is_closing():
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    def client_connected(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        task = asyncio.create_task(handle_client(reader, writer))
        active_tasks.add(task)
        task.add_done_callback(active_tasks.discard)

    server = await asyncio.start_server(client_connected, host, port)
    proxy = ForwardProxyServer(server)
    proxy._tasks = active_tasks
    logger.info("forward_proxy_started", host=host, port=port)
    return proxy


class _ConnectionHandler:
    """Handles a single client connection to the forward proxy."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        ca: CertAuthority,
        scanner: TextScanner,
        passthrough_domains: set[str],
        upstream_ssl: ssl.SSLContext | None = None,
    ):
        self._reader = reader
        self._writer = writer
        self._ca = ca
        self._scanner = scanner
        self._passthrough = passthrough_domains
        self._upstream_ssl = upstream_ssl

    @staticmethod
    def _is_auth_path(path: str) -> bool:
        """Return True if the request path is an auth/token endpoint that should skip scanning."""
        return bool(_AUTH_PATH_PATTERNS.search(path))

    async def run(self) -> None:
        """Read the initial request and dispatch."""
        # Read the initial HTTP request line + headers
        header_data = await self._read_headers()
        if not header_data:
            return

        request_line, headers = self._parse_request(header_data)
        if not request_line:
            await self._send_error(self._writer, 400, "Bad Request", "Malformed HTTP request")
            return

        method, target, _ = request_line.split(" ", 2)

        if method.upper() == "CONNECT":
            await self._handle_connect(target, headers)
        else:
            await self._handle_plain_http(method, target, headers, header_data)

    async def _read_headers(self) -> bytes:
        """Read until we get the full HTTP headers (ending with \\r\\n\\r\\n)."""
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = await self._reader.read(8192)
            if not chunk:
                return b""
            buf += chunk
            if len(buf) > MAX_BUFFER_SIZE:
                await self._send_error(
                    self._writer,
                    413,
                    "Request Entity Too Large",
                    "Request headers exceed maximum buffer size",
                )
                return b""
        return buf

    def _parse_request(self, data: bytes) -> tuple[str, dict[str, str]]:
        """Parse HTTP request line and headers from raw bytes."""
        header_end = data.index(b"\r\n\r\n")
        header_block = data[:header_end].decode("latin-1")
        lines = header_block.split("\r\n")
        request_line = lines[0]

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip().lower()] = val.strip()

        return request_line, headers

    async def _handle_connect(self, target: str, headers: dict[str, str]) -> None:
        """Handle CONNECT method — establish TLS MITM tunnel."""
        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            port = int(port_str)
        else:
            host = target
            port = 443

        # Check if this domain should be passed through without MITM
        if host in self._passthrough:
            await self._passthrough_tunnel(host, port)
            return

        upstream_ssl = self._upstream_ssl or ssl.create_default_context()
        # Advertise h2 and http/1.1 to upstream so we can match client protocol
        upstream_ssl.set_alpn_protocols(["h2", "http/1.1"])

        # Connect to the real upstream with TLS verification
        try:
            up_reader, up_writer = await asyncio.open_connection(host, port, ssl=upstream_ssl)
        except Exception as exc:
            logger.warning("forward_upstream_connect_failed", host=host, error=str(exc))
            self._writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await self._writer.drain()
            return

        # Check what protocol upstream negotiated
        up_ssl_obj = up_writer.get_extra_info("ssl_object")
        upstream_proto = up_ssl_obj.selected_alpn_protocol() if up_ssl_obj else None

        # Tell the client the tunnel is established
        self._writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await self._writer.drain()

        # Upgrade client side to TLS using our generated cert (server-side)
        mitm_ctx = self._ca.get_domain_context(host)
        try:
            await self._writer.start_tls(mitm_ctx)
        except Exception as exc:
            logger.debug("forward_tls_handshake_failed", host=host, error=str(exc))
            up_writer.close()
            return

        # Check what protocol client negotiated
        client_ssl_obj = self._writer.get_extra_info("ssl_object")
        client_proto = client_ssl_obj.selected_alpn_protocol() if client_ssl_obj else None

        # Dispatch based on negotiated protocols
        use_h2 = client_proto == "h2" and upstream_proto == "h2"
        if client_proto == "h2" and upstream_proto != "h2":
            # Client wants h2 but upstream doesn't support it — reconnect upstream
            # with h1-only ALPN is not possible (already connected). Fall back to h1.
            # This shouldn't normally happen since our MITM cert advertises h2 only
            # when we know upstream supports it. But handle it gracefully.
            logger.debug(
                "h2_protocol_mismatch",
                host=host,
                client=client_proto,
                upstream=upstream_proto,
            )

        try:
            if use_h2:
                logger.debug("h2_relay_start", host=host)
                handler = H2ConnectionHandler(self._scanner, host)
                await handler.run(self._reader, self._writer, up_reader, up_writer)
            else:
                await self._relay_http(
                    self._reader,
                    self._writer,
                    up_reader,
                    up_writer,
                    host,
                    upstream_ssl=upstream_ssl,
                    upstream_port=port,
                )
        finally:
            if not up_writer.is_closing():
                up_writer.close()
                try:
                    await up_writer.wait_closed()
                except Exception:
                    pass

    async def _passthrough_tunnel(self, host: str, port: int) -> None:
        """Pass through a CONNECT tunnel without MITM (for passthrough domains)."""
        try:
            up_reader, up_writer = await asyncio.open_connection(host, port)
        except Exception as exc:
            logger.warning("forward_upstream_connect_failed", host=host, error=str(exc))
            self._writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await self._writer.drain()
            return

        self._writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await self._writer.drain()

        # Simple bidirectional relay
        await asyncio.gather(
            self._pipe(self._reader, up_writer),
            self._pipe(up_reader, self._writer),
            return_exceptions=True,
        )

    async def _pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Copy data from reader to writer until EOF."""
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass

    @staticmethod
    async def _send_error(
        writer: asyncio.StreamWriter, status: int, reason: str, body: str
    ) -> None:
        """Send an HTTP error response to the client."""
        body_bytes = body.encode()
        response = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: text/plain\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + body_bytes
        try:
            writer.write(response)
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass  # client already gone

    async def _relay_http(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
        host: str,
        upstream_ssl: ssl.SSLContext | None = None,
        upstream_port: int = 443,
    ) -> None:
        """Relay HTTP requests from client to upstream, scanning outbound bodies."""
        while True:
            # Read request headers from client
            req_header_data = b""
            while b"\r\n\r\n" not in req_header_data:
                chunk = await client_reader.read(8192)
                if not chunk:
                    return
                req_header_data += chunk
                if len(req_header_data) > MAX_BUFFER_SIZE:
                    logger.warning("forward_request_headers_too_large", host=host)
                    await self._send_error(
                        client_writer,
                        413,
                        "Request Entity Too Large",
                        "Request headers exceed maximum buffer size",
                    )
                    return

            # Split headers from any body data that was read
            header_end = req_header_data.index(b"\r\n\r\n") + 4
            headers_bytes = req_header_data[:header_end]
            body_start = req_header_data[header_end:]

            request_line, req_headers = self._parse_request(req_header_data)
            if not request_line:
                await self._send_error(client_writer, 400, "Bad Request", "Malformed HTTP request")
                return

            # Read the request body
            content_length_str = req_headers.get("content-length")
            req_transfer = req_headers.get("transfer-encoding", "").lower()
            body = body_start
            was_chunked = False

            if content_length_str is not None:
                content_length = int(content_length_str)
                while len(body) < content_length:
                    remaining = content_length - len(body)
                    chunk = await client_reader.read(min(remaining, 65536))
                    if not chunk:
                        break
                    body += chunk
            elif "chunked" in req_transfer:
                # Use h11 to decode chunked body into plain bytes so
                # redaction works on content only (not chunk-size framing) and
                # so we can switch to Content-Length framing for forwarding.
                was_chunked = True
                h11_conn = h11.Connection(our_role=h11.SERVER)
                h11_conn.receive_data(req_header_data)

                body_parts: list[bytes] = []
                done = False
                while True:
                    event = h11_conn.next_event()
                    if isinstance(event, h11.Request):
                        continue
                    elif isinstance(event, h11.Data):
                        body_parts.append(bytes(event.data))
                    elif isinstance(event, h11.EndOfMessage):
                        done = True
                        break
                    elif event is h11.NEED_DATA:
                        break
                    else:
                        break

                while not done:
                    chunk = await client_reader.read(65536)
                    if not chunk:
                        break
                    h11_conn.receive_data(chunk)
                    while True:
                        event = h11_conn.next_event()
                        if isinstance(event, h11.Data):
                            body_parts.append(bytes(event.data))
                        elif isinstance(event, h11.EndOfMessage):
                            done = True
                            break
                        elif event is h11.NEED_DATA:
                            break
                        else:
                            done = True
                            break

                body = b"".join(body_parts)
                content_length = len(body)
            else:
                content_length = len(body)

            # Scan outbound request body (skip auth endpoints to avoid
            # redacting OAuth tokens / refresh tokens)
            req_path = request_line.split(" ", 2)[1] if request_line else ""
            content_type = req_headers.get("content-type", "application/octet-stream")
            scanned_body = body
            skip_scan = self._is_auth_path(req_path)
            if skip_scan:
                logger.debug("forward_skip_auth_path", host=host, path=req_path)
            if body and content_length > 0 and not skip_scan:
                try:
                    scanned_body, alerts = self._scanner.scan_body(body, content_type)
                    for alert in alerts:
                        logger.warning("forward_proxy_alert", host=host, alert=alert)
                except BlockedError as exc:
                    # Send error back to the client
                    for alert in exc.alerts:
                        logger.error("forward_proxy_blocked", host=host, alert=alert)
                    error_msg = str(exc)
                    _print_block_notice(error_msg, exc.alerts, host)

                    # For git push: return a git protocol response so git
                    # displays our error message to the user
                    git_response = _build_git_receive_pack_error(body, error_msg)
                    if git_response is not None and "git-receive-pack" in content_type:
                        response = (
                            b"HTTP/1.1 200 OK\r\n"
                            b"Content-Type: application/x-git-receive-pack-result\r\n"
                            b"Content-Length: " + str(len(git_response)).encode() + b"\r\n"
                            b"Connection: close\r\n"
                            b"\r\n" + git_response
                        )
                    else:
                        error_body = (
                            f"[secretgate] {error_msg}\n"
                            f"Details:\n" + "\n".join(f"  - {a}" for a in exc.alerts) + "\n"
                        ).encode()
                        response = (
                            b"HTTP/1.1 403 Forbidden\r\n"
                            b"Content-Type: text/plain\r\n"
                            b"Content-Length: " + str(len(error_body)).encode() + b"\r\n"
                            b"Connection: close\r\n"
                            b"\r\n" + error_body
                        )
                    client_writer.write(response)
                    await client_writer.drain()
                    return

            # Update headers if body was modified or chunked encoding was decoded
            new_body_len = len(scanned_body)
            if was_chunked or (new_body_len != content_length and content_length > 0):
                headers_text = headers_bytes.decode("latin-1")
                if was_chunked:
                    # Remove Transfer-Encoding: chunked — body is now plain bytes
                    headers_text = re.sub(r"(?i)transfer-encoding:\s*chunked\r\n", "", headers_text)
                if re.search(r"(?i)content-length:", headers_text):
                    headers_text = re.sub(
                        r"(?i)content-length:\s*\d+",
                        f"Content-Length: {new_body_len}",
                        headers_text,
                    )
                else:
                    # No existing Content-Length — insert one before the blank line
                    headers_text = headers_text.replace(
                        "\r\n\r\n", f"\r\nContent-Length: {new_body_len}\r\n\r\n", 1
                    )
                headers_bytes = headers_text.encode("latin-1")

            # Forward to upstream (reconnect if upstream closed the connection)
            try:
                upstream_writer.write(headers_bytes + scanned_body)
                await upstream_writer.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                # Upstream closed — reconnect
                logger.debug("forward_upstream_reconnect", host=host)
                if not upstream_writer.is_closing():
                    upstream_writer.close()
                try:
                    _ssl = upstream_ssl or ssl.create_default_context()
                    upstream_reader, upstream_writer = await asyncio.open_connection(
                        host,
                        upstream_port,
                        ssl=_ssl,
                    )
                except Exception as exc:
                    logger.warning("forward_upstream_reconnect_failed", host=host, error=str(exc))
                    await self._send_error(
                        client_writer,
                        502,
                        "Bad Gateway",
                        "Failed to reconnect to upstream server",
                    )
                    return
                upstream_writer.write(headers_bytes + scanned_body)
                await upstream_writer.drain()

            # Read response headers from upstream (with one reconnect attempt)
            resp_header_data = b""
            reconnected = False
            while b"\r\n\r\n" not in resp_header_data:
                chunk = await upstream_reader.read(8192)
                if not chunk:
                    # Upstream closed before sending response — try reconnecting once
                    if not reconnected and (
                        upstream_ssl is not None or self._upstream_ssl is not None
                    ):
                        logger.debug("forward_upstream_reconnect_on_read", host=host)
                        if not upstream_writer.is_closing():
                            upstream_writer.close()
                        try:
                            _ssl = upstream_ssl or ssl.create_default_context()
                            upstream_reader, upstream_writer = await asyncio.open_connection(
                                host,
                                upstream_port,
                                ssl=_ssl,
                            )
                        except Exception:
                            await self._send_error(
                                client_writer,
                                502,
                                "Bad Gateway",
                                "Failed to reconnect to upstream server",
                            )
                            return
                        # Resend the request on the new connection
                        upstream_writer.write(headers_bytes + scanned_body)
                        await upstream_writer.drain()
                        resp_header_data = b""
                        reconnected = True
                        continue
                    logger.warning("forward_upstream_eof", host=host)
                    await self._send_error(
                        client_writer,
                        502,
                        "Bad Gateway",
                        "Upstream server closed connection without responding",
                    )
                    return
                resp_header_data += chunk
                if len(resp_header_data) > MAX_BUFFER_SIZE:
                    logger.warning("forward_response_headers_too_large", host=host)
                    await self._send_error(
                        client_writer,
                        502,
                        "Bad Gateway",
                        "Upstream response headers exceed maximum buffer size",
                    )
                    return

            resp_header_end = resp_header_data.index(b"\r\n\r\n") + 4
            resp_headers_bytes = resp_header_data[:resp_header_end]
            resp_body_start = resp_header_data[resp_header_end:]

            _, resp_headers = self._parse_request(resp_header_data)

            # Send response headers to client immediately
            client_writer.write(resp_headers_bytes)
            await client_writer.drain()

            # Relay response body based on transfer type
            transfer_encoding = resp_headers.get("transfer-encoding", "").lower()
            resp_content_length = resp_headers.get("content-length")
            connection = resp_headers.get("connection", "").lower()

            if resp_body_start:
                client_writer.write(resp_body_start)
                await client_writer.drain()

            if resp_content_length is not None:
                # Fixed-length body
                cl = int(resp_content_length)
                sent = len(resp_body_start)
                while sent < cl:
                    remaining = cl - sent
                    chunk = await upstream_reader.read(min(remaining, 65536))
                    if not chunk:
                        return
                    client_writer.write(chunk)
                    await client_writer.drain()
                    sent += len(chunk)
            elif "chunked" in transfer_encoding:
                # Use h11 to properly detect end of chunked response stream.
                # h11 tracks chunk framing and emits EndOfMessage at the terminal chunk.
                resp_conn = h11.Connection(our_role=h11.CLIENT)
                # Put h11 in the correct state by telling it we "sent" a request
                method_str = request_line.split(" ", 1)[0]
                # Only include headers h11 needs for response parsing (host).
                # Exclude body-framing headers so h11 doesn't expect request body data.
                skip_headers = {"content-length", "transfer-encoding", "content-type"}
                h11_headers = [
                    (k.encode("latin-1"), v.encode("latin-1"))
                    for k, v in req_headers.items()
                    if k not in skip_headers
                ]
                if "host" not in req_headers:
                    h11_headers.append((b"host", host.encode("latin-1")))
                resp_conn.send(
                    h11.Request(
                        method=method_str.encode("latin-1"), target=b"/", headers=h11_headers
                    )
                )
                resp_conn.send(h11.EndOfMessage())

                # Feed the response data we already have (headers + any body start)
                resp_conn.receive_data(resp_header_data)
                resp_done = False
                while True:
                    ev = resp_conn.next_event()
                    if isinstance(ev, (h11.Response, h11.InformationalResponse, h11.Data)):
                        continue
                    elif isinstance(ev, h11.EndOfMessage):
                        resp_done = True
                        break
                    elif ev is h11.NEED_DATA:
                        break
                    else:
                        break

                while not resp_done:
                    chunk = await upstream_reader.read(65536)
                    if not chunk:
                        return
                    client_writer.write(chunk)
                    await client_writer.drain()
                    resp_conn.receive_data(chunk)
                    while True:
                        ev = resp_conn.next_event()
                        if isinstance(ev, h11.Data):
                            continue
                        elif isinstance(ev, h11.EndOfMessage):
                            resp_done = True
                            break
                        elif ev is h11.NEED_DATA:
                            break
                        else:
                            resp_done = True
                            break
            else:
                # No content-length, no chunked — read until connection close
                try:
                    while True:
                        chunk = await upstream_reader.read(65536)
                        if not chunk:
                            break
                        client_writer.write(chunk)
                        await client_writer.drain()
                except (ConnectionResetError, BrokenPipeError):
                    pass
                return  # connection is done

            if connection == "close":
                return

    async def _handle_plain_http(
        self,
        method: str,
        target: str,
        headers: dict[str, str],
        raw_data: bytes,
    ) -> None:
        """Handle plain HTTP requests (non-CONNECT)."""
        parsed = urlparse(target)
        host = parsed.hostname or headers.get("host", "")
        port = parsed.port or 80

        if not host:
            self._writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await self._writer.drain()
            return

        try:
            up_reader, up_writer = await asyncio.open_connection(host, port)
        except Exception as exc:
            logger.warning("forward_upstream_connect_failed", host=host, error=str(exc))
            self._writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await self._writer.drain()
            return

        # Rewrite the request line to use relative path
        header_end = raw_data.index(b"\r\n\r\n") + 4
        headers_part = raw_data[:header_end]
        body_part = raw_data[header_end:]

        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        # Replace the absolute URL with relative path in the request line
        lines = headers_part.split(b"\r\n")
        parts = lines[0].split(b" ", 2)
        parts[1] = path.encode("latin-1")
        lines[0] = b" ".join(parts)
        modified_headers = b"\r\n".join(lines)

        # Read remaining body if Content-Length present
        content_length = int(headers.get("content-length", "0"))
        body = body_part
        while len(body) < content_length:
            remaining = content_length - len(body)
            chunk = await self._reader.read(min(remaining, 65536))
            if not chunk:
                break
            body += chunk

        # Scan body (skip auth endpoints to avoid redacting OAuth tokens)
        req_path = parsed.path or "/"
        content_type = headers.get("content-type", "application/octet-stream")
        scanned_body = body
        skip_scan = self._is_auth_path(req_path)
        if skip_scan:
            logger.debug("forward_skip_auth_path", host=host, path=req_path)
        if body and content_length > 0 and not skip_scan:
            try:
                scanned_body, alerts = self._scanner.scan_body(body, content_type)
                for alert in alerts:
                    logger.warning("forward_proxy_alert", host=host, alert=alert)
            except BlockedError as exc:
                for alert in exc.alerts:
                    logger.error("forward_proxy_blocked", host=host, alert=alert)
                error_msg = str(exc)
                _print_block_notice(error_msg, exc.alerts, host)
                error_body = (
                    f"[secretgate] {error_msg}\n"
                    f"Details:\n" + "\n".join(f"  - {a}" for a in exc.alerts) + "\n"
                ).encode()
                response = (
                    b"HTTP/1.1 403 Forbidden\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(error_body)).encode() + b"\r\n"
                    b"\r\n" + error_body
                )
                self._writer.write(response)
                await self._writer.drain()
                return

        # Update Content-Length if body was modified by scanning
        if len(scanned_body) != content_length and content_length > 0:
            hdr_text = modified_headers.decode("latin-1")
            hdr_text = re.sub(
                r"(?i)content-length:\s*\d+",
                f"Content-Length: {len(scanned_body)}",
                hdr_text,
            )
            modified_headers = hdr_text.encode("latin-1")

        up_writer.write(modified_headers + scanned_body)
        await up_writer.drain()

        # Relay response back
        try:
            while True:
                chunk = await up_reader.read(65536)
                if not chunk:
                    break
                self._writer.write(chunk)
                await self._writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            up_writer.close()
