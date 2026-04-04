"""Integration tests for the forward proxy."""

from __future__ import annotations

import asyncio
import ssl

import h2.config
import h2.connection
import h2.events
import pytest

from secretgate.certs import CertAuthority
from secretgate.forward import _ConnectionHandler, start_forward_proxy
from secretgate.scan import TextScanner
from secretgate.secrets.scanner import SecretScanner


@pytest.fixture
def ca(tmp_path):
    authority = CertAuthority(tmp_path / "certs")
    authority.ensure_ca()
    return authority


@pytest.fixture
def text_scanner():
    scanner = SecretScanner()
    return TextScanner(scanner, mode="redact")


@pytest.fixture
def block_scanner():
    scanner = SecretScanner()
    return TextScanner(scanner, mode="block")


@pytest.fixture
def upstream_ssl(ca):
    """SSL context that trusts only our test CA for upstream connections.

    Uses PROTOCOL_TLS_CLIENT instead of create_default_context() to avoid
    loading system CAs — a previously installed secretgate CA in the system
    trust store would conflict (same issuer name, different key).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(str(ca.ca_cert_path))
    return ctx


@pytest.fixture
async def proxy_server(ca, text_scanner, upstream_ssl):
    """Start a forward proxy on a random port."""
    server = await start_forward_proxy("127.0.0.1", 0, ca, text_scanner, upstream_ssl=upstream_ssl)
    port = server.sockets[0].getsockname()[1]
    yield server, port
    server.close()
    await server.wait_closed()


@pytest.fixture
async def blocking_proxy_server(ca, block_scanner, upstream_ssl):
    """Start a forward proxy in block mode."""
    server = await start_forward_proxy("127.0.0.1", 0, ca, block_scanner, upstream_ssl=upstream_ssl)
    port = server.sockets[0].getsockname()[1]
    yield server, port
    server.close()
    await server.wait_closed()


async def _run_echo_https_server(ca: CertAuthority, host: str = "127.0.0.1"):
    """Run a simple HTTPS echo server that returns the request body in the response."""
    domain = host
    ssl_ctx = ca.get_domain_context(domain)

    async def handle(reader, writer):
        # Read request headers
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = await reader.read(4096)
            if not chunk:
                writer.close()
                return
            data += chunk

        # Parse content-length
        header_end = data.index(b"\r\n\r\n") + 4
        body_start = data[header_end:]
        headers_text = data[:header_end].decode("latin-1")
        content_length = 0
        for line in headers_text.split("\r\n"):
            if line.lower().startswith("content-length:"):
                content_length = int(line.split(":", 1)[1].strip())
                break

        # Read remaining body
        body = body_start
        while len(body) < content_length:
            chunk = await reader.read(4096)
            if not chunk:
                break
            body += chunk

        # Echo back
        response_body = body if body else b"OK"
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(response_body)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" + response_body
        )
        writer.write(response)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, host, 0, ssl=ssl_ctx)
    return server


class TestForwardProxyStartup:
    async def test_starts_and_listens(self, proxy_server):
        server, port = proxy_server
        assert server.is_serving()
        assert port > 0

    async def test_accepts_connections(self, proxy_server):
        _, port = proxy_server
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.close()
        await writer.wait_closed()

    async def test_alpn_negotiates_h2(self, ca, proxy_server):
        """TLS MITM context should negotiate h2 via ALPN when client supports it."""
        _, port = proxy_server

        echo_server = await _run_echo_https_server(ca)
        echo_port = echo_server.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            connect_req = (
                f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n"
            )
            writer.write(connect_req.encode())
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert b"200 Connection Established" in response

            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_ctx.load_verify_locations(str(ca.ca_cert_path))
            ssl_ctx.set_alpn_protocols(["h2", "http/1.1"])
            await writer.start_tls(ssl_ctx, server_hostname="127.0.0.1")

            ssl_object = writer.get_extra_info("ssl_object")
            assert ssl_object is not None
            assert ssl_object.selected_alpn_protocol() == "h2"

            writer.close()
        finally:
            echo_server.close()
            await echo_server.wait_closed()

    async def test_alpn_falls_back_to_http11(self, ca, proxy_server):
        """When client only supports http/1.1, ALPN should negotiate http/1.1."""
        _, port = proxy_server

        echo_server = await _run_echo_https_server(ca)
        echo_port = echo_server.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            connect_req = (
                f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n"
            )
            writer.write(connect_req.encode())
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert b"200 Connection Established" in response

            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_ctx.load_verify_locations(str(ca.ca_cert_path))
            ssl_ctx.set_alpn_protocols(["http/1.1"])
            await writer.start_tls(ssl_ctx, server_hostname="127.0.0.1")

            ssl_object = writer.get_extra_info("ssl_object")
            assert ssl_object is not None
            assert ssl_object.selected_alpn_protocol() == "http/1.1"

            writer.close()
        finally:
            echo_server.close()
            await echo_server.wait_closed()


class TestPlainHTTP:
    async def test_plain_http_proxy(self, proxy_server):
        """Test proxying a plain HTTP request."""
        _, port = proxy_server

        # Start a simple HTTP echo server
        async def handle(reader, writer):
            await reader.read(4096)  # consume request
            body = b"echo response"
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n"
                b"\r\n" + body
            )
            writer.write(response)
            await writer.drain()
            writer.close()

        echo_server = await asyncio.start_server(handle, "127.0.0.1", 0)
        echo_port = echo_server.sockets[0].getsockname()[1]

        try:
            # Connect to proxy and send a plain HTTP request
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            request = (
                f"GET http://127.0.0.1:{echo_port}/test HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{echo_port}\r\n"
                f"\r\n"
            ).encode()
            writer.write(request)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert b"200 OK" in response
            assert b"echo response" in response

            writer.close()
            await writer.wait_closed()
        finally:
            echo_server.close()
            await echo_server.wait_closed()


class TestCONNECTTunnel:
    async def test_connect_tunnel_with_scanning(self, ca, proxy_server):
        """Test CONNECT tunnel with TLS MITM and secret scanning."""
        _, port = proxy_server

        # Start an HTTPS echo server using the same CA
        echo_server = await _run_echo_https_server(ca)
        echo_port = echo_server.sockets[0].getsockname()[1]

        try:
            # Connect to proxy
            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            # Send CONNECT
            connect_req = (
                f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n"
            )
            writer.write(connect_req.encode())
            await writer.drain()

            # Read CONNECT response
            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert b"200 Connection Established" in response

            # Upgrade to TLS (trust only our test CA, not system CAs)
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_ctx.load_verify_locations(str(ca.ca_cert_path))
            await writer.start_tls(ssl_ctx, server_hostname="127.0.0.1")

            # Send an HTTP request with a secret through the tunnel
            body = b"data=AKIAIOSFODNN7EXAMPLE"
            inner_request = (
                b"POST /test HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"\r\n" + body
            )
            writer.write(inner_request)
            await writer.drain()

            # Read the response — the secret should be redacted in the echoed body
            inner_response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert b"200 OK" in inner_response
            # The AWS key should have been redacted before reaching the echo server
            assert b"AKIAIOSFODNN7EXAMPLE" not in inner_response

            writer.close()
        finally:
            echo_server.close()
            await echo_server.wait_closed()

    async def test_connect_passthrough_domain(self, ca, text_scanner):
        """Passthrough domains should not be MITM'd."""
        server = await start_forward_proxy(
            "127.0.0.1",
            0,
            ca,
            text_scanner,
            passthrough_domains=["passthrough.test"],
        )
        port = server.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            # CONNECT to a passthrough domain (will fail to connect since it doesn't exist,
            # but we verify the proxy attempts a direct tunnel, not MITM)
            connect_req = b"CONNECT passthrough.test:443 HTTP/1.1\r\nHost: passthrough.test\r\n\r\n"
            writer.write(connect_req)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            # Should get 502 since passthrough.test doesn't exist, but NOT a MITM attempt
            assert b"502" in response

            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()


class TestBlockMode:
    async def test_connect_blocks_secrets(self, ca, blocking_proxy_server):
        """Block mode should return 403 when secrets are detected."""
        _, port = blocking_proxy_server

        echo_server = await _run_echo_https_server(ca)
        echo_port = echo_server.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            connect_req = (
                f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n"
            )
            writer.write(connect_req.encode())
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert b"200 Connection Established" in response

            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_ctx.load_verify_locations(str(ca.ca_cert_path))
            await writer.start_tls(ssl_ctx, server_hostname="127.0.0.1")

            body = b"secret=AKIAIOSFODNN7EXAMPLE"
            inner_request = (
                b"POST /test HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"\r\n" + body
            )
            writer.write(inner_request)
            await writer.drain()

            inner_response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert b"403 Forbidden" in inner_response

            writer.close()
        finally:
            echo_server.close()
            await echo_server.wait_closed()


async def _run_chunked_echo_https_server(ca: CertAuthority, host: str = "127.0.0.1"):
    """HTTPS echo server that returns the request body as a chunked response."""
    ssl_ctx = ca.get_domain_context(host)

    async def handle(reader, writer):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = await reader.read(4096)
            if not chunk:
                writer.close()
                return
            data += chunk

        header_end = data.index(b"\r\n\r\n") + 4
        body_start = data[header_end:]
        headers_text = data[:header_end].decode("latin-1")
        content_length = 0
        for line in headers_text.split("\r\n"):
            if line.lower().startswith("content-length:"):
                content_length = int(line.split(":", 1)[1].strip())
                break

        body = body_start
        while len(body) < content_length:
            chunk = await reader.read(4096)
            if not chunk:
                break
            body += chunk

        # Echo back using chunked transfer encoding
        response_body = body if body else b"OK"
        response_headers = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"
        )
        writer.write(response_headers)
        await writer.drain()

        # Send body in two chunks
        mid = len(response_body) // 2 or 1
        for part in [response_body[:mid], response_body[mid:]]:
            chunk_header = f"{len(part):x}\r\n".encode()
            writer.write(chunk_header + part + b"\r\n")
            await writer.drain()

        # Terminal chunk
        writer.write(b"0\r\n\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, host, 0, ssl=ssl_ctx)
    return server


class TestChunkedEncoding:
    async def test_chunked_request_body_decoded(self, ca, proxy_server):
        """Chunked request body should be decoded and scanned for secrets."""
        _, port = proxy_server

        echo_server = await _run_echo_https_server(ca)
        echo_port = echo_server.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            connect_req = (
                f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n"
            )
            writer.write(connect_req.encode())
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert b"200 Connection Established" in response

            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_ctx.load_verify_locations(str(ca.ca_cert_path))
            await writer.start_tls(ssl_ctx, server_hostname="127.0.0.1")

            # Send a chunked request with a secret embedded in chunk data
            secret = b"REDACTED<aws-access-key:1a5d44a2dca1>"
            chunk1 = b"data="
            chunk2 = secret
            chunked_body = (
                f"{len(chunk1):x}\r\n".encode()
                + chunk1
                + b"\r\n"
                + f"{len(chunk2):x}\r\n".encode()
                + chunk2
                + b"\r\n"
                + b"0\r\n\r\n"
            )
            inner_request = (
                b"POST /test HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"\r\n" + chunked_body
            )
            writer.write(inner_request)
            await writer.drain()

            inner_response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert b"200 OK" in inner_response
            # Secret should be redacted
            assert b"REDACTED<aws-access-key:1a5d44a2dca1>" not in inner_response

            writer.close()
        finally:
            echo_server.close()
            await echo_server.wait_closed()

    async def test_chunked_response_relayed(self, ca, proxy_server):
        """Chunked response from upstream should be streamed through to client."""
        _, port = proxy_server

        echo_server = await _run_chunked_echo_https_server(ca)
        echo_port = echo_server.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            connect_req = (
                f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n"
            )
            writer.write(connect_req.encode())
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert b"200 Connection Established" in response

            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_ctx.load_verify_locations(str(ca.ca_cert_path))
            await writer.start_tls(ssl_ctx, server_hostname="127.0.0.1")

            body = b"hello chunked world"
            inner_request = (
                b"POST /test HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"\r\n" + body
            )
            writer.write(inner_request)
            await writer.drain()

            inner_response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert b"200 OK" in inner_response
            assert b"Transfer-Encoding: chunked" in inner_response
            # Body is split across chunks, so check the terminal chunk was relayed
            assert b"0\r\n\r\n" in inner_response
            # Verify the body content is present (may span chunk boundaries)
            assert b"hello chu" in inner_response
            assert b"nked world" in inner_response

            writer.close()
        finally:
            echo_server.close()
            await echo_server.wait_closed()


class TestAuthPathSkip:
    """Auth/token endpoints should skip scanning to avoid redacting OAuth tokens."""

    def test_is_auth_path_matches(self):
        assert _ConnectionHandler._is_auth_path("/oauth/token") is True
        assert _ConnectionHandler._is_auth_path("/v1/oauth/token") is True
        assert _ConnectionHandler._is_auth_path("/auth/refresh") is True
        assert _ConnectionHandler._is_auth_path("/v1/auth/callback") is True
        assert _ConnectionHandler._is_auth_path("/token") is True
        assert _ConnectionHandler._is_auth_path("/api/token") is True
        assert _ConnectionHandler._is_auth_path("/authorize") is True
        assert _ConnectionHandler._is_auth_path("/.well-known/openid-configuration") is True
        assert _ConnectionHandler._is_auth_path("/login") is True

    def test_is_auth_path_no_match(self):
        assert _ConnectionHandler._is_auth_path("/v1/messages") is False
        assert _ConnectionHandler._is_auth_path("/v1/chat/completions") is False
        assert _ConnectionHandler._is_auth_path("/v1/embeddings") is False
        assert _ConnectionHandler._is_auth_path("/health") is False
        assert _ConnectionHandler._is_auth_path("/") is False

    async def test_auth_path_not_scanned_in_tunnel(self, ca, proxy_server):
        """Secrets in auth endpoint requests should pass through unredacted."""
        _, port = proxy_server

        echo_server = await _run_echo_https_server(ca)
        echo_port = echo_server.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            connect_req = (
                f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n"
            )
            writer.write(connect_req.encode())
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert b"200 Connection Established" in response

            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_ctx.load_verify_locations(str(ca.ca_cert_path))
            await writer.start_tls(ssl_ctx, server_hostname="127.0.0.1")

            # Send a request to an auth endpoint with a JWT (would normally be redacted)
            jwt = b"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature_here"
            body = b'{"refresh_token":"' + jwt + b'"}'
            inner_request = (
                b"POST /oauth/token HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"\r\n" + body
            )
            writer.write(inner_request)
            await writer.drain()

            inner_response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert b"200 OK" in inner_response
            # The JWT should NOT be redacted — auth paths skip scanning
            assert jwt in inner_response

            writer.close()
        finally:
            echo_server.close()
            await echo_server.wait_closed()

    async def test_non_auth_path_still_scanned(self, ca, proxy_server):
        """Secrets in regular API requests should still be redacted."""
        _, port = proxy_server

        echo_server = await _run_echo_https_server(ca)
        echo_port = echo_server.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            connect_req = (
                f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n"
            )
            writer.write(connect_req.encode())
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert b"200 Connection Established" in response

            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_ctx.load_verify_locations(str(ca.ca_cert_path))
            await writer.start_tls(ssl_ctx, server_hostname="127.0.0.1")

            # Send a request to a regular endpoint with a secret
            body = b"data=AKIAIOSFODNN7EXAMPLE"
            inner_request = (
                b"POST /v1/messages HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"\r\n" + body
            )
            writer.write(inner_request)
            await writer.drain()

            inner_response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert b"200 OK" in inner_response
            # The AWS key should still be redacted on non-auth paths
            assert b"AKIAIOSFODNN7EXAMPLE" not in inner_response

            writer.close()
        finally:
            echo_server.close()
            await echo_server.wait_closed()


class TestErrorResponses:
    async def test_502_when_upstream_drops_connection(self, ca, proxy_server):
        """Proxy should send 502 instead of EOF when upstream drops the connection."""
        _, port = proxy_server

        # Start a server that accepts the TLS connection then immediately closes
        ssl_ctx = ca.get_domain_context("127.0.0.1")

        async def handle(reader, writer):
            # Read request headers then close without responding
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                data += chunk
            writer.close()
            await writer.wait_closed()

        drop_server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ssl_ctx)
        drop_port = drop_server.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            connect_req = (
                f"CONNECT 127.0.0.1:{drop_port} HTTP/1.1\r\nHost: 127.0.0.1:{drop_port}\r\n\r\n"
            )
            writer.write(connect_req.encode())
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert b"200 Connection Established" in response

            ssl_ctx_client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_ctx_client.load_verify_locations(str(ca.ca_cert_path))
            await writer.start_tls(ssl_ctx_client, server_hostname="127.0.0.1")

            inner_request = b"GET /test HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
            writer.write(inner_request)
            await writer.drain()

            inner_response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            # Should get a proper 502 error, not EOF
            assert b"502 Bad Gateway" in inner_response

            writer.close()
        finally:
            drop_server.close()
            await drop_server.wait_closed()


# --- HTTP/2 test infrastructure ---


async def _run_h2_echo_server(ca: CertAuthority, host: str = "127.0.0.1"):
    """Run an HTTPS echo server that speaks HTTP/2 and echoes request bodies back."""
    ssl_ctx = ca.get_domain_context(host)

    async def handle(reader, writer):
        config = h2.config.H2Configuration(client_side=False)
        conn = h2.connection.H2Connection(config=config)
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        await writer.drain()

        # Per-stream state
        streams: dict[int, tuple[list, bytearray]] = {}  # stream_id -> (headers, body)

        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break

                events = conn.receive_data(data)
                for event in events:
                    if isinstance(event, h2.events.RequestReceived):
                        streams[event.stream_id] = (event.headers, bytearray())

                    elif isinstance(event, h2.events.DataReceived):
                        if event.stream_id in streams:
                            streams[event.stream_id][1].extend(event.data)
                        conn.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )

                    elif isinstance(event, h2.events.StreamEnded):
                        if event.stream_id in streams:
                            req_headers, req_body = streams.pop(event.stream_id)
                            response_body = bytes(req_body) if req_body else b"OK"
                            response_headers = [
                                (":status", "200"),
                                ("content-type", "text/plain"),
                                ("content-length", str(len(response_body))),
                            ]
                            conn.send_headers(event.stream_id, response_headers)
                            conn.send_data(event.stream_id, response_body, end_stream=True)

                    elif isinstance(event, h2.events.ConnectionTerminated):
                        writer.write(conn.data_to_send())
                        await writer.drain()
                        return

                writer.write(conn.data_to_send())
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            if not writer.is_closing():
                writer.close()

    server = await asyncio.start_server(handle, host, 0, ssl=ssl_ctx)
    return server


async def _h2_connect_and_upgrade(ca, proxy_port, echo_port, host="127.0.0.1"):
    """Helper: CONNECT through proxy, upgrade to TLS with h2 ALPN, return (reader, writer, h2_conn)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)

    connect_req = f"CONNECT {host}:{echo_port} HTTP/1.1\r\nHost: {host}:{echo_port}\r\n\r\n"
    writer.write(connect_req.encode())
    await writer.drain()

    response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
    assert b"200 Connection Established" in response

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.load_verify_locations(str(ca.ca_cert_path))
    ssl_ctx.set_alpn_protocols(["h2", "http/1.1"])
    await writer.start_tls(ssl_ctx, server_hostname=host)

    # Verify h2 was negotiated
    ssl_object = writer.get_extra_info("ssl_object")
    assert ssl_object.selected_alpn_protocol() == "h2"

    # Set up h2 client connection
    config = h2.config.H2Configuration(client_side=True)
    h2_conn = h2.connection.H2Connection(config=config)
    h2_conn.initiate_connection()
    writer.write(h2_conn.data_to_send())
    await writer.drain()

    # Read server settings
    data = await asyncio.wait_for(reader.read(65536), timeout=5.0)
    h2_conn.receive_data(data)
    writer.write(h2_conn.data_to_send())
    await writer.drain()

    return reader, writer, h2_conn


async def _h2_send_request(h2_conn, writer, headers, body=b""):
    """Send an h2 request, return the stream_id."""
    stream_id = h2_conn.get_next_available_stream_id()
    h2_conn.send_headers(stream_id, headers, end_stream=(len(body) == 0))
    if body:
        h2_conn.send_data(stream_id, body, end_stream=True)
    writer.write(h2_conn.data_to_send())
    await writer.drain()
    return stream_id


async def _h2_read_response(reader, h2_conn, writer, stream_id, timeout=5.0):
    """Read an h2 response for the given stream_id, return (status, headers, body)."""
    response_headers = None
    body = bytearray()
    done = False

    deadline = asyncio.get_event_loop().time() + timeout
    while not done:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            raise asyncio.TimeoutError()
        data = await asyncio.wait_for(reader.read(65536), timeout=remaining)
        if not data:
            break
        events = h2_conn.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.ResponseReceived) and event.stream_id == stream_id:
                response_headers = event.headers
            elif isinstance(event, h2.events.DataReceived) and event.stream_id == stream_id:
                body.extend(event.data)
                h2_conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            elif isinstance(event, h2.events.StreamEnded) and event.stream_id == stream_id:
                done = True
            elif isinstance(event, h2.events.StreamReset) and event.stream_id == stream_id:
                done = True
        writer.write(h2_conn.data_to_send())
        await writer.drain()

    status = None
    hdrs = {}
    if response_headers:
        for name, value in response_headers:
            n = name.decode("utf-8") if isinstance(name, bytes) else name
            v = value.decode("utf-8") if isinstance(value, bytes) else value
            if n == ":status":
                status = int(v)
            else:
                hdrs[n] = v

    return status, hdrs, bytes(body)


class TestH2Tunnel:
    """HTTP/2 support through CONNECT tunnel with TLS MITM."""

    async def test_h2_echo_through_proxy(self, ca, proxy_server):
        """Basic h2 request/response through the MITM tunnel."""
        _, port = proxy_server

        echo_server = await _run_h2_echo_server(ca)
        echo_port = echo_server.sockets[0].getsockname()[1]

        try:
            reader, writer, h2_conn = await _h2_connect_and_upgrade(ca, port, echo_port)

            headers = [
                (":method", "POST"),
                (":path", "/test"),
                (":scheme", "https"),
                (":authority", "127.0.0.1"),
                ("content-type", "text/plain"),
                ("content-length", "5"),
            ]
            stream_id = await _h2_send_request(h2_conn, writer, headers, body=b"hello")

            status, hdrs, body = await _h2_read_response(reader, h2_conn, writer, stream_id)
            assert status == 200
            assert body == b"hello"

            writer.close()
        finally:
            echo_server.close()
            await echo_server.wait_closed()

    async def test_h2_secret_redacted(self, ca, proxy_server):
        """Secrets in h2 request bodies should be redacted."""
        _, port = proxy_server

        echo_server = await _run_h2_echo_server(ca)
        echo_port = echo_server.sockets[0].getsockname()[1]

        try:
            reader, writer, h2_conn = await _h2_connect_and_upgrade(ca, port, echo_port)

            secret = b"AKIAIOSFODNN7EXAMPLE"
            body = b"data=" + secret
            headers = [
                (":method", "POST"),
                (":path", "/v1/messages"),
                (":scheme", "https"),
                (":authority", "127.0.0.1"),
                ("content-type", "application/x-www-form-urlencoded"),
                ("content-length", str(len(body))),
            ]
            stream_id = await _h2_send_request(h2_conn, writer, headers, body=body)

            status, hdrs, resp_body = await _h2_read_response(reader, h2_conn, writer, stream_id)
            assert status == 200
            # The AWS key should be redacted
            assert b"AKIAIOSFODNN7EXAMPLE" not in resp_body
            assert b"REDACTED<" in resp_body

            writer.close()
        finally:
            echo_server.close()
            await echo_server.wait_closed()

    async def test_h2_block_mode(self, ca, blocking_proxy_server):
        """Block mode should return 403 on h2 stream when secrets detected."""
        _, port = blocking_proxy_server

        echo_server = await _run_h2_echo_server(ca)
        echo_port = echo_server.sockets[0].getsockname()[1]

        try:
            reader, writer, h2_conn = await _h2_connect_and_upgrade(ca, port, echo_port)

            body = b"secret=AKIAIOSFODNN7EXAMPLE"
            headers = [
                (":method", "POST"),
                (":path", "/test"),
                (":scheme", "https"),
                (":authority", "127.0.0.1"),
                ("content-type", "text/plain"),
                ("content-length", str(len(body))),
            ]
            stream_id = await _h2_send_request(h2_conn, writer, headers, body=body)

            status, hdrs, resp_body = await _h2_read_response(reader, h2_conn, writer, stream_id)
            assert status == 403
            assert b"[secretgate]" in resp_body

            writer.close()
        finally:
            echo_server.close()
            await echo_server.wait_closed()

    async def test_h2_auth_path_skip(self, ca, proxy_server):
        """Auth endpoints should skip scanning in h2 mode."""
        _, port = proxy_server

        echo_server = await _run_h2_echo_server(ca)
        echo_port = echo_server.sockets[0].getsockname()[1]

        try:
            reader, writer, h2_conn = await _h2_connect_and_upgrade(ca, port, echo_port)

            jwt = b"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature_here"
            body = b'{"refresh_token":"' + jwt + b'"}'
            headers = [
                (":method", "POST"),
                (":path", "/oauth/token"),
                (":scheme", "https"),
                (":authority", "127.0.0.1"),
                ("content-type", "application/json"),
                ("content-length", str(len(body))),
            ]
            stream_id = await _h2_send_request(h2_conn, writer, headers, body=body)

            status, hdrs, resp_body = await _h2_read_response(reader, h2_conn, writer, stream_id)
            assert status == 200
            # JWT should NOT be redacted — auth path skips scanning
            assert jwt in resp_body

            writer.close()
        finally:
            echo_server.close()
            await echo_server.wait_closed()

    async def test_h2_no_body_request(self, ca, proxy_server):
        """GET request with no body should work through h2."""
        _, port = proxy_server

        echo_server = await _run_h2_echo_server(ca)
        echo_port = echo_server.sockets[0].getsockname()[1]

        try:
            reader, writer, h2_conn = await _h2_connect_and_upgrade(ca, port, echo_port)

            headers = [
                (":method", "GET"),
                (":path", "/health"),
                (":scheme", "https"),
                (":authority", "127.0.0.1"),
            ]
            stream_id = await _h2_send_request(h2_conn, writer, headers, body=b"")

            status, hdrs, body = await _h2_read_response(reader, h2_conn, writer, stream_id)
            assert status == 200
            assert body == b"OK"

            writer.close()
        finally:
            echo_server.close()
            await echo_server.wait_closed()

    async def test_h2_upstream_reconnect(self, ca, proxy_server):
        """After upstream closes h2 connection, proxy should reconnect for next request."""
        _, port = proxy_server

        # Use an h2 echo server that sends GOAWAY after the first response
        ssl_ctx = ca.get_domain_context("127.0.0.1")
        request_count = 0

        async def h2_handle_once(h2_reader, h2_writer):
            """H2 server that closes connection after first request via GOAWAY."""
            nonlocal request_count
            config = h2.config.H2Configuration(client_side=False)
            conn = h2.connection.H2Connection(config=config)
            conn.initiate_connection()
            h2_writer.write(conn.data_to_send())
            await h2_writer.drain()
            streams: dict[int, tuple[list, bytearray]] = {}
            try:
                while True:
                    data = await h2_reader.read(65536)
                    if not data:
                        break
                    events = conn.receive_data(data)
                    for event in events:
                        if isinstance(event, h2.events.RequestReceived):
                            streams[event.stream_id] = (event.headers, bytearray())
                        elif isinstance(event, h2.events.DataReceived):
                            if event.stream_id in streams:
                                streams[event.stream_id][1].extend(event.data)
                            conn.acknowledge_received_data(
                                event.flow_controlled_length, event.stream_id
                            )
                        elif isinstance(event, h2.events.StreamEnded):
                            if event.stream_id in streams:
                                _, req_body = streams.pop(event.stream_id)
                                resp_body = bytes(req_body) if req_body else b"OK"
                                conn.send_headers(
                                    event.stream_id,
                                    [
                                        (":status", "200"),
                                        ("content-type", "text/plain"),
                                        ("content-length", str(len(resp_body))),
                                    ],
                                )
                                conn.send_data(event.stream_id, resp_body, end_stream=True)
                                request_count += 1
                                if request_count == 1:
                                    # After first response, send GOAWAY and close
                                    conn.close_connection(error_code=0)
                                    h2_writer.write(conn.data_to_send())
                                    await h2_writer.drain()
                                    h2_writer.close()
                                    return
                    h2_writer.write(conn.data_to_send())
                    await h2_writer.drain()
            except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
                pass
            finally:
                if not h2_writer.is_closing():
                    h2_writer.close()

        echo_server = await asyncio.start_server(h2_handle_once, "127.0.0.1", 0, ssl=ssl_ctx)
        echo_port = echo_server.sockets[0].getsockname()[1]

        try:
            reader, writer, h2_conn = await _h2_connect_and_upgrade(ca, port, echo_port)

            # First request — works, then server sends GOAWAY and closes
            headers = [
                (":method", "POST"),
                (":path", "/test"),
                (":scheme", "https"),
                (":authority", "127.0.0.1"),
                ("content-type", "text/plain"),
                ("content-length", "5"),
            ]
            stream_id = await _h2_send_request(h2_conn, writer, headers, body=b"hello")
            status, _, body = await _h2_read_response(reader, h2_conn, writer, stream_id)
            assert status == 200
            assert body == b"hello"

            # Give proxy time to detect upstream GOAWAY/close and reconnect
            await asyncio.sleep(0.5)

            # Second request — proxy should have reconnected to the same echo server
            # (which now accepts new connections and serves normally)
            headers2 = [
                (":method", "POST"),
                (":path", "/test2"),
                (":scheme", "https"),
                (":authority", "127.0.0.1"),
                ("content-type", "text/plain"),
                ("content-length", "5"),
            ]
            stream_id2 = await _h2_send_request(h2_conn, writer, headers2, body=b"world")
            status2, _, body2 = await _h2_read_response(
                reader, h2_conn, writer, stream_id2, timeout=10.0
            )
            assert status2 == 200
            assert body2 == b"world"

            writer.close()
        finally:
            echo_server.close()
            await echo_server.wait_closed()

    async def test_h2_large_response_flow_control(self, ca, proxy_server):
        """Large responses exceeding the H2 flow control window must arrive intact."""
        _, port = proxy_server

        # 200KB response — well over the default 64KB H2 window
        echo_server, expected_body = await _run_h2_large_response_server(ca, 200_000)
        echo_port = echo_server.sockets[0].getsockname()[1]

        try:
            reader, writer, h2_conn = await _h2_connect_and_upgrade(ca, port, echo_port)

            headers = [
                (":method", "GET"),
                (":path", "/large"),
                (":scheme", "https"),
                (":authority", "127.0.0.1"),
            ]
            stream_id = await _h2_send_request(h2_conn, writer, headers)

            status, _, body = await _h2_read_response(
                reader, h2_conn, writer, stream_id, timeout=15.0
            )
            assert status == 200
            assert len(body) == len(expected_body)
            assert body == expected_body

            writer.close()
        finally:
            echo_server.close()
            await echo_server.wait_closed()


async def _run_h2_large_response_server(
    ca: CertAuthority, response_size: int, host: str = "127.0.0.1"
):
    """H2 server that returns a large response body, handling flow control properly."""
    ssl_ctx = ca.get_domain_context(host)
    # Generate deterministic response data
    pattern = b"ABCDEFGHIJKLMNOP"  # 16 bytes
    response_body = (pattern * (response_size // len(pattern) + 1))[:response_size]

    async def handle(reader, writer):
        config = h2.config.H2Configuration(client_side=False)
        conn = h2.connection.H2Connection(config=config)
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        await writer.drain()

        pending: dict[int, tuple[bytes, int]] = {}  # stream_id -> (remaining_data, offset)

        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break

                events = conn.receive_data(data)
                for event in events:
                    if isinstance(event, h2.events.RequestReceived):
                        pass  # wait for stream end

                    elif isinstance(event, h2.events.DataReceived):
                        conn.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )

                    elif isinstance(event, h2.events.StreamEnded):
                        resp_headers = [
                            (":status", "200"),
                            ("content-type", "application/octet-stream"),
                            ("content-length", str(len(response_body))),
                        ]
                        conn.send_headers(event.stream_id, resp_headers)
                        # Send as much as flow control allows
                        offset = 0
                        while offset < len(response_body):
                            window = conn.local_flow_control_window(event.stream_id)
                            if window <= 0:
                                pending[event.stream_id] = (response_body, offset)
                                break
                            chunk_size = min(
                                window, conn.max_outbound_frame_size, len(response_body) - offset
                            )
                            is_last = offset + chunk_size >= len(response_body)
                            conn.send_data(
                                event.stream_id,
                                response_body[offset : offset + chunk_size],
                                end_stream=is_last,
                            )
                            offset += chunk_size
                        else:
                            pending.pop(event.stream_id, None)

                    elif isinstance(event, h2.events.WindowUpdated):
                        sid = event.stream_id
                        targets = list(pending.keys()) if sid == 0 else [sid]
                        for s in targets:
                            if s not in pending:
                                continue
                            body_data, off = pending[s]
                            while off < len(body_data):
                                w = conn.local_flow_control_window(s)
                                if w <= 0:
                                    break
                                cs = min(w, conn.max_outbound_frame_size, len(body_data) - off)
                                is_last = off + cs >= len(body_data)
                                conn.send_data(s, body_data[off : off + cs], end_stream=is_last)
                                off += cs
                            if off >= len(body_data):
                                del pending[s]
                            else:
                                pending[s] = (body_data, off)

                    elif isinstance(event, h2.events.ConnectionTerminated):
                        writer.write(conn.data_to_send())
                        await writer.drain()
                        return

                writer.write(conn.data_to_send())
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            if not writer.is_closing():
                writer.close()

    server = await asyncio.start_server(handle, host, 0, ssl=ssl_ctx)
    return server, response_body


async def _run_websocket_echo_server(ca: CertAuthority, host: str = "127.0.0.1"):
    """HTTPS server that accepts WebSocket upgrades and echoes one message back."""
    ssl_ctx = ca.get_domain_context(host)

    async def handle(reader, writer):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = await reader.read(4096)
            if not chunk:
                writer.close()
                return
            data += chunk

        headers_text = data.split(b"\r\n\r\n")[0].decode("latin-1")
        headers = {}
        for line in headers_text.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        if headers.get("upgrade", "").lower() != "websocket":
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        # Send 101 Switching Protocols
        import hashlib
        import base64

        ws_key = headers.get("sec-websocket-key", "")
        accept = base64.b64encode(
            hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-5AB5DC85B175").encode()).digest()
        ).decode()
        response = (
            f"HTTP/1.1 101 Switching Protocols\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            f"\r\n"
        ).encode()
        writer.write(response)
        await writer.drain()

        # Read one WebSocket frame and echo it back
        # Minimal frame parsing: client frames are masked (RFC 6455)
        try:
            frame_header = await asyncio.wait_for(reader.read(2), timeout=5.0)
            if len(frame_header) < 2:
                writer.close()
                return
            payload_len = frame_header[1] & 0x7F
            is_masked = bool(frame_header[1] & 0x80)
            if payload_len == 126:
                ext = await reader.read(2)
                payload_len = int.from_bytes(ext, "big")
            elif payload_len == 127:
                ext = await reader.read(8)
                payload_len = int.from_bytes(ext, "big")

            mask_key = b""
            if is_masked:
                mask_key = await reader.read(4)

            payload = await reader.read(payload_len)
            if is_masked:
                payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

            # Send unmasked text frame back
            resp_frame = bytes([0x81, len(payload)]) + payload
            writer.write(resp_frame)
            await writer.drain()
        except Exception:
            pass
        writer.close()

    server = await asyncio.start_server(handle, host, 0, ssl=ssl_ctx)
    return server


async def _run_rejecting_upgrade_server(ca: CertAuthority, host: str = "127.0.0.1"):
    """HTTPS server that rejects WebSocket upgrades with 403."""
    ssl_ctx = ca.get_domain_context(host)

    async def handle(reader, writer):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = await reader.read(4096)
            if not chunk:
                writer.close()
                return
            data += chunk
        body = b"WebSocket not allowed"
        response = (
            b"HTTP/1.1 403 Forbidden\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" + body
        )
        writer.write(response)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, host, 0, ssl=ssl_ctx)
    return server


class TestWebSocketPassthrough:
    """WebSocket upgrade requests should be detected and passed through."""

    async def _connect_and_tls(self, ca, port, echo_port):
        """Helper: CONNECT to proxy, TLS handshake, return (reader, writer)."""
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        connect_req = (
            f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n"
        )
        writer.write(connect_req.encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
        assert b"200 Connection Established" in response

        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.load_verify_locations(str(ca.ca_cert_path))
        await writer.start_tls(ssl_ctx, server_hostname="127.0.0.1")
        return reader, writer

    async def test_websocket_upgrade_passthrough(self, ca, proxy_server):
        """WebSocket upgrade should be forwarded and bidirectional pipe established."""
        _, port = proxy_server

        echo_server = await _run_websocket_echo_server(ca)
        echo_port = echo_server.sockets[0].getsockname()[1]

        try:
            reader, writer = await self._connect_and_tls(ca, port, echo_port)

            # Send WebSocket upgrade request
            upgrade_req = (
                b"GET /ws HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                b"Sec-WebSocket-Version: 13\r\n"
                b"\r\n"
            )
            writer.write(upgrade_req)
            await writer.drain()

            # Should receive 101 Switching Protocols
            resp = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert b"101 Switching Protocols" in resp
            assert b"Upgrade: websocket" in resp

            # Send a masked WebSocket text frame
            payload = b"hello websocket"
            mask_key = b"\x01\x02\x03\x04"
            masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
            frame = bytes([0x81, 0x80 | len(payload)]) + mask_key + masked
            writer.write(frame)
            await writer.drain()

            # Read echoed frame (unmasked from server)
            echo_frame = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert len(echo_frame) >= 2
            echo_payload_len = echo_frame[1] & 0x7F
            echo_payload = echo_frame[2 : 2 + echo_payload_len]
            assert echo_payload == b"hello websocket"

            writer.close()
        finally:
            echo_server.close()
            await echo_server.wait_closed()

    async def test_non_websocket_request_still_scanned(self, ca, proxy_server):
        """Regular POST requests should still go through scanning, not the WebSocket path."""
        _, port = proxy_server

        echo_server = await _run_echo_https_server(ca)
        echo_port = echo_server.sockets[0].getsockname()[1]

        try:
            reader, writer = await self._connect_and_tls(ca, port, echo_port)

            body = b"secret=AKIAIOSFODNN7EXAMPLE"
            inner_request = (
                b"POST /test HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"\r\n" + body
            )
            writer.write(inner_request)
            await writer.drain()

            inner_response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert b"200 OK" in inner_response
            assert b"AKIAIOSFODNN7EXAMPLE" not in inner_response

            writer.close()
        finally:
            echo_server.close()
            await echo_server.wait_closed()

    async def test_websocket_upgrade_rejected_by_upstream(self, ca, proxy_server):
        """If upstream rejects the upgrade (non-101), the error should be forwarded to client."""
        _, port = proxy_server

        reject_server = await _run_rejecting_upgrade_server(ca)
        reject_port = reject_server.sockets[0].getsockname()[1]

        try:
            reader, writer = await self._connect_and_tls(ca, port, reject_port)

            upgrade_req = (
                b"GET /ws HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                b"Sec-WebSocket-Version: 13\r\n"
                b"\r\n"
            )
            writer.write(upgrade_req)
            await writer.drain()

            resp = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert b"403 Forbidden" in resp
            assert b"WebSocket not allowed" in resp

            writer.close()
        finally:
            reject_server.close()
            await reject_server.wait_closed()
