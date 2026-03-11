"""Integration tests for the forward proxy."""

from __future__ import annotations

import asyncio
import ssl

import pytest

from secretgate.certs import CertAuthority
from secretgate.forward import start_forward_proxy
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
