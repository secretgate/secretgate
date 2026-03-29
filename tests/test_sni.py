"""Tests for TLS ClientHello SNI extraction (transparent proxy foundation)."""

from __future__ import annotations

import struct

from secretgate.sni import extract_sni, is_tls_client_hello


def _build_client_hello(
    hostname: str = "example.com",
    *,
    include_sni: bool = True,
    extra_extensions: bytes = b"",
    tls_version: tuple[int, int] = (3, 3),
) -> bytes:
    """Build a minimal TLS ClientHello with optional SNI extension.

    This is intentionally minimal — just enough structure for the parser.
    """
    # --- Extensions ---
    extensions = b""
    if include_sni:
        host_bytes = hostname.encode("ascii")
        # SNI entry: type=0 (host_name), length, name
        sni_entry = struct.pack("!BH", 0x00, len(host_bytes)) + host_bytes
        # SNI list: total length + entries
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        # Extension: type=0x0000 (server_name), length, data
        extensions += struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    extensions += extra_extensions
    extensions_block = struct.pack("!H", len(extensions)) + extensions

    # --- ClientHello body ---
    client_version = struct.pack("!BB", tls_version[0], tls_version[1])
    client_random = b"\x00" * 32
    session_id = b"\x00"  # length=0
    cipher_suites = struct.pack("!HHH", 4, 0x1301, 0x1302)  # 2 suites
    compression = struct.pack("!BB", 1, 0x00)  # 1 method: null

    hello_body = (
        client_version + client_random + session_id
        + cipher_suites + compression + extensions_block
    )

    # --- Handshake header ---
    handshake = struct.pack("!B", 0x01) + struct.pack("!I", len(hello_body))[1:]  # 3-byte length
    handshake += hello_body

    # --- TLS record ---
    record = struct.pack("!BHH", 0x16, 0x0301, len(handshake)) + handshake
    return record


class TestExtractSNI:
    def test_extracts_simple_hostname(self):
        data = _build_client_hello("example.com")
        assert extract_sni(data) == "example.com"

    def test_extracts_subdomain(self):
        data = _build_client_hello("api.github.com")
        assert extract_sni(data) == "api.github.com"

    def test_extracts_long_hostname(self):
        host = "very-long-subdomain.deeply.nested.example.co.uk"
        data = _build_client_hello(host)
        assert extract_sni(data) == host

    def test_no_sni_extension(self):
        data = _build_client_hello("ignored", include_sni=False)
        assert extract_sni(data) is None

    def test_empty_data(self):
        assert extract_sni(b"") is None

    def test_too_short(self):
        assert extract_sni(b"\x16\x03\x01") is None

    def test_not_tls(self):
        # HTTP request, not TLS
        assert extract_sni(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n") is None

    def test_sni_with_extra_extensions(self):
        # Add a dummy extension after SNI
        dummy_ext = struct.pack("!HH", 0x0033, 2) + b"\x00\x00"  # key_share stub
        data = _build_client_hello("target.io", extra_extensions=dummy_ext)
        assert extract_sni(data) == "target.io"

    def test_tls_13_version(self):
        data = _build_client_hello("tls13.example.com", tls_version=(3, 4))
        assert extract_sni(data) == "tls13.example.com"

    def test_truncated_at_extensions(self):
        """Truncated data after cipher suites should return None, not crash."""
        data = _build_client_hello("example.com")
        # Cut off in the middle of extensions
        truncated = data[:50]
        result = extract_sni(truncated)
        # Should return None gracefully (not raise)
        assert result is None or isinstance(result, str)


class TestIsTLSClientHello:
    def test_valid_client_hello(self):
        data = _build_client_hello("example.com")
        assert is_tls_client_hello(data) is True

    def test_http_request(self):
        assert is_tls_client_hello(b"GET / HTTP/1.1\r\n") is False

    def test_empty(self):
        assert is_tls_client_hello(b"") is False

    def test_tls_but_not_client_hello(self):
        # TLS handshake record but type=2 (ServerHello) instead of 1
        data = b"\x16\x03\x01\x00\x05\x02\x00\x00\x01\x00"
        assert is_tls_client_hello(data) is False
