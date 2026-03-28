"""Tests for TLS ClientHello SNI parser."""

from __future__ import annotations

import struct

import pytest

from secretgate.sni import SNIParseError, is_tls_client_hello, parse_sni


def _build_client_hello(
    hostname: str | None = "example.com",
    *,
    session_id: bytes = b"",
    cipher_suites: bytes = b"\x00\x02\x13\x01",  # TLS_AES_128_GCM_SHA256
    compression: bytes = b"\x01\x00",  # 1 method: null
    extra_extensions: bytes = b"",
    tls_version: tuple[int, int] = (0x03, 0x03),  # TLS 1.2
    include_sni: bool = True,
) -> bytes:
    """Build a minimal TLS ClientHello with optional SNI extension."""
    # Build extensions
    extensions = b""

    if hostname is not None and include_sni:
        # SNI extension
        host_bytes = hostname.encode("ascii")
        # ServerName: NameType(1) + Length(2) + Name
        server_name = struct.pack("!BH", 0x00, len(host_bytes)) + host_bytes
        # ServerNameList: Length(2) + ServerName entries
        sni_list = struct.pack("!H", len(server_name)) + server_name
        # Extension: Type(2) + Length(2) + Data
        extensions += struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    extensions += extra_extensions

    # ClientHello body
    body = b""
    # ProtocolVersion (2 bytes)
    body += bytes(tls_version)
    # Random (32 bytes)
    body += b"\x00" * 32
    # SessionID
    body += struct.pack("!B", len(session_id)) + session_id
    # CipherSuites
    body += struct.pack("!H", len(cipher_suites)) + cipher_suites
    # CompressionMethods
    body += compression
    # Extensions
    if extensions:
        body += struct.pack("!H", len(extensions)) + extensions

    # Handshake header: type(1) + length(3)
    handshake = struct.pack("!B", 0x01) + struct.pack("!I", len(body))[1:]  # 3-byte length
    handshake += body

    # TLS record header: ContentType(1) + Version(2) + Length(2)
    record = struct.pack("!BHH", 0x16, 0x0301, len(handshake)) + handshake

    return record


class TestParseSNI:
    def test_basic_sni(self):
        data = _build_client_hello("example.com")
        assert parse_sni(data) == "example.com"

    def test_long_hostname(self):
        hostname = "very-long-subdomain.deeply.nested.example.com"
        data = _build_client_hello(hostname)
        assert parse_sni(data) == hostname

    def test_no_sni_extension(self):
        data = _build_client_hello(include_sni=False)
        assert parse_sni(data) is None

    def test_with_session_id(self):
        data = _build_client_hello("test.org", session_id=b"\xab" * 32)
        assert parse_sni(data) == "test.org"

    def test_with_extra_extensions(self):
        # Add a dummy extension (type 0xFF01, length 2, data 0x0000) before SNI
        extra = struct.pack("!HH", 0xFF01, 2) + b"\x00\x00"
        # Build with SNI but put extra extension after
        data = _build_client_hello("api.example.com", extra_extensions=extra)
        assert parse_sni(data) == "api.example.com"

    def test_not_tls_handshake(self):
        data = b"\x17\x03\x01\x00\x05hello"  # Application data, not handshake
        with pytest.raises(SNIParseError, match="Not a TLS Handshake"):
            parse_sni(data)

    def test_not_client_hello(self):
        # Build a record with ServerHello type (0x02)
        body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
        handshake = struct.pack("!B", 0x02) + struct.pack("!I", len(body))[1:] + body
        record = struct.pack("!BHH", 0x16, 0x0301, len(handshake)) + handshake
        with pytest.raises(SNIParseError, match="Not a ClientHello"):
            parse_sni(record)

    def test_data_too_short(self):
        with pytest.raises(SNIParseError, match="too short"):
            parse_sni(b"\x16\x03")

    def test_empty_data(self):
        with pytest.raises(SNIParseError, match="too short"):
            parse_sni(b"")

    def test_truncated_at_random(self):
        # Build a valid record header but truncate the ClientHello body
        handshake = b"\x01\x00\x00\x20" + b"\x03\x03" + b"\x00" * 10  # truncated random
        record = struct.pack("!BHH", 0x16, 0x0301, len(handshake)) + handshake
        with pytest.raises(SNIParseError, match="truncated"):
            parse_sni(record)


class TestIsTLSClientHello:
    def test_valid_client_hello(self):
        data = _build_client_hello("example.com")
        assert is_tls_client_hello(data) is True

    def test_not_tls(self):
        assert is_tls_client_hello(b"GET / HTTP/1.1\r\n") is False

    def test_too_short(self):
        assert is_tls_client_hello(b"\x16\x03") is False

    def test_application_data(self):
        data = b"\x17\x03\x03\x00\x05\x01hello"
        assert is_tls_client_hello(data) is False

    def test_server_hello(self):
        # Handshake type 0x02 (ServerHello)
        data = b"\x16\x03\x03\x00\x05\x02\x00\x00\x01\x00"
        assert is_tls_client_hello(data) is False
