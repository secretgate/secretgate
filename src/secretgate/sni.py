"""TLS ClientHello SNI (Server Name Indication) parser.

Extracts the hostname from a TLS ClientHello message by parsing the
SNI extension. This is the foundation for transparent proxy mode (#49)
where traffic arrives without HTTP CONNECT — the proxy must peek at the
ClientHello to determine the target hostname.

SNI is unencrypted in TLS 1.2 and 1.3 ClientHello, making hostname
extraction reliable for all current TLS versions.

References:
    - RFC 5246 §7.4.1.2 (TLS 1.2 ClientHello)
    - RFC 8446 §4.1.2 (TLS 1.3 ClientHello)
    - RFC 6066 §3 (SNI extension)
"""

from __future__ import annotations


# TLS record type for Handshake
_TLS_HANDSHAKE = 0x16
# Handshake type for ClientHello
_HANDSHAKE_CLIENT_HELLO = 0x01
# SNI extension type
_SNI_EXTENSION_TYPE = 0x0000
# SNI host_name type
_SNI_HOST_NAME = 0x00


class SNIParseError(Exception):
    """Raised when SNI cannot be extracted from the data."""


def parse_sni(data: bytes) -> str | None:
    """Extract the SNI hostname from a TLS ClientHello message.

    Args:
        data: Raw bytes starting with the TLS record header.
              At least the ClientHello through extensions is needed
              (~200+ bytes typically, but varies).

    Returns:
        The SNI hostname as a string, or None if no SNI extension is present.

    Raises:
        SNIParseError: If the data is not a valid TLS ClientHello.
    """
    if len(data) < 5:
        raise SNIParseError("Data too short for TLS record header")

    # TLS record header: ContentType(1) + ProtocolVersion(2) + Length(2)
    content_type = data[0]
    if content_type != _TLS_HANDSHAKE:
        raise SNIParseError(f"Not a TLS Handshake record (type=0x{content_type:02x})")

    # We may not have the full record — that's fine, we just need
    # enough to parse the extensions
    payload = data[5:]

    if len(payload) < 1:
        raise SNIParseError("Empty handshake payload")

    # Handshake header: HandshakeType(1) + Length(3)
    handshake_type = payload[0]
    if handshake_type != _HANDSHAKE_CLIENT_HELLO:
        raise SNIParseError(f"Not a ClientHello (type=0x{handshake_type:02x})")

    if len(payload) < 4:
        raise SNIParseError("Handshake header truncated")

    pos = 4  # skip handshake header (type + 3-byte length)

    # ClientHello body:
    #   ProtocolVersion(2) + Random(32) = 34 bytes
    if pos + 34 > len(payload):
        raise SNIParseError("ClientHello truncated at version/random")
    pos += 34

    # SessionID: length(1) + data
    if pos + 1 > len(payload):
        raise SNIParseError("ClientHello truncated at session_id length")
    session_id_len = payload[pos]
    pos += 1 + session_id_len

    # CipherSuites: length(2) + data
    if pos + 2 > len(payload):
        raise SNIParseError("ClientHello truncated at cipher_suites length")
    cipher_suites_len = int.from_bytes(payload[pos : pos + 2], "big")
    pos += 2 + cipher_suites_len

    # CompressionMethods: length(1) + data
    if pos + 1 > len(payload):
        raise SNIParseError("ClientHello truncated at compression_methods length")
    comp_methods_len = payload[pos]
    pos += 1 + comp_methods_len

    # Extensions: length(2) + extension data
    if pos + 2 > len(payload):
        # No extensions — valid but no SNI
        return None
    extensions_len = int.from_bytes(payload[pos : pos + 2], "big")
    pos += 2

    extensions_end = pos + extensions_len
    while pos + 4 <= min(extensions_end, len(payload)):
        ext_type = int.from_bytes(payload[pos : pos + 2], "big")
        ext_len = int.from_bytes(payload[pos + 2 : pos + 4], "big")
        pos += 4

        if ext_type == _SNI_EXTENSION_TYPE:
            return _parse_sni_extension(payload[pos : pos + ext_len])

        pos += ext_len

    return None  # no SNI extension found


def _parse_sni_extension(data: bytes) -> str | None:
    """Parse the SNI extension payload to extract the hostname.

    SNI extension format:
        ServerNameList length(2)
            NameType(1) + HostName length(2) + HostName(variable)
    """
    if len(data) < 2:
        return None

    sni_list_len = int.from_bytes(data[0:2], "big")
    pos = 2

    end = min(pos + sni_list_len, len(data))
    while pos + 3 <= end:
        name_type = data[pos]
        name_len = int.from_bytes(data[pos + 1 : pos + 3], "big")
        pos += 3

        if name_type == _SNI_HOST_NAME:
            if pos + name_len > len(data):
                return None
            try:
                return data[pos : pos + name_len].decode("ascii")
            except UnicodeDecodeError:
                return None

        pos += name_len

    return None


def is_tls_client_hello(data: bytes) -> bool:
    """Quick check if the data starts with a TLS ClientHello.

    Useful for transparent proxy mode to distinguish TLS connections
    from HTTP CONNECT requests.
    """
    if len(data) < 6:
        return False
    return (
        data[0] == _TLS_HANDSHAKE
        and data[1] in (0x03,)  # TLS major version 3
        and data[2] in (0x01, 0x02, 0x03, 0x04)  # minor: TLS 1.0-1.3
        and data[5] == _HANDSHAKE_CLIENT_HELLO
    )
