"""TLS ClientHello SNI extraction for transparent proxy mode.

Parses the Server Name Indication (SNI) extension from a raw TLS
ClientHello message.  SNI is unencrypted in TLS 1.2 and 1.3, so
hostname extraction is reliable.

This module is the foundation for issue #49 (transparent proxy via
iptables REDIRECT / pf rdr).  When traffic is redirected to secretgate
at the kernel level (no HTTP CONNECT), the proxy peeks at the first
bytes of the connection:

- If byte 0 is ``0x16`` (TLS handshake) → extract the SNI hostname
  from the ClientHello, generate a MITM cert, and relay.
- Otherwise treat it as a plain HTTP request (existing path).

Reference: RFC 6066 §3 (Server Name Indication), RFC 8446 §4.1.2
(TLS 1.3 ClientHello).
"""

from __future__ import annotations

# TLS record / handshake constants
_TLS_HANDSHAKE = 0x16
_HANDSHAKE_CLIENT_HELLO = 0x01
_EXT_SERVER_NAME = 0x0000
_SNI_HOST_NAME = 0x00


def extract_sni(data: bytes) -> str | None:
    """Extract the SNI hostname from a TLS ClientHello message.

    Parameters
    ----------
    data:
        Raw bytes peeked from the connection.  Must contain at least
        the TLS record header and enough of the ClientHello to include
        the extensions block.  Typically the first 4–8 KB is sufficient.

    Returns
    -------
    str | None
        The SNI hostname if found, otherwise ``None``.
    """
    if len(data) < 5:
        return None

    # --- TLS record layer ---
    content_type = data[0]
    if content_type != _TLS_HANDSHAKE:
        return None

    # record length (bytes 3-4), but we don't strictly need it — just
    # ensure we have enough data to start parsing the handshake.
    # tls_version = (data[1], data[2])  # not needed
    # record_length = int.from_bytes(data[3:5], "big")

    # --- Handshake header ---
    pos = 5
    if pos >= len(data):
        return None
    if data[pos] != _HANDSHAKE_CLIENT_HELLO:
        return None
    pos += 1

    if pos + 3 > len(data):
        return None
    # handshake_length = int.from_bytes(data[pos : pos + 3], "big")
    pos += 3

    # --- ClientHello body ---
    # client_version (2) + random (32)
    pos += 2 + 32
    if pos >= len(data):
        return None

    # session_id (variable, 1-byte length prefix)
    if pos + 1 > len(data):
        return None
    session_id_len = data[pos]
    pos += 1 + session_id_len

    # cipher_suites (variable, 2-byte length prefix)
    if pos + 2 > len(data):
        return None
    cipher_suites_len = int.from_bytes(data[pos : pos + 2], "big")
    pos += 2 + cipher_suites_len

    # compression_methods (variable, 1-byte length prefix)
    if pos + 1 > len(data):
        return None
    comp_len = data[pos]
    pos += 1 + comp_len

    # --- Extensions ---
    if pos + 2 > len(data):
        return None
    extensions_len = int.from_bytes(data[pos : pos + 2], "big")
    pos += 2
    extensions_end = pos + extensions_len

    while pos + 4 <= min(extensions_end, len(data)):
        ext_type = int.from_bytes(data[pos : pos + 2], "big")
        ext_len = int.from_bytes(data[pos + 2 : pos + 4], "big")
        pos += 4

        if ext_type == _EXT_SERVER_NAME:
            return _parse_sni_extension(data[pos : pos + ext_len])

        pos += ext_len

    return None


def _parse_sni_extension(ext_data: bytes) -> str | None:
    """Parse the SNI extension payload and return the first hostname."""
    if len(ext_data) < 2:
        return None

    # server_name_list_length (2 bytes)
    # list_len = int.from_bytes(ext_data[0:2], "big")
    pos = 2

    while pos + 3 <= len(ext_data):
        name_type = ext_data[pos]
        name_len = int.from_bytes(ext_data[pos + 1 : pos + 3], "big")
        pos += 3

        if name_type == _SNI_HOST_NAME:
            if pos + name_len > len(ext_data):
                return None
            try:
                return ext_data[pos : pos + name_len].decode("ascii")
            except UnicodeDecodeError:
                return None

        pos += name_len

    return None


def is_tls_client_hello(data: bytes) -> bool:
    """Return True if *data* starts with a TLS ClientHello record."""
    return len(data) >= 6 and data[0] == _TLS_HANDSHAKE and data[5] == _HANDSHAKE_CLIENT_HELLO
