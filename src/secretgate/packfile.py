"""Extract scannable text from git packfile data.

Git push over HTTP sends objects as binary packfiles (zlib-compressed).
This module parses the packfile format and extracts text from commit,
blob, and tag objects so they can be scanned for secrets.
"""

from __future__ import annotations

import struct
import zlib

import structlog

logger = structlog.get_logger()

# Object types in git packfiles
OBJ_COMMIT = 1
OBJ_TREE = 2
OBJ_BLOB = 3
OBJ_TAG = 4
OBJ_OFS_DELTA = 6
OBJ_REF_DELTA = 7

# Scannable object types (contain human-readable text)
_SCANNABLE_TYPES = frozenset({OBJ_COMMIT, OBJ_BLOB, OBJ_TAG})

# Safety limits
MAX_OBJECT_SIZE = 1 * 1024 * 1024  # 1MB per object decompression
MAX_TOTAL_SIZE = 10 * 1024 * 1024  # 10MB total decompressed text

PACK_MAGIC = b"PACK"


def find_pack_offset(data: bytes) -> int | None:
    """Find the offset of the PACK magic in the data.

    Git receive-pack requests start with pkt-line text (ref updates)
    followed by the PACK binary payload.
    """
    idx = data.find(PACK_MAGIC)
    if idx < 0:
        return None
    # Verify there's enough room for the 12-byte header
    if len(data) - idx < 12:
        return None
    return idx


def extract_texts_from_packfile(data: bytes) -> list[str]:
    """Extract scannable text strings from a git packfile.

    Parses the packfile header and iterates over objects, decompressing
    commit, blob, and tag objects and returning their text content.
    Delta objects (ofs_delta, ref_delta) and tree objects are skipped.

    Returns a list of decoded text strings suitable for secret scanning.
    """
    offset = find_pack_offset(data)
    if offset is None:
        return []

    pack_data = data[offset:]
    if len(pack_data) < 12:
        return []

    # Parse header: PACK + version (uint32 BE) + object count (uint32 BE)
    magic = pack_data[:4]
    if magic != PACK_MAGIC:
        return []

    version = struct.unpack(">I", pack_data[4:8])[0]
    if version not in (2, 3):
        logger.debug("packfile_unsupported_version", version=version)
        return []

    obj_count = struct.unpack(">I", pack_data[8:12])[0]

    texts: list[str] = []
    total_size = 0
    pos = 12  # past the header

    for _ in range(obj_count):
        if pos >= len(pack_data):
            break

        try:
            obj_type, obj_size, pos = _read_object_header(pack_data, pos)
        except (IndexError, ValueError):
            break

        # Skip delta objects — they reference base objects we may not have
        if obj_type == OBJ_OFS_DELTA:
            pos = _skip_ofs_delta(pack_data, pos)
            if pos is None:
                break
            continue
        elif obj_type == OBJ_REF_DELTA:
            # ref_delta has a 20-byte base object SHA before compressed data
            pos += 20
            if pos > len(pack_data):
                break
            pos = _skip_compressed(pack_data, pos)
            if pos is None:
                break
            continue

        # Skip tree objects — binary format, no meaningful scannable text
        if obj_type == OBJ_TREE:
            pos = _skip_compressed(pack_data, pos)
            if pos is None:
                break
            continue

        if obj_type not in _SCANNABLE_TYPES:
            pos = _skip_compressed(pack_data, pos)
            if pos is None:
                break
            continue

        # Decompress scannable object
        try:
            decompressed, pos = _decompress_object(pack_data, pos, obj_size)
        except (zlib.error, ValueError):
            break

        if decompressed is None:
            continue

        # Enforce size limits
        if len(decompressed) > MAX_OBJECT_SIZE:
            logger.debug(
                "packfile_object_too_large",
                size=len(decompressed),
                limit=MAX_OBJECT_SIZE,
            )
            continue

        total_size += len(decompressed)
        if total_size > MAX_TOTAL_SIZE:
            logger.debug("packfile_total_size_exceeded", total=total_size, limit=MAX_TOTAL_SIZE)
            break

        try:
            text = decompressed.decode("utf-8", errors="replace")
            texts.append(text)
        except Exception:
            continue

    return texts


def _read_object_header(data: bytes, pos: int) -> tuple[int, int, int]:
    """Read a variable-length object header. Returns (type, size, new_pos).

    The header is encoded as a variable-length integer:
    - First byte: bits 6-4 = type, bits 3-0 = size (low 4 bits)
    - Subsequent bytes (if MSB set): 7 bits of size each, shifted left
    """
    byte = data[pos]
    obj_type = (byte >> 4) & 0x07
    size = byte & 0x0F
    shift = 4
    pos += 1

    while byte & 0x80:
        if pos >= len(data):
            raise IndexError("Unexpected end of packfile header")
        byte = data[pos]
        size |= (byte & 0x7F) << shift
        shift += 7
        pos += 1

    return obj_type, size, pos


def _decompress_object(data: bytes, pos: int, expected_size: int) -> tuple[bytes | None, int]:
    """Decompress a zlib-compressed object at the given position.

    Returns (decompressed_bytes, new_pos). new_pos points past the
    compressed data. Returns (None, new_pos) if decompression is skipped.
    """
    if expected_size > MAX_OBJECT_SIZE:
        # Skip without decompressing
        new_pos = _skip_compressed(data, pos)
        return None, new_pos if new_pos is not None else len(data)

    dec = zlib.decompressobj()
    try:
        result = dec.decompress(data[pos:], MAX_OBJECT_SIZE + 1024)
    except zlib.error:
        raise

    # Find how many compressed bytes were consumed
    consumed = len(data[pos:]) - len(dec.unused_data)
    return result, pos + consumed


def _skip_compressed(data: bytes, pos: int) -> int | None:
    """Skip past a zlib-compressed block without fully decompressing it.

    Returns the new position, or None if the data is malformed.
    """
    dec = zlib.decompressobj()
    try:
        buf = data[pos:]
        while True:
            # Decompress in chunks, discarding the output
            dec.decompress(buf, 4096)
            if dec.unused_data:
                # Decompressor found end of stream — unused_data is beyond it
                consumed = len(data[pos:]) - len(dec.unused_data)
                return pos + consumed
            if not dec.unconsumed_tail:
                break
            buf = dec.unconsumed_tail
        dec.flush()
    except zlib.error:
        return None

    consumed = len(data[pos:]) - len(dec.unused_data)
    return pos + consumed


def _skip_ofs_delta(data: bytes, pos: int) -> int | None:
    """Skip an ofs_delta object (variable-length negative offset + compressed data)."""
    # Read variable-length offset
    if pos >= len(data):
        return None
    byte = data[pos]
    pos += 1
    while byte & 0x80:
        if pos >= len(data):
            return None
        byte = data[pos]
        pos += 1

    return _skip_compressed(data, pos)
