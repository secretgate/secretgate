"""Tests for git packfile scanning."""

from __future__ import annotations

import struct
import zlib

import pytest

from secretgate.packfile import (
    OBJ_BLOB,
    OBJ_COMMIT,
    OBJ_OFS_DELTA,
    OBJ_REF_DELTA,
    OBJ_TAG,
    OBJ_TREE,
    extract_texts_from_packfile,
    find_pack_offset,
)
from secretgate.scan import BlockedError, TextScanner
from secretgate.secrets.scanner import SecretScanner


# ---------------------------------------------------------------------------
# Helpers for building synthetic packfiles
# ---------------------------------------------------------------------------


def _encode_object_header(obj_type: int, size: int) -> bytes:
    """Encode a git packfile variable-length object header."""
    # First byte: type in bits 6-4, low 4 bits of size
    byte = (obj_type << 4) | (size & 0x0F)
    size >>= 4
    if size:
        byte |= 0x80
    result = bytes([byte])
    while size:
        byte = size & 0x7F
        size >>= 7
        if size:
            byte |= 0x80
        result += bytes([byte])
    return result


def _make_packfile(*objects: tuple[int, bytes], pkt_prefix: bytes = b"") -> bytes:
    """Build a synthetic packfile with the given objects.

    Each object is (type, raw_data). Data will be zlib-compressed.
    Returns bytes including the PACK header and a dummy 20-byte trailer.
    """
    obj_data = b""
    for obj_type, raw in objects:
        header = _encode_object_header(obj_type, len(raw))
        compressed = zlib.compress(raw)
        obj_data += header + compressed

    pack = b"PACK"
    pack += struct.pack(">I", 2)  # version 2
    pack += struct.pack(">I", len(objects))  # object count
    pack += obj_data
    pack += b"\x00" * 20  # dummy SHA-1 trailer

    return pkt_prefix + pack


# Test secrets
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01"


# ---------------------------------------------------------------------------
# Tests for packfile parsing
# ---------------------------------------------------------------------------


class TestFindPackOffset:
    def test_finds_pack_at_start(self):
        data = b"PACK" + b"\x00" * 20
        assert find_pack_offset(data) == 0

    def test_finds_pack_after_pktlines(self):
        pkt = b"0078oldref newref refs/heads/main\n0000"
        data = pkt + b"PACK" + b"\x00" * 20
        assert find_pack_offset(data) == len(pkt)

    def test_returns_none_for_no_pack(self):
        assert find_pack_offset(b"just some text") is None

    def test_returns_none_for_truncated(self):
        # PACK magic present but not enough room for 12-byte header
        assert find_pack_offset(b"PACK\x00\x00") is None


class TestExtractTexts:
    def test_extracts_blob(self):
        content = b"Hello, this is a file with a secret: " + AWS_KEY.encode()
        pack = _make_packfile((OBJ_BLOB, content))
        texts = extract_texts_from_packfile(pack)
        assert len(texts) == 1
        assert AWS_KEY in texts[0]

    def test_extracts_commit(self):
        commit_msg = (
            b"tree 0000000000000000000000000000000000000000\n"
            b"author Test <test@test.com> 1234567890 +0000\n"
            b"committer Test <test@test.com> 1234567890 +0000\n"
            b"\n"
            b"Add config with key " + AWS_KEY.encode()
        )
        pack = _make_packfile((OBJ_COMMIT, commit_msg))
        texts = extract_texts_from_packfile(pack)
        assert len(texts) == 1
        assert AWS_KEY in texts[0]

    def test_extracts_tag(self):
        tag = (
            b"object 0000000000000000000000000000000000000000\n"
            b"type commit\n"
            b"tag v1.0\n"
            b"tagger Test <test@test.com> 1234567890 +0000\n"
            b"\n"
            b"Release with " + AWS_KEY.encode()
        )
        pack = _make_packfile((OBJ_TAG, tag))
        texts = extract_texts_from_packfile(pack)
        assert len(texts) == 1
        assert AWS_KEY in texts[0]

    def test_skips_tree_objects(self):
        # Tree objects are binary — should not appear in results
        tree_data = b"\x00" * 40  # fake tree entry
        blob = b"some text content"
        pack = _make_packfile((OBJ_TREE, tree_data), (OBJ_BLOB, blob))
        texts = extract_texts_from_packfile(pack)
        assert len(texts) == 1
        assert texts[0] == "some text content"

    def test_skips_ref_delta_objects(self):
        blob = b"text content"
        pack_body = b""

        # First: a normal blob
        header = _encode_object_header(OBJ_BLOB, len(blob))
        pack_body += header + zlib.compress(blob)

        # Second: a ref_delta (20-byte base SHA + compressed delta instructions)
        delta_data = b"\x05\x06\x90\x05"  # fake delta instructions
        header = _encode_object_header(OBJ_REF_DELTA, len(delta_data))
        base_sha = b"\xab" * 20
        pack_body += header + base_sha + zlib.compress(delta_data)

        pack = b"PACK" + struct.pack(">I", 2) + struct.pack(">I", 2) + pack_body + b"\x00" * 20
        texts = extract_texts_from_packfile(pack)
        assert len(texts) == 1
        assert texts[0] == "text content"

    def test_skips_ofs_delta_objects(self):
        blob = b"text content"
        pack_body = b""

        # First: a normal blob
        header = _encode_object_header(OBJ_BLOB, len(blob))
        pack_body += header + zlib.compress(blob)

        # Second: an ofs_delta (variable-length negative offset + compressed data)
        delta_data = b"\x05\x06"
        header = _encode_object_header(OBJ_OFS_DELTA, len(delta_data))
        # Offset: single byte < 128 (no continuation)
        offset_bytes = b"\x10"
        pack_body += header + offset_bytes + zlib.compress(delta_data)

        pack = b"PACK" + struct.pack(">I", 2) + struct.pack(">I", 2) + pack_body + b"\x00" * 20
        texts = extract_texts_from_packfile(pack)
        assert len(texts) == 1
        assert texts[0] == "text content"

    def test_multiple_blobs(self):
        blob1 = b"first file content"
        blob2 = b"second file with " + AWS_KEY.encode()
        pack = _make_packfile((OBJ_BLOB, blob1), (OBJ_BLOB, blob2))
        texts = extract_texts_from_packfile(pack)
        assert len(texts) == 2
        assert any(AWS_KEY in t for t in texts)

    def test_malformed_packfile_returns_empty(self):
        assert extract_texts_from_packfile(b"not a packfile") == []
        assert extract_texts_from_packfile(b"PACK") == []
        assert extract_texts_from_packfile(b"") == []

    def test_bad_version_returns_empty(self):
        pack = b"PACK" + struct.pack(">I", 99) + struct.pack(">I", 0) + b"\x00" * 20
        assert extract_texts_from_packfile(pack) == []

    def test_pkt_prefix_before_pack(self):
        """Packfile preceded by pkt-line ref update text."""
        pkt = b"0078" + b"a" * 40 + b" " + b"b" * 40 + b" refs/heads/main\n" + b"0000"
        content = b"file with " + AWS_KEY.encode()
        pack = _make_packfile((OBJ_BLOB, content), pkt_prefix=pkt)
        texts = extract_texts_from_packfile(pack)
        assert len(texts) == 1
        assert AWS_KEY in texts[0]

    def test_oversized_object_skipped(self, monkeypatch):
        import secretgate.packfile as pf

        monkeypatch.setattr(pf, "MAX_OBJECT_SIZE", 10)
        content = b"A" * 100
        pack = _make_packfile((OBJ_BLOB, content))
        texts = extract_texts_from_packfile(pack)
        assert len(texts) == 0

    def test_total_size_limit(self, monkeypatch):
        import secretgate.packfile as pf

        monkeypatch.setattr(pf, "MAX_TOTAL_SIZE", 50)
        blob1 = b"A" * 30
        blob2 = b"B" * 30
        pack = _make_packfile((OBJ_BLOB, blob1), (OBJ_BLOB, blob2))
        texts = extract_texts_from_packfile(pack)
        # Should get at most 1 (second would exceed 50 byte total limit)
        assert len(texts) == 1


# ---------------------------------------------------------------------------
# Tests for TextScanner integration with packfiles
# ---------------------------------------------------------------------------


@pytest.fixture
def scanner():
    return SecretScanner()


@pytest.fixture
def redact_scanner(scanner):
    return TextScanner(scanner, mode="redact")


@pytest.fixture
def block_scanner(scanner):
    return TextScanner(scanner, mode="block")


@pytest.fixture
def audit_scanner(scanner):
    return TextScanner(scanner, mode="audit")


class TestScanPackfileIntegration:
    def test_should_scan_git_receive_pack(self, redact_scanner):
        assert redact_scanner.should_scan("application/x-git-receive-pack-request") is True

    def test_should_scan_git_upload_pack(self, redact_scanner):
        assert redact_scanner.should_scan("application/x-git-upload-pack-request") is True

    def test_scan_body_routes_to_packfile(self, audit_scanner):
        """scan_body with git content type routes to packfile scanning."""
        content = b"file with key " + AWS_KEY.encode()
        pack = _make_packfile((OBJ_BLOB, content))
        _, alerts = audit_scanner.scan_body(pack, "application/x-git-receive-pack-request")
        assert len(alerts) > 0
        assert any("packfile" in a.lower() for a in alerts)

    def test_audit_mode_returns_body_unchanged(self, audit_scanner):
        content = b"key=" + AWS_KEY.encode()
        pack = _make_packfile((OBJ_BLOB, content))
        result, alerts = audit_scanner.scan_body(pack, "application/x-git-receive-pack-request")
        assert result == pack  # body unchanged in audit mode
        assert len(alerts) > 0

    def test_block_mode_raises(self, block_scanner):
        content = b"key=" + AWS_KEY.encode()
        pack = _make_packfile((OBJ_BLOB, content))
        with pytest.raises(BlockedError) as exc_info:
            block_scanner.scan_body(pack, "application/x-git-receive-pack-request")
        assert len(exc_info.value.alerts) > 0

    def test_redact_mode_raises_for_packfile(self, redact_scanner):
        """Redact mode falls back to block for packfiles since we can't safely rewrite binary."""
        content = b"key=" + AWS_KEY.encode()
        pack = _make_packfile((OBJ_BLOB, content))
        with pytest.raises(BlockedError) as exc_info:
            redact_scanner.scan_body(pack, "application/x-git-receive-pack-request")
        assert len(exc_info.value.alerts) > 0

    def test_clean_packfile_passes(self, redact_scanner):
        content = b"just some normal code without secrets"
        pack = _make_packfile((OBJ_BLOB, content))
        result, alerts = redact_scanner.scan_body(pack, "application/x-git-receive-pack-request")
        assert result == pack
        assert alerts == []

    def test_commit_message_with_secret_detected(self, block_scanner):
        commit = (
            b"tree 0000000000000000000000000000000000000000\n"
            b"author Test <test@test.com> 1234567890 +0000\n"
            b"committer Test <test@test.com> 1234567890 +0000\n"
            b"\n"
            b"Add " + AWS_KEY.encode() + b" to config"
        )
        pack = _make_packfile((OBJ_COMMIT, commit))
        with pytest.raises(BlockedError):
            block_scanner.scan_body(pack, "application/x-git-receive-pack-request")

    def test_github_token_in_blob_detected(self, block_scanner):
        content = b"TOKEN=" + GITHUB_TOKEN.encode()
        pack = _make_packfile((OBJ_BLOB, content))
        with pytest.raises(BlockedError):
            block_scanner.scan_body(pack, "application/x-git-receive-pack-request")
