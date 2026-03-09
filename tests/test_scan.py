"""Tests for the TextScanner raw body scanning adapter."""

from __future__ import annotations

import pytest

from secretgate.scan import BlockedError, TextScanner
from secretgate.secrets.scanner import SecretScanner


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


class TestShouldScan:
    def test_scans_text_plain(self, redact_scanner):
        assert redact_scanner.should_scan("text/plain") is True

    def test_scans_json(self, redact_scanner):
        assert redact_scanner.should_scan("application/json") is True

    def test_scans_form_data(self, redact_scanner):
        assert redact_scanner.should_scan("application/x-www-form-urlencoded") is True

    def test_skips_images(self, redact_scanner):
        assert redact_scanner.should_scan("image/png") is False
        assert redact_scanner.should_scan("image/jpeg") is False

    def test_skips_audio(self, redact_scanner):
        assert redact_scanner.should_scan("audio/mpeg") is False

    def test_skips_video(self, redact_scanner):
        assert redact_scanner.should_scan("video/mp4") is False

    def test_skips_binary(self, redact_scanner):
        assert redact_scanner.should_scan("application/octet-stream") is False
        assert redact_scanner.should_scan("application/gzip") is False
        assert redact_scanner.should_scan("application/zip") is False

    def test_handles_charset(self, redact_scanner):
        assert redact_scanner.should_scan("text/plain; charset=utf-8") is True


class TestScanBody:
    def test_detects_aws_key(self, redact_scanner):
        body = b"key=AKIAIOSFODNN7EXAMPLE"
        result, alerts = redact_scanner.scan_body(body, "text/plain")
        assert b"AKIAIOSFODNN7EXAMPLE" not in result
        assert len(alerts) > 0

    def test_clean_body_passes_through(self, redact_scanner):
        body = b"just some normal text here"
        result, alerts = redact_scanner.scan_body(body, "text/plain")
        assert result == body
        assert alerts == []

    def test_empty_body(self, redact_scanner):
        result, alerts = redact_scanner.scan_body(b"", "text/plain")
        assert result == b""
        assert alerts == []

    def test_skips_binary_content(self, redact_scanner):
        body = b"AKIAIOSFODNN7EXAMPLE"
        result, alerts = redact_scanner.scan_body(body, "application/octet-stream")
        assert result == body  # unchanged — not scanned
        assert alerts == []

    def test_block_mode_raises(self, block_scanner):
        body = b"secret=AKIAIOSFODNN7EXAMPLE"
        with pytest.raises(BlockedError) as exc_info:
            block_scanner.scan_body(body, "text/plain")
        assert len(exc_info.value.alerts) > 0

    def test_audit_mode_passes_through(self, audit_scanner):
        body = b"key=AKIAIOSFODNN7EXAMPLE"
        result, alerts = audit_scanner.scan_body(body, "text/plain")
        assert result == body  # unchanged in audit mode
        assert len(alerts) > 0

    def test_redact_mode_replaces_secrets(self, redact_scanner):
        body = b"my key is AKIAIOSFODNN7EXAMPLE ok"
        result, alerts = redact_scanner.scan_body(body, "text/plain")
        assert b"AKIAIOSFODNN7EXAMPLE" not in result
        assert b"REDACTED<" in result
        assert len(alerts) > 0
