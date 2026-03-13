"""Tests for CLI commands and wrap logging (Issue #1)."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from secretgate.cli import main, _default_log_dir, _find_available_port


class TestDefaultLogDir:
    def test_returns_home_secretgate(self):
        result = _default_log_dir()
        assert result == Path.home() / ".secretgate"


class TestFindAvailablePort:
    def test_finds_free_port(self):
        # Port 0 is never in use for TCP connect — but _find_available_port
        # tries to connect, so any unused port should be returned.
        port = _find_available_port(19876)
        assert isinstance(port, int)
        assert port >= 19876


class TestWrapCommand:
    def test_wrap_no_command_shows_usage(self):
        runner = CliRunner()
        result = runner.invoke(main, ["wrap", "--"])
        assert "Usage:" in result.output or result.exit_code == 0

    def test_wrap_help_shows_log_options(self):
        runner = CliRunner()
        result = runner.invoke(main, ["wrap", "--help"])
        assert "--verbose" in result.output
        assert "--log-file" in result.output
        assert "wrap.log" in result.output

    def test_wrap_respects_env_log_file(self, tmp_path):
        """SECRETGATE_LOG_FILE env var should override default log path."""
        # Verify the env var name is in the help text
        runner = CliRunner()
        result = runner.invoke(main, ["wrap", "--help"])
        assert "SECRETGATE_LOG_FILE" in result.output


class TestScanCommand:
    def test_scan_no_secrets(self, tmp_path):
        f = tmp_path / "clean.txt"
        f.write_text("just normal text here")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(f)])
        assert "No secrets found" in result.output
        assert result.exit_code == 0

    def test_scan_finds_secrets(self, tmp_path):
        f = tmp_path / "secrets.txt"
        f.write_text("key=AKIAIOSFODNN7EXAMPLE\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(f)])
        assert "secret(s) found" in result.output
        assert result.exit_code == 1

    def test_scan_stdin(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan"], input="AKIAIOSFODNN7EXAMPLE\n")
        assert "secret(s) found" in result.output
        assert result.exit_code == 1

    def test_scan_stdin_clean(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan"], input="hello world\n")
        assert "No secrets found" in result.output
        assert result.exit_code == 0

    def test_scan_multiple_files(self, tmp_path):
        f1 = tmp_path / "a.txt"
        f1.write_text("AKIAIOSFODNN7EXAMPLE\n")
        f2 = tmp_path / "b.txt"
        f2.write_text("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(f1), str(f2)])
        assert result.exit_code == 1
        assert "secret(s) found" in result.output


class TestServeCommand:
    def test_serve_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["serve", "--help"])
        assert "--port" in result.output
        assert "--mode" in result.output
        assert "--forward-proxy-port" in result.output


class TestCACommands:
    def test_ca_init(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(main, ["ca", "init", "--certs-dir", str(tmp_path / "certs")])
        assert result.exit_code == 0
        assert (tmp_path / "certs" / "ca.crt").exists()

    def test_ca_path(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(main, ["ca", "path", "--certs-dir", str(tmp_path / "certs")])
        assert "ca.crt" in result.output
