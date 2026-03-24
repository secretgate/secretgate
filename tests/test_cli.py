"""Tests for the CLI entry point."""

from __future__ import annotations


from click.testing import CliRunner

from secretgate.cli import main


class TestVersion:
    def test_version_flag(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.5.1" in result.output

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "secretgate" in result.output
        assert "serve" in result.output
        assert "scan" in result.output
        assert "wrap" in result.output
        assert "ca" in result.output


class TestScanCommand:
    def test_scan_clean_stdin(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan"], input="just normal text\nnothing secret here\n")
        assert result.exit_code == 0
        assert "No secrets found" in result.output

    def test_scan_detects_aws_key(self):
        runner = CliRunner()
        text = "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
        result = runner.invoke(main, ["scan"], input=text)
        assert result.exit_code == 1
        assert "secret(s) found" in result.output
        assert "aws" in result.output.lower()

    def test_scan_detects_github_pat(self):
        runner = CliRunner()
        text = "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12\n"
        result = runner.invoke(main, ["scan"], input=text)
        assert result.exit_code == 1
        assert "secret(s) found" in result.output

    def test_scan_file(self, tmp_path):
        secret_file = tmp_path / "secrets.txt"
        secret_file.write_text("MY_KEY=AKIAIOSFODNN7EXAMPLE\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(secret_file)])
        assert result.exit_code == 1
        assert "secret(s) found" in result.output

    def test_scan_clean_file(self, tmp_path):
        clean_file = tmp_path / "clean.txt"
        clean_file.write_text("Hello, world!\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(clean_file)])
        assert result.exit_code == 0
        assert "No secrets found" in result.output

    def test_scan_no_entropy_flag(self):
        runner = CliRunner()
        # High-entropy value that might trigger entropy detection
        text = "API_KEY=aB3dE6gH9jK2mN5pQ8sT1vX4zA7cF0iL\n"
        result = runner.invoke(main, ["scan", "--no-entropy"], input=text)
        # With --no-entropy, only regex matches count
        # This may or may not match depending on patterns; just check it runs
        assert result.exit_code in (0, 1)

    def test_scan_no_known_values_flag(self):
        runner = CliRunner()
        result = runner.invoke(
            main, ["scan", "--no-known-values"], input="nothing secret\n"
        )
        assert result.exit_code == 0


class TestCaCommands:
    def test_ca_init(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(main, ["ca", "init", "--certs-dir", str(tmp_path / "certs")])
        assert result.exit_code == 0
        assert "CA certificate" in result.output

    def test_ca_path(self, tmp_path):
        certs_dir = tmp_path / "certs"
        runner = CliRunner()
        result = runner.invoke(main, ["ca", "path", "--certs-dir", str(certs_dir)])
        assert result.exit_code == 0
        assert "ca.pem" in result.output or "certs" in result.output

    def test_ca_trust(self):
        runner = CliRunner()
        result = runner.invoke(main, ["ca", "trust"])
        assert result.exit_code == 0
        assert "CA certificate" in result.output


class TestWrapCommand:
    def test_wrap_no_command(self):
        runner = CliRunner()
        result = runner.invoke(main, ["wrap"])
        assert result.exit_code == 0
        assert "Usage" in result.output or "secretgate wrap" in result.output

    def test_wrap_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["wrap", "--help"])
        assert result.exit_code == 0
        assert "Run a command with all traffic routed through secretgate" in result.output


class TestServeCommand:
    def test_serve_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["serve", "--help"])
        assert result.exit_code == 0
        assert "--port" in result.output
        assert "--mode" in result.output
        assert "--forward-proxy-port" in result.output
        assert "redact" in result.output
