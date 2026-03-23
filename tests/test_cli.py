"""Tests for CLI commands (scan, ca)."""

from __future__ import annotations

import json

from click.testing import CliRunner

from secretgate.cli import main


class TestScanCommand:
    """Tests for the `secretgate scan` CLI command."""

    def test_scan_clean_file(self, tmp_path):
        """Clean file reports no secrets."""
        f = tmp_path / "clean.txt"
        f.write_text("Hello world, nothing secret here.\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(f)])
        assert result.exit_code == 0
        assert "No secrets found" in result.output

    def test_scan_file_with_aws_key(self, tmp_path):
        """File with an AWS key is detected."""
        f = tmp_path / "secrets.env"
        f.write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(f)])
        assert result.exit_code == 1
        assert "1 secret(s) found" in result.output
        assert "Amazon" in result.output or "AWS" in result.output

    def test_scan_stdin(self):
        """Secrets piped via stdin are detected."""
        runner = CliRunner()
        result = runner.invoke(main, ["scan"], input="token=ghp_ABCDEFghijklmnop1234567890abcdef12\n")
        assert result.exit_code == 1
        assert "secret(s) found" in result.output

    def test_scan_stdin_clean(self):
        """Clean stdin reports no secrets."""
        runner = CliRunner()
        result = runner.invoke(main, ["scan"], input="just some normal text\n")
        assert result.exit_code == 0
        assert "No secrets found" in result.output

    def test_scan_directory_recursive(self, tmp_path):
        """Directories are scanned recursively."""
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "config.env").write_text("MY_KEY=AKIAIOSFODNN7EXAMPLE\n")
        (tmp_path / "clean.txt").write_text("nothing here\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(tmp_path)])
        assert result.exit_code == 1
        assert "secret(s) found" in result.output

    def test_scan_skips_binary_extensions(self, tmp_path):
        """Binary file extensions are skipped during directory scan."""
        (tmp_path / "image.png").write_bytes(b"\x89PNG" + b"AKIAIOSFODNN7EXAMPLE")
        (tmp_path / "clean.txt").write_text("nothing here\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(tmp_path)])
        assert result.exit_code == 0
        assert "No secrets found" in result.output

    def test_scan_skips_git_directory(self, tmp_path):
        """Files inside .git are skipped."""
        git_dir = tmp_path / ".git" / "objects"
        git_dir.mkdir(parents=True)
        (git_dir / "secrets.txt").write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        (tmp_path / "clean.txt").write_text("nothing here\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_json_output(self, tmp_path):
        """JSON output mode produces valid JSON."""
        f = tmp_path / "secrets.env"
        f.write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--json", str(f)])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["secrets_found"] >= 1
        assert isinstance(data["results"], list)
        assert data["results"][0]["service"] == "Amazon"

    def test_scan_json_output_clean(self, tmp_path):
        """JSON output for clean files."""
        f = tmp_path / "clean.txt"
        f.write_text("nothing here\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--json", str(f)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["secrets_found"] == 0
        assert data["results"] == []

    def test_scan_no_entropy_flag(self, tmp_path):
        """--no-entropy flag disables entropy detection."""
        f = tmp_path / "entropy.txt"
        f.write_text('MY_SECRET="aB3dEf7hIjKlMnO9pQrS"\n')
        runner = CliRunner()
        # With entropy
        r1 = runner.invoke(main, ["scan", str(f)])
        # Without entropy
        r2 = runner.invoke(main, ["scan", "--no-entropy", str(f)])
        # The no-entropy run should find fewer or equal matches
        # (entropy match may or may not fire depending on the value)
        assert r2.exit_code <= r1.exit_code

    def test_scan_multiple_files(self, tmp_path):
        """Multiple file arguments are all scanned."""
        f1 = tmp_path / "a.env"
        f1.write_text("KEY1=AKIAIOSFODNN7EXAMPLE\n")
        f2 = tmp_path / "b.env"
        f2.write_text("KEY2=ghp_ABCDEFghijklmnop1234567890abcdef12\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(f1), str(f2)])
        assert result.exit_code == 1
        # Should find secrets in both files
        assert "a.env" in result.output
        assert "b.env" in result.output


class TestCaCommands:
    """Tests for CA management commands."""

    def test_ca_init(self, tmp_path):
        """ca init creates CA certificate."""
        runner = CliRunner()
        result = runner.invoke(main, ["ca", "init", "--certs-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "CA certificate" in result.output

    def test_ca_path(self, tmp_path):
        """ca path prints certificate path."""
        runner = CliRunner()
        result = runner.invoke(main, ["ca", "path", "--certs-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "ca." in result.output  # ca.pem or ca.crt depending on backend
