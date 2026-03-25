"""Tests for CLI commands (harden, scan, version)."""

from __future__ import annotations

import json

from click.testing import CliRunner

from secretgate.cli import main


@classmethod
def runner():
    return CliRunner()


class TestVersion:
    def test_version_flag(self):
        result = CliRunner().invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "version" in result.output


class TestHardenEnv:
    def test_bash_output(self):
        result = CliRunner().invoke(main, ["harden", "env"])
        assert result.exit_code == 0
        assert "export https_proxy=" in result.output
        assert "readonly" in result.output
        assert "localhost:8083" in result.output

    def test_fish_output(self):
        result = CliRunner().invoke(main, ["harden", "env", "--shell", "fish"])
        assert result.exit_code == 0
        assert "set -gx https_proxy" in result.output
        assert "readonly" not in result.output

    def test_custom_port(self):
        result = CliRunner().invoke(main, ["harden", "env", "-f", "9090"])
        assert result.exit_code == 0
        assert "localhost:9090" in result.output


class TestHardenIptables:
    def test_generates_rules(self):
        result = CliRunner().invoke(main, ["harden", "iptables"])
        assert result.exit_code == 0
        assert "iptables -A OUTPUT" in result.output
        assert "api.anthropic.com" in result.output
        assert "api.openai.com" in result.output

    def test_remove_flag(self):
        result = CliRunner().invoke(main, ["harden", "iptables", "--remove"])
        assert result.exit_code == 0
        assert "iptables -D OUTPUT" in result.output
        assert "Removing" in result.output

    def test_extra_domain(self):
        result = CliRunner().invoke(
            main, ["harden", "iptables", "--extra-domain", "api.custom.com"]
        )
        assert result.exit_code == 0
        assert "api.custom.com" in result.output


class TestHardenHooks:
    def test_outputs_valid_json(self):
        result = CliRunner().invoke(main, ["harden", "hooks"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "hooks" in data
        assert "PreToolUse" in data["hooks"]

    def test_write_to_file(self, tmp_path):
        out = tmp_path / "hooks.json"
        result = CliRunner().invoke(main, ["harden", "hooks", "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "hooks" in data


class TestScanCommand:
    def test_scan_clean_file(self, tmp_path):
        f = tmp_path / "clean.txt"
        f.write_text("just normal text here\n")
        result = CliRunner().invoke(main, ["scan", str(f)])
        assert result.exit_code == 0
        assert "No secrets found" in result.output

    def test_scan_file_with_secret(self, tmp_path):
        f = tmp_path / "secrets.txt"
        f.write_text("aws_key=AKIAIOSFODNN7EXAMPLE\n")
        result = CliRunner().invoke(main, ["scan", str(f)])
        assert result.exit_code == 1
        assert "secret(s) found" in result.output

    def test_scan_directory_recursive(self, tmp_path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "config.env").write_text("TOKEN=AKIAIOSFODNN7EXAMPLE\n")
        (tmp_path / "clean.txt").write_text("hello\n")
        result = CliRunner().invoke(main, ["scan", "--no-entropy", str(tmp_path)])
        assert result.exit_code == 1
        assert "subdir" in result.output

    def test_scan_stdin(self):
        result = CliRunner().invoke(main, ["scan"], input="key=AKIAIOSFODNN7EXAMPLE\n")
        assert result.exit_code == 1
        assert "secret(s) found" in result.output
