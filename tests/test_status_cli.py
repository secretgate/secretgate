"""Tests for the CLI harden and status commands."""

from __future__ import annotations

from click.testing import CliRunner

from secretgate.cli import main


class TestHardenCLI:
    def test_harden_produces_output(self):
        runner = CliRunner()
        result = runner.invoke(main, ["harden"])
        assert result.exit_code == 0
        # Should produce a shell script
        assert "#!/usr/bin/env bash" in result.output or "block out" in result.output

    def test_harden_uninstall(self):
        runner = CliRunner()
        result = runner.invoke(main, ["harden", "--uninstall"])
        assert result.exit_code == 0
        assert "removed" in result.output

    def test_harden_custom_port(self):
        runner = CliRunner()
        result = runner.invoke(main, ["harden", "-f", "9999"])
        assert result.exit_code == 0
        assert "9999" in result.output


class TestStatusCLI:
    def test_status_not_running(self):
        """When nothing is listening, status should report not running."""
        runner = CliRunner()
        # Use unusual ports that are very unlikely to be in use
        result = runner.invoke(main, ["status", "-p", "59123", "-f", "59124"])
        assert result.exit_code == 1
        assert "not running" in result.output
