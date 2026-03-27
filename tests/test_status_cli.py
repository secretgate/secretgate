"""Tests for the secretgate status and harden CLI commands."""

from __future__ import annotations

import json

from click.testing import CliRunner

from secretgate.cli import main


class TestStatusCommand:
    """Tests for `secretgate status`."""

    def test_status_shows_stopped(self):
        """When no proxy is running, status should show stopped."""
        runner = CliRunner()
        # Use high ports that are almost certainly not in use
        result = runner.invoke(main, ["status", "-f", "59123", "-p", "59124"])
        assert result.exit_code == 0
        assert "stopped" in result.output

    def test_status_json_output(self):
        """JSON output should be valid and contain expected keys."""
        runner = CliRunner()
        result = runner.invoke(main, ["status", "-f", "59123", "-p", "59124", "--json-output"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "reverse_proxy" in data
        assert "forward_proxy" in data
        assert data["reverse_proxy"]["status"] == "stopped"
        assert data["forward_proxy"]["status"] == "stopped"


class TestHardenCommand:
    """Tests for `secretgate harden`."""

    def test_harden_prints_guide(self):
        runner = CliRunner()
        result = runner.invoke(main, ["harden"])
        assert result.exit_code == 0
        assert "Hardening Guide" in result.output
        assert "Firewall" in result.output

    def test_harden_custom_port(self):
        runner = CliRunner()
        result = runner.invoke(main, ["harden", "-f", "9999"])
        assert result.exit_code == 0
        assert "9999" in result.output

    def test_harden_writes_to_dir(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(main, ["harden", "-o", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / "firewall.sh").exists()
        assert (tmp_path / "readonly-env.sh").exists()
        assert (tmp_path / "claude-hooks.json").exists()
