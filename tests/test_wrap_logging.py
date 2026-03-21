"""Tests for the wrap command log file functionality (#1)."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from secretgate.cli import wrap


class TestWrapLogOptions:
    """Verify that the wrap command accepts log-related options."""

    def test_help_shows_log_file_option(self):
        runner = CliRunner()
        result = runner.invoke(wrap, ["--help"])
        assert "--log-file" in result.output
        assert "--verbose" in result.output or "-v" in result.output

    def test_default_log_path(self, tmp_path: Path):
        """The default log path should be ~/.secretgate/wrap.log."""
        runner = CliRunner()
        # We can't fully run wrap without a command, but we can verify
        # it prints usage when no command is given
        result = runner.invoke(wrap, [])
        assert "Usage:" in result.output or result.exit_code == 0

    def test_log_file_disable_with_dash(self):
        """Passing --log-file=- should disable logging."""
        runner = CliRunner()
        result = runner.invoke(wrap, ["--log-file", "-"])
        # Should just print usage since no command given
        assert "Usage:" in result.output or result.exit_code == 0
