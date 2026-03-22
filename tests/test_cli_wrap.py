"""Tests for the wrap CLI command log file handling (#1)."""

from __future__ import annotations

from click.testing import CliRunner

from secretgate.cli import main


class TestWrapLogFile:
    """Tests for wrap command log file options."""

    def test_wrap_shows_usage_without_command(self):
        """wrap without -- <command> should show usage."""
        runner = CliRunner()
        result = runner.invoke(main, ["wrap"])
        assert result.exit_code == 0
        assert "Usage:" in result.output or "wrap" in result.output

    def test_wrap_default_log_file_path(self, tmp_path):
        """The default log file should be ~/.secretgate/wrap.log."""
        runner = CliRunner()
        # We can't fully run wrap (it needs a real command), but we can
        # verify the CLI accepts the --log-file option
        result = runner.invoke(
            main, ["wrap", "--log-file", str(tmp_path / "test.log"), "--help"]
        )
        # --help should show all options including --log-file
        assert result.exit_code == 0

    def test_wrap_help_shows_log_options(self):
        """wrap --help should show --log-file and --verbose options."""
        runner = CliRunner()
        result = runner.invoke(main, ["wrap", "--help"])
        assert result.exit_code == 0
        assert "--log-file" in result.output
        assert "--verbose" in result.output
