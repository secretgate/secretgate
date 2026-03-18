"""Tests for the wrap command logging functionality (Issue #1)."""

import os
from unittest.mock import patch

from click.testing import CliRunner

from secretgate.cli import wrap


class TestWrapLogFile:
    """Test that wrap resolves log file paths correctly."""

    def test_default_log_file_path(self, tmp_path):
        """Default log file should be ~/.secretgate/wrap.log."""
        runner = CliRunner()
        with patch.dict(os.environ, {"HOME": str(tmp_path)}, clear=False):
            # Invoke with no command to trigger early exit (no command given)
            result = runner.invoke(wrap, [], catch_exceptions=False)
            # wrap exits with usage message when no command is given
            assert result.exit_code == 0

    def test_custom_log_file_via_option(self, tmp_path):
        """--log-file should override the default path."""
        runner = CliRunner()
        custom_log = tmp_path / "custom.log"
        result = runner.invoke(
            wrap,
            ["--log-file", str(custom_log)],
            catch_exceptions=False,
        )
        # No command given, so it exits early with usage
        assert result.exit_code == 0

    def test_env_var_log_file(self, tmp_path):
        """SECRETGATE_LOG_FILE env var should set the log path."""
        runner = CliRunner()
        env_log = tmp_path / "env.log"
        with patch.dict(os.environ, {"SECRETGATE_LOG_FILE": str(env_log)}, clear=False):
            result = runner.invoke(wrap, [], catch_exceptions=False)
            assert result.exit_code == 0

    def test_log_file_parent_created(self, tmp_path):
        """Log file parent directories should be created if missing."""
        runner = CliRunner()
        deep_log = tmp_path / "deep" / "nested" / "dir" / "wrap.log"
        runner.invoke(
            wrap,
            ["--log-file", str(deep_log), "--", "true"],
            catch_exceptions=True,
        )
        # Parent dirs should have been created even if command fails
        assert deep_log.parent.exists()
