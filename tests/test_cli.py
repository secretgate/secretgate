"""Tests for CLI commands — wrap logging fix and scan report mode."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from secretgate.cli import _find_available_port, main


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

ENV_FILE_CONTENT = """\
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcde12
SAFE_VALUE=hello_world
"""


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def env_file(tmp_path):
    """Write a temp .env file with known secrets."""
    p = tmp_path / ".env"
    p.write_text(ENV_FILE_CONTENT)
    return p


# ---------------------------------------------------------------------------
# Tests: scan --report
# ---------------------------------------------------------------------------


class TestScanReport:
    def test_report_shows_summary(self, runner, env_file):
        result = runner.invoke(main, ["scan", "--report", str(env_file)])
        assert "SECRET SCAN REPORT" in result.output
        assert "Secret Types Found:" in result.output
        assert result.exit_code == 1

    def test_report_no_secrets(self, runner, tmp_path):
        safe = tmp_path / "safe.txt"
        safe.write_text("nothing secret here\njust normal text\n")
        result = runner.invoke(main, ["scan", "--report", str(safe)])
        assert "No secrets found" in result.output
        assert result.exit_code == 0

    def test_report_shows_file_count(self, runner, env_file):
        result = runner.invoke(main, ["scan", "--report", str(env_file)])
        assert "Files scanned:" in result.output
        assert "Total secrets:" in result.output

    def test_report_shows_confidence(self, runner, env_file):
        result = runner.invoke(main, ["scan", "--report", str(env_file)])
        assert "confidence:" in result.output


# ---------------------------------------------------------------------------
# Tests: scan --json
# ---------------------------------------------------------------------------


class TestScanJson:
    def test_json_output_valid(self, runner, env_file):
        result = runner.invoke(main, ["scan", "--json", str(env_file)])
        data = json.loads(result.output)
        assert "total" in data
        assert "secrets" in data
        assert "summary" in data
        assert data["total"] > 0
        assert result.exit_code == 1

    def test_json_secret_fields(self, runner, env_file):
        result = runner.invoke(main, ["scan", "--json", str(env_file)])
        data = json.loads(result.output)
        secret = data["secrets"][0]
        assert "file" in secret
        assert "line" in secret
        assert "service" in secret
        assert "pattern" in secret
        assert "confidence" in secret
        assert "preview" in secret

    def test_json_no_secrets(self, runner, tmp_path):
        safe = tmp_path / "safe.txt"
        safe.write_text("just text\n")
        result = runner.invoke(main, ["scan", "--json", str(safe)])
        data = json.loads(result.output)
        assert data["total"] == 0
        assert data["secrets"] == []
        assert result.exit_code == 0

    def test_json_summary_groups(self, runner, env_file):
        result = runner.invoke(main, ["scan", "--json", str(env_file)])
        data = json.loads(result.output)
        assert isinstance(data["summary"], dict)
        assert len(data["summary"]) > 0

    def test_json_preview_truncated(self, runner, env_file):
        result = runner.invoke(main, ["scan", "--json", str(env_file)])
        data = json.loads(result.output)
        for secret in data["secrets"]:
            # Previews of long values should be truncated
            if len(secret["preview"]) > 8:
                assert secret["preview"].endswith("...")


# ---------------------------------------------------------------------------
# Tests: scan default output still works
# ---------------------------------------------------------------------------


class TestScanDefault:
    def test_scan_default_output(self, runner, env_file):
        result = runner.invoke(main, ["scan", str(env_file)])
        assert "secret(s) found" in result.output
        assert result.exit_code == 1

    def test_scan_stdin(self, runner):
        result = runner.invoke(main, ["scan"], input="AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Tests: wrap logging (Issue #1 fix)
# ---------------------------------------------------------------------------


class TestWrapLogging:
    def test_wrap_no_command_shows_usage(self, runner):
        result = runner.invoke(main, ["wrap"])
        assert "Usage:" in result.output or "secretgate wrap" in result.output

    def test_wrap_shows_log_path(self, runner, tmp_path):
        """wrap should print log file path on startup."""
        log_path = tmp_path / "test.log"
        # Mock the subprocess to avoid actually starting a server
        with patch("subprocess.Popen") as mock_popen, patch(
            "subprocess.run"
        ) as mock_run, patch("secretgate.cli._find_available_port", return_value=19999):
            proc = MagicMock()
            proc.poll.return_value = None
            proc.pid = 12345
            proc.stderr = None
            mock_popen.return_value = proc

            run_result = MagicMock()
            run_result.returncode = 0
            mock_run.return_value = run_result

            # Mock socket connect to simulate proxy being ready
            with patch("socket.socket") as mock_socket:
                sock_instance = MagicMock()
                mock_socket.return_value = sock_instance
                # First poll: process alive, connect succeeds
                sock_instance.connect.return_value = None

                # Mock CertAuthority
                with patch("secretgate.certs.CertAuthority") as mock_ca:
                    ca_instance = MagicMock()
                    ca_instance.ca_cert_path = "/tmp/fake-ca.pem"
                    ca_instance.create_ca_bundle.return_value = Path("/tmp/fake-bundle.pem")
                    mock_ca.return_value = ca_instance

                    result = runner.invoke(
                        main,
                        ["wrap", "--log-file", str(log_path), "--", "echo", "hello"],
                        catch_exceptions=False,
                    )

        assert "Logs:" in result.output

    def test_wrap_verbose_flag_accepted(self, runner):
        """--verbose flag should be accepted."""
        result = runner.invoke(main, ["wrap", "--verbose", "--help"])
        # --help should work and show the verbose option
        assert "--verbose" in result.output or "-v" in result.output

    def test_wrap_log_file_flag_accepted(self, runner):
        """--log-file flag should be accepted."""
        result = runner.invoke(main, ["wrap", "--help"])
        assert "--log-file" in result.output

    def test_wrap_popen_uses_log_file(self, runner, tmp_path):
        """Popen should NOT use DEVNULL for stdout anymore."""
        log_path = tmp_path / "test.log"

        with patch("subprocess.Popen") as mock_popen, patch(
            "subprocess.run"
        ) as mock_run, patch("secretgate.cli._find_available_port", return_value=19998):
            proc = MagicMock()
            proc.poll.return_value = None
            proc.pid = 12345
            proc.stderr = None
            mock_popen.return_value = proc

            run_result = MagicMock()
            run_result.returncode = 0
            mock_run.return_value = run_result

            with patch("socket.socket") as mock_socket:
                sock_instance = MagicMock()
                mock_socket.return_value = sock_instance
                sock_instance.connect.return_value = None

                with patch("secretgate.certs.CertAuthority") as mock_ca:
                    ca_instance = MagicMock()
                    ca_instance.ca_cert_path = "/tmp/fake-ca.pem"
                    ca_instance.create_ca_bundle.return_value = Path("/tmp/fake-bundle.pem")
                    mock_ca.return_value = ca_instance

                    runner.invoke(
                        main,
                        ["wrap", "--log-file", str(log_path), "--", "echo", "hi"],
                        catch_exceptions=False,
                    )

            # Verify Popen was NOT called with DEVNULL
            call_kwargs = mock_popen.call_args
            assert call_kwargs is not None
            # stdout should be a file handle, not DEVNULL
            stdout_val = call_kwargs.kwargs.get("stdout") or call_kwargs[1].get("stdout")
            assert stdout_val != subprocess.DEVNULL
            # stderr should be STDOUT (merged)
            stderr_val = call_kwargs.kwargs.get("stderr") or call_kwargs[1].get("stderr")
            assert stderr_val == subprocess.STDOUT


# ---------------------------------------------------------------------------
# Tests: _find_available_port
# ---------------------------------------------------------------------------


class TestFindAvailablePort:
    def test_finds_free_port(self):
        port = _find_available_port(49152)
        assert isinstance(port, int)
        assert port >= 49152

    def test_returns_preferred_if_free(self):
        # Use a high port that's almost certainly free
        port = _find_available_port(59123)
        assert port == 59123


# ---------------------------------------------------------------------------
# Tests: scan with multiple files
# ---------------------------------------------------------------------------


class TestScanMultipleFiles:
    def test_report_multiple_files(self, runner, tmp_path):
        f1 = tmp_path / "a.env"
        f1.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
        f2 = tmp_path / "b.env"
        f2.write_text("GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcde12\n")
        result = runner.invoke(main, ["scan", "--report", str(f1), str(f2)])
        assert "Files Affected:" in result.output
        assert result.exit_code == 1

    def test_json_multiple_files(self, runner, tmp_path):
        f1 = tmp_path / "a.env"
        f1.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
        f2 = tmp_path / "b.env"
        f2.write_text("GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcde12\n")
        result = runner.invoke(main, ["scan", "--json", str(f1), str(f2)])
        data = json.loads(result.output)
        assert data["files_scanned"] == 2
        assert data["total"] >= 2
