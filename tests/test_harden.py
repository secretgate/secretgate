"""Tests for firewall rule generation (secretgate harden)."""

from __future__ import annotations

from click.testing import CliRunner

from secretgate.cli import main
from secretgate.harden import generate_remove, generate_rules, validate_domain


# ---------------------------------------------------------------------------
# Unit tests: generate_rules
# ---------------------------------------------------------------------------


class TestGenerateRules:
    def test_iptables_default(self):
        rules = generate_rules(tool="iptables")
        assert "iptables" in rules
        assert "--dport 443" in rules
        assert "-j DROP" in rules
        assert "-o lo -j ACCEPT" in rules

    def test_iptables_custom_port(self):
        rules = generate_rules(proxy_port=9090, tool="iptables")
        assert "localhost:9090" in rules

    def test_iptables_specific_user(self):
        rules = generate_rules(tool="iptables", user="testuser")
        assert '"testuser"' in rules

    def test_iptables_specific_domains(self):
        rules = generate_rules(tool="iptables", domains=["api.anthropic.com", "api.openai.com"])
        assert "api.anthropic.com" in rules
        assert "api.openai.com" in rules
        assert "dig +short" in rules

    def test_nftables_default(self):
        rules = generate_rules(tool="nftables")
        assert "#!/usr/bin/env bash" in rules
        assert "nft -f -" in rules
        assert "table inet secretgate" in rules
        assert "tcp dport 443" in rules
        assert "drop" in rules

    def test_nftables_user(self):
        rules = generate_rules(tool="nftables", user="dev")
        assert 'meta skuid "dev"' in rules

    def test_pf_default(self):
        rules = generate_rules(tool="pf")
        assert "#!/usr/bin/env bash" in rules
        assert "block out proto tcp" in rules
        assert "port 443" in rules
        assert "port 8083" in rules
        assert "pfctl" in rules

    def test_pf_resolves_username(self):
        import getpass

        rules = generate_rules(tool="pf")
        assert getpass.getuser() in rules

    def test_pf_custom_user(self):
        rules = generate_rules(tool="pf", user="developer")
        assert "user developer" in rules

    def test_windows_default(self):
        rules = generate_rules(tool="windows")
        assert "netsh" in rules
        assert "secretgate-block-https" in rules

    def test_unknown_tool(self):
        rules = generate_rules(tool="freebsd-ipfw")
        assert "Unsupported" in rules

    def test_auto_detect(self):
        """Auto-detect should return something non-empty."""
        rules = generate_rules()
        assert len(rules) > 10


class TestGenerateRemove:
    def test_iptables_remove(self):
        script = generate_remove(tool="iptables")
        assert "iptables -D" in script
        assert "removed" in script.lower()

    def test_nftables_remove(self):
        script = generate_remove(tool="nftables")
        assert "nft delete table" in script

    def test_pf_remove(self):
        script = generate_remove(tool="pf")
        assert "pfctl" in script
        assert "-F all" in script

    def test_windows_remove(self):
        script = generate_remove(tool="windows")
        assert "delete rule" in script


class TestValidateDomain:
    def test_valid_domains(self):
        assert validate_domain("api.anthropic.com")
        assert validate_domain("api.openai.com")
        assert validate_domain("example.co.uk")

    def test_invalid_domains(self):
        assert not validate_domain("; rm -rf /")
        assert not validate_domain("$(whoami)")
        assert not validate_domain("foo bar")
        assert not validate_domain("")

    def test_rejects_injection_in_generate_rules(self):
        import pytest

        with pytest.raises(ValueError, match="Invalid domain"):
            generate_rules(tool="iptables", domains=["; rm -rf /"])


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------


class TestHardenCLI:
    def test_harden_default(self):
        runner = CliRunner()
        result = runner.invoke(main, ["harden"])
        assert result.exit_code == 0
        assert len(result.output) > 10

    def test_harden_iptables(self):
        runner = CliRunner()
        result = runner.invoke(main, ["harden", "--tool", "iptables"])
        assert result.exit_code == 0
        assert "iptables" in result.output
        assert "--dport 443" in result.output

    def test_harden_nftables(self):
        runner = CliRunner()
        result = runner.invoke(main, ["harden", "--tool", "nftables"])
        assert result.exit_code == 0
        assert "nftables" in result.output

    def test_harden_pf(self):
        runner = CliRunner()
        result = runner.invoke(main, ["harden", "--tool", "pf"])
        assert result.exit_code == 0
        assert "block out" in result.output

    def test_harden_windows(self):
        runner = CliRunner()
        result = runner.invoke(main, ["harden", "--tool", "windows"])
        assert result.exit_code == 0
        assert "netsh" in result.output

    def test_harden_custom_port(self):
        runner = CliRunner()
        result = runner.invoke(main, ["harden", "--tool", "iptables", "-f", "9090"])
        assert result.exit_code == 0
        assert "9090" in result.output

    def test_harden_with_domains(self):
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["harden", "--tool", "iptables", "-d", "api.anthropic.com", "-d", "api.openai.com"],
        )
        assert result.exit_code == 0
        assert "api.anthropic.com" in result.output
        assert "api.openai.com" in result.output

    def test_harden_with_user(self):
        runner = CliRunner()
        result = runner.invoke(main, ["harden", "--tool", "iptables", "-u", "developer"])
        assert result.exit_code == 0
        assert "developer" in result.output

    def test_harden_remove(self):
        runner = CliRunner()
        result = runner.invoke(main, ["harden", "--tool", "iptables", "--remove"])
        assert result.exit_code == 0
        assert "iptables -D" in result.output

    def test_harden_output_file(self, tmp_path):
        out = tmp_path / "firewall.sh"
        runner = CliRunner()
        result = runner.invoke(main, ["harden", "--tool", "iptables", "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        content = out.read_text()
        assert "iptables" in content
        # File should be executable
        assert out.stat().st_mode & 0o755

    def test_harden_invalid_domain(self):
        runner = CliRunner()
        result = runner.invoke(main, ["harden", "--tool", "iptables", "-d", "; rm -rf /"])
        assert result.exit_code != 0
        assert "Invalid domain" in result.output
