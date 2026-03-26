"""Tests for the firewall CLI subcommand."""

from click.testing import CliRunner

from secretgate.cli import main


class TestFirewallCLI:
    def test_firewall_show_default(self):
        runner = CliRunner()
        result = runner.invoke(main, ["firewall", "show"])
        assert result.exit_code == 0
        # Should generate some rules regardless of platform
        assert len(result.output) > 10

    def test_firewall_show_iptables(self):
        runner = CliRunner()
        result = runner.invoke(main, ["firewall", "show", "--tool", "iptables"])
        assert result.exit_code == 0
        assert "iptables" in result.output
        assert "--dport 443" in result.output

    def test_firewall_show_nftables(self):
        runner = CliRunner()
        result = runner.invoke(main, ["firewall", "show", "--tool", "nftables"])
        assert result.exit_code == 0
        assert "nftables" in result.output

    def test_firewall_show_pf(self):
        runner = CliRunner()
        result = runner.invoke(main, ["firewall", "show", "--tool", "pf"])
        assert result.exit_code == 0
        assert "pf" in result.output
        assert "block out" in result.output

    def test_firewall_show_custom_port(self):
        runner = CliRunner()
        result = runner.invoke(main, ["firewall", "show", "--tool", "iptables", "-f", "9090"])
        assert result.exit_code == 0
        assert "9090" in result.output

    def test_firewall_show_with_domains(self):
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["firewall", "show", "--tool", "iptables", "-d", "api.anthropic.com", "-d", "api.openai.com"],
        )
        assert result.exit_code == 0
        assert "api.anthropic.com" in result.output
        assert "api.openai.com" in result.output

    def test_firewall_show_with_user(self):
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["firewall", "show", "--tool", "iptables", "-u", "developer"],
        )
        assert result.exit_code == 0
        assert "developer" in result.output

    def test_firewall_group_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["firewall", "--help"])
        assert result.exit_code == 0
        assert "proxy bypass" in result.output.lower() or "firewall" in result.output.lower()
