"""Tests for firewall rule generation (issue #33)."""

from secretgate.firewall import (
    generate_iptables_rules,
    generate_nftables_rules,
    generate_pf_rules,
    generate_rules,
)


class TestIptablesRules:
    def test_default_rules_block_all_443(self):
        rules = generate_iptables_rules()
        assert "PROXY_PORT=8083" in rules
        assert "--dport 443" in rules
        assert "-j DROP" in rules
        assert "-o lo -j ACCEPT" in rules

    def test_custom_port(self):
        rules = generate_iptables_rules(proxy_port=9090)
        assert "PROXY_PORT=9090" in rules

    def test_specific_user(self):
        rules = generate_iptables_rules(user="testuser")
        assert '"testuser"' in rules

    def test_specific_domains(self):
        rules = generate_iptables_rules(domains=["api.anthropic.com", "api.openai.com"])
        assert "api.anthropic.com" in rules
        assert "api.openai.com" in rules
        assert "dig +short" in rules


class TestNftablesRules:
    def test_default_rules(self):
        rules = generate_nftables_rules()
        assert "table inet secretgate" in rules
        assert "tcp dport 443" in rules
        assert "drop" in rules

    def test_specific_user(self):
        rules = generate_nftables_rules(user="testuser")
        assert 'meta skuid "testuser"' in rules


class TestPfRules:
    def test_default_rules(self):
        rules = generate_pf_rules()
        assert "block out proto tcp" in rules
        assert "port 443" in rules
        assert "port 8083" in rules

    def test_custom_port(self):
        rules = generate_pf_rules(proxy_port=9090)
        assert "port 9090" in rules


class TestGenerateRules:
    def test_auto_generates_something(self):
        rules = generate_rules()
        assert len(rules) > 0

    def test_explicit_tool(self):
        rules = generate_rules(tool="iptables")
        assert "iptables" in rules

    def test_unknown_platform(self):
        rules = generate_rules(tool="unknown")
        assert "Unsupported" in rules

    def test_windows(self):
        rules = generate_rules(tool="windows")
        assert "netsh" in rules
