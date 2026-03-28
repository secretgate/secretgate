"""Tests for the harden module (firewall rule generation)."""

from __future__ import annotations


from secretgate.harden import (
    generate_iptables_rules,
    generate_iptables_uninstall,
    generate_pf_rules,
    generate_pf_install_script,
    generate_pf_uninstall_script,
    detect_os,
)


class TestDetectOS:
    def test_returns_string(self):
        result = detect_os()
        assert result in ("linux", "macos", "unsupported")


class TestIptablesRules:
    def test_default_rules(self):
        script = generate_iptables_rules()
        assert "iptables" in script
        assert "8083" in script
        assert "--dport 443" in script
        assert "#!/usr/bin/env bash" in script

    def test_custom_port(self):
        script = generate_iptables_rules(proxy_port=9999)
        assert "9999" in script

    def test_with_uid(self):
        script = generate_iptables_rules(uid=1000)
        assert "--uid-owner 1000" in script

    def test_without_uid(self):
        script = generate_iptables_rules()
        assert "--uid-owner" not in script

    def test_with_block_domains(self):
        script = generate_iptables_rules(
            block_domains=["api.anthropic.com", "api.openai.com"]
        )
        assert "api.anthropic.com" in script
        assert "api.openai.com" in script
        # Should NOT have a blanket block
        lines = script.splitlines()
        blanket_blocks = [
            line for line in lines
            if "--dport 443" in line and "-d " not in line and "REJECT" in line
        ]
        assert len(blanket_blocks) == 0

    def test_uninstall(self):
        script = generate_iptables_uninstall()
        assert "iptables -D" in script
        assert "removed" in script

    def test_uninstall_with_uid(self):
        script = generate_iptables_uninstall(uid=1000)
        assert "--uid-owner 1000" in script


class TestPfRules:
    def test_default_rules(self):
        rules = generate_pf_rules()
        assert "block out" in rules
        assert "port 443" in rules
        assert "pass out" in rules
        assert "8083" in rules

    def test_custom_port(self):
        rules = generate_pf_rules(proxy_port=7777)
        assert "7777" in rules

    def test_with_username(self):
        rules = generate_pf_rules(username="testuser")
        assert "user testuser" in rules

    def test_without_username(self):
        rules = generate_pf_rules()
        # Should not have a user clause
        assert "user " not in rules.split("port 443")[1]

    def test_install_script(self):
        script = generate_pf_install_script()
        assert "pfctl" in script
        assert "#!/usr/bin/env bash" in script
        assert "com.secretgate" in script

    def test_uninstall_script(self):
        script = generate_pf_uninstall_script()
        assert "pfctl" in script
        assert "-F all" in script
        assert "removed" in script
