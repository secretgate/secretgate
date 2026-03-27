"""Tests for the hardening script generator (secretgate harden)."""

from __future__ import annotations

import json
import platform

from secretgate.harden import (
    generate_claude_hooks,
    generate_firewall_script,
    generate_readonly_env,
    print_harden_guide,
)


class TestGenerateFirewallScript:
    """Tests for firewall script generation."""

    def test_linux_script_contains_iptables(self, monkeypatch):
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        script = generate_firewall_script(proxy_port=8083)
        assert "iptables" in script
        assert "8083" in script
        assert "--dport 443" in script

    def test_darwin_script_contains_pf(self, monkeypatch):
        monkeypatch.setattr(platform, "system", lambda: "Darwin")
        script = generate_firewall_script(proxy_port=8083)
        assert "pfctl" in script
        assert "8083" in script
        assert "port 443" in script

    def test_custom_port(self, monkeypatch):
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        script = generate_firewall_script(proxy_port=9999)
        assert "9999" in script

    def test_unknown_platform(self, monkeypatch):
        monkeypatch.setattr(platform, "system", lambda: "FreeBSD")
        script = generate_firewall_script()
        assert "No automatic script" in script


class TestGenerateReadonlyEnv:
    """Tests for readonly env var snippet."""

    def test_contains_proxy_vars(self):
        snippet = generate_readonly_env(proxy_port=8083)
        assert "https_proxy" in snippet
        assert "HTTPS_PROXY" in snippet
        assert "readonly" in snippet
        assert "8083" in snippet

    def test_custom_port(self):
        snippet = generate_readonly_env(proxy_port=7777)
        assert "7777" in snippet


class TestGenerateClaudeHooks:
    """Tests for Claude Code hooks generation."""

    def test_valid_json(self):
        hooks = generate_claude_hooks()
        parsed = json.loads(hooks)
        assert "hooks" in parsed
        assert "pre_tool_call" in parsed["hooks"]

    def test_blocks_proxy_manipulation(self):
        hooks = generate_claude_hooks()
        assert "https?_proxy" in hooks
        assert "ANTHROPIC_BASE_URL" in hooks
        assert "SSL_CERT_FILE" in hooks


class TestPrintHardenGuide:
    """Tests for the full hardening guide output."""

    def test_prints_all_sections(self, capsys):
        print_harden_guide(proxy_port=8083)
        output = capsys.readouterr().out
        assert "Firewall" in output
        assert "Readonly" in output
        assert "Claude Code" in output

    def test_writes_scripts_to_dir(self, tmp_path):
        print_harden_guide(proxy_port=8083, output_dir=str(tmp_path))
        assert (tmp_path / "firewall.sh").exists()
        assert (tmp_path / "readonly-env.sh").exists()
        assert (tmp_path / "claude-hooks.json").exists()

        # Verify Claude hooks file is valid JSON
        hooks = json.loads((tmp_path / "claude-hooks.json").read_text())
        assert "hooks" in hooks
