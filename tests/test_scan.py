"""Tests for the TextScanner raw body scanning adapter."""

from __future__ import annotations

import json

import pytest

from secretgate.scan import (
    BlockedError,
    TextScanner,
    _blank_gemini_part,
    _strip_cohere,
    _strip_gemini,
    _strip_messages_format,
)
from secretgate.secrets.scanner import SecretScanner


@pytest.fixture
def scanner():
    return SecretScanner()


@pytest.fixture
def redact_scanner(scanner):
    return TextScanner(scanner, mode="redact")


@pytest.fixture
def block_scanner(scanner):
    return TextScanner(scanner, mode="block")


@pytest.fixture
def audit_scanner(scanner):
    return TextScanner(scanner, mode="audit")


class TestShouldScan:
    def test_scans_text_plain(self, redact_scanner):
        assert redact_scanner.should_scan("text/plain") is True

    def test_scans_json(self, redact_scanner):
        assert redact_scanner.should_scan("application/json") is True

    def test_scans_form_data(self, redact_scanner):
        assert redact_scanner.should_scan("application/x-www-form-urlencoded") is True

    def test_skips_images(self, redact_scanner):
        assert redact_scanner.should_scan("image/png") is False
        assert redact_scanner.should_scan("image/jpeg") is False

    def test_skips_audio(self, redact_scanner):
        assert redact_scanner.should_scan("audio/mpeg") is False

    def test_skips_video(self, redact_scanner):
        assert redact_scanner.should_scan("video/mp4") is False

    def test_skips_binary(self, redact_scanner):
        assert redact_scanner.should_scan("application/octet-stream") is False
        assert redact_scanner.should_scan("application/gzip") is False
        assert redact_scanner.should_scan("application/zip") is False

    def test_handles_charset(self, redact_scanner):
        assert redact_scanner.should_scan("text/plain; charset=utf-8") is True


class TestScanBody:
    def test_detects_aws_key(self, redact_scanner):
        body = b"key=AKIAIOSFODNN7EXAMPLE"
        result, alerts = redact_scanner.scan_body(body, "text/plain")
        assert b"AKIAIOSFODNN7EXAMPLE" not in result
        assert len(alerts) > 0

    def test_clean_body_passes_through(self, redact_scanner):
        body = b"just some normal text here"
        result, alerts = redact_scanner.scan_body(body, "text/plain")
        assert result == body
        assert alerts == []

    def test_empty_body(self, redact_scanner):
        result, alerts = redact_scanner.scan_body(b"", "text/plain")
        assert result == b""
        assert alerts == []

    def test_skips_binary_content(self, redact_scanner):
        body = b"AKIAIOSFODNN7EXAMPLE"
        result, alerts = redact_scanner.scan_body(body, "application/octet-stream")
        assert result == body  # unchanged — not scanned
        assert alerts == []

    def test_block_mode_raises(self, block_scanner):
        body = b"secret=AKIAIOSFODNN7EXAMPLE"
        with pytest.raises(BlockedError) as exc_info:
            block_scanner.scan_body(body, "text/plain")
        assert len(exc_info.value.alerts) > 0

    def test_audit_mode_passes_through(self, audit_scanner):
        body = b"key=AKIAIOSFODNN7EXAMPLE"
        result, alerts = audit_scanner.scan_body(body, "text/plain")
        assert result == body  # unchanged in audit mode
        assert len(alerts) > 0

    def test_redact_mode_replaces_secrets(self, redact_scanner):
        body = b"my key is AKIAIOSFODNN7EXAMPLE ok"
        result, alerts = redact_scanner.scan_body(body, "text/plain")
        assert b"AKIAIOSFODNN7EXAMPLE" not in result
        assert b"REDACTED<" in result
        assert len(alerts) > 0


# ---------------------------------------------------------------------------
# Format detection and stripping tests
# ---------------------------------------------------------------------------

# Use a real AWS access key pattern for integration tests
_TEST_KEY = "AKIAIOSFODNN7EXAMPLE"


class TestStripMessagesFormat:
    """Tests for OpenAI/Anthropic/Mistral message format stripping."""

    def test_blanks_earlier_user_messages(self):
        body = {
            "messages": [
                {"role": "user", "content": "earlier question"},
                {"role": "assistant", "content": "earlier answer"},
                {"role": "user", "content": "current question"},
            ]
        }
        _strip_messages_format(body)
        assert body["messages"][0]["content"] == ""
        assert body["messages"][1]["content"] == ""
        assert body["messages"][2]["content"] == "current question"

    def test_blanks_openai_system_role(self):
        body = {
            "messages": [
                {"role": "system", "content": "You are a helpful assistant"},
                {"role": "user", "content": "hello"},
            ]
        }
        _strip_messages_format(body)
        assert body["messages"][0]["content"] == ""
        assert body["messages"][1]["content"] == "hello"

    def test_blanks_anthropic_system_field(self):
        body = {
            "system": "You are a helpful assistant",
            "messages": [{"role": "user", "content": "hello"}],
        }
        _strip_messages_format(body)
        assert body["system"] == ""
        assert body["messages"][0]["content"] == "hello"

    def test_blanks_anthropic_system_blocks(self):
        body = {
            "system": [{"type": "text", "text": "System prompt"}],
            "messages": [{"role": "user", "content": "hello"}],
        }
        _strip_messages_format(body)
        assert body["system"][0]["text"] == ""

    def test_keeps_last_user_turn_with_tool_messages(self):
        """OpenAI tool messages in the last turn should be kept."""
        body = {
            "messages": [
                {"role": "user", "content": "earlier"},
                {"role": "assistant", "content": "ok"},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "get_data", "arguments": '{"x": 1}'},
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": "call_1", "content": "result data"},
                {"role": "user", "content": "current question"},
            ]
        }
        _strip_messages_format(body)
        # Earlier messages blanked
        assert body["messages"][0]["content"] == ""
        assert body["messages"][1]["content"] == ""
        assert body["messages"][2]["tool_calls"][0]["function"]["arguments"] == ""
        # Last turn (tool + user) kept
        assert body["messages"][3]["content"] == "result data"
        assert body["messages"][4]["content"] == "current question"

    def test_blanks_tool_calls_arguments(self):
        """OpenAI tool_calls arguments in earlier messages should be blanked."""
        body = {
            "messages": [
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "bash",
                                "arguments": f'{{"cmd": "{_TEST_KEY}"}}',
                            },
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": "call_1", "content": "ok"},
                {"role": "user", "content": "next question"},
            ]
        }
        _strip_messages_format(body)
        assert body["messages"][0]["tool_calls"][0]["function"]["arguments"] == ""

    def test_strips_thinking_blocks_in_last_turn(self):
        body = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "thinking", "thinking": "internal", "signature": "sig"},
                        {"type": "text", "text": "user input"},
                    ],
                }
            ]
        }
        _strip_messages_format(body)
        assert body["messages"][0]["content"][0]["thinking"] == ""
        assert body["messages"][0]["content"][0]["signature"] == ""
        assert body["messages"][0]["content"][1]["text"] == "user input"

    def test_unmodified_returns_false(self):
        body = {"messages": [{"role": "user", "content": "hello"}]}
        assert _strip_messages_format(body) is False

    def test_modified_returns_true(self):
        body = {
            "messages": [
                {"role": "user", "content": "old"},
                {"role": "assistant", "content": "reply"},
                {"role": "user", "content": "new"},
            ]
        }
        assert _strip_messages_format(body) is True

    def test_blanks_anthropic_tool_use_input(self):
        """Anthropic tool_use.input in earlier assistant messages should be blanked."""
        body = {
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_01",
                            "name": "bash",
                            "input": {"command": "cat /etc/secrets"},
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "tool_use_id": "toolu_01", "content": "ok"}
                    ],
                },
                {"role": "user", "content": "current question"},
            ]
        }
        _strip_messages_format(body)
        assert body["messages"][0]["content"][0]["input"] == {}

    def test_blanks_document_source_text(self):
        """Document block source text in earlier messages should be blanked."""
        body = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "document",
                            "source": {"type": "text", "text": "secret content"},
                        }
                    ],
                },
                {"role": "assistant", "content": "noted"},
                {"role": "user", "content": "current"},
            ]
        }
        _strip_messages_format(body)
        assert body["messages"][0]["content"][0]["source"]["text"] == ""

    def test_blanks_server_tool_result_content(self):
        """Server tool result list content in earlier messages should be blanked."""
        body = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "code_execution_tool_result",
                            "tool_use_id": "srvtoolu_01",
                            "content": [{"type": "text", "text": "output"}],
                        }
                    ],
                },
                {"role": "assistant", "content": "ok"},
                {"role": "user", "content": "current"},
            ]
        }
        _strip_messages_format(body)
        assert body["messages"][0]["content"][0]["content"] == []


class TestStripGemini:
    """Tests for Google Gemini format stripping."""

    def test_keeps_last_user_turn(self):
        body = {
            "contents": [
                {"role": "user", "parts": [{"text": "earlier"}]},
                {"role": "model", "parts": [{"text": "response"}]},
                {"role": "user", "parts": [{"text": "current"}]},
            ]
        }
        _strip_gemini(body)
        assert body["contents"][0]["parts"][0]["text"] == ""
        assert body["contents"][1]["parts"][0]["text"] == ""
        assert body["contents"][2]["parts"][0]["text"] == "current"

    def test_blanks_system_instruction(self):
        body = {
            "systemInstruction": {"parts": [{"text": "Be helpful"}]},
            "contents": [{"role": "user", "parts": [{"text": "hello"}]}],
        }
        _strip_gemini(body)
        assert body["systemInstruction"]["parts"][0]["text"] == ""
        assert body["contents"][0]["parts"][0]["text"] == "hello"

    def test_multiple_parts(self):
        body = {
            "contents": [
                {"role": "user", "parts": [{"text": "part1"}, {"text": "part2"}]},
                {"role": "model", "parts": [{"text": "reply"}]},
                {"role": "user", "parts": [{"text": "current"}]},
            ]
        }
        _strip_gemini(body)
        assert body["contents"][0]["parts"][0]["text"] == ""
        assert body["contents"][0]["parts"][1]["text"] == ""
        assert body["contents"][2]["parts"][0]["text"] == "current"

    def test_unmodified_returns_false(self):
        body = {"contents": [{"role": "user", "parts": [{"text": "hello"}]}]}
        assert _strip_gemini(body) is False

    def test_blanks_function_call_args_in_earlier_turn(self):
        """Model functionCall args in earlier turns should be blanked."""
        body = {
            "contents": [
                {"role": "user", "parts": [{"text": "get weather"}]},
                {
                    "role": "model",
                    "parts": [{"functionCall": {"name": "get_weather", "args": {"city": "Paris"}}}],
                },
                {
                    "role": "user",
                    "parts": [
                        {"functionResponse": {"name": "get_weather", "response": {"temp": 22}}}
                    ],
                },
                {"role": "model", "parts": [{"text": "It's 22C"}]},
                {"role": "user", "parts": [{"text": "current question"}]},
            ]
        }
        _strip_gemini(body)
        # Earlier model functionCall args blanked
        assert body["contents"][1]["parts"][0]["functionCall"]["args"] == {}
        # Earlier user functionResponse blanked
        assert body["contents"][2]["parts"][0]["functionResponse"]["response"] == {}
        # Current turn kept
        assert body["contents"][4]["parts"][0]["text"] == "current question"

    def test_blanks_code_execution_in_earlier_turn(self):
        """codeExecutionResult and executableCode in earlier turns should be blanked."""
        body = {
            "contents": [
                {
                    "role": "model",
                    "parts": [
                        {"executableCode": {"language": "PYTHON", "code": "print('secret')"}},
                        {"codeExecutionResult": {"outcome": "OUTCOME_OK", "output": "secret"}},
                    ],
                },
                {"role": "user", "parts": [{"text": "current"}]},
            ]
        }
        _strip_gemini(body)
        assert body["contents"][0]["parts"][0]["executableCode"]["code"] == ""
        assert body["contents"][0]["parts"][1]["codeExecutionResult"]["output"] == ""
        assert body["contents"][1]["parts"][0]["text"] == "current"


class TestBlankGeminiPart:
    """Test the Gemini part blanking helper directly."""

    def test_blanks_text(self):
        part = {"text": "hello"}
        assert _blank_gemini_part(part) is True
        assert part["text"] == ""

    def test_blanks_function_call_args(self):
        part = {"functionCall": {"name": "fn", "args": {"key": "val"}}}
        assert _blank_gemini_part(part) is True
        assert part["functionCall"]["args"] == {}

    def test_blanks_function_response(self):
        part = {"functionResponse": {"name": "fn", "response": {"result": "data"}}}
        assert _blank_gemini_part(part) is True
        assert part["functionResponse"]["response"] == {}

    def test_blanks_code_execution_result(self):
        part = {"codeExecutionResult": {"outcome": "OUTCOME_OK", "output": "secret"}}
        assert _blank_gemini_part(part) is True
        assert part["codeExecutionResult"]["output"] == ""

    def test_blanks_executable_code(self):
        part = {"executableCode": {"language": "PYTHON", "code": "print(x)"}}
        assert _blank_gemini_part(part) is True
        assert part["executableCode"]["code"] == ""

    def test_skips_inline_data(self):
        """inlineData (binary) should not be modified."""
        part = {"inlineData": {"mimeType": "image/png", "data": "base64data"}}
        assert _blank_gemini_part(part) is False


class TestStripCohere:
    """Tests for Cohere format stripping."""

    def test_keeps_message_blanks_history(self):
        body = {
            "message": "current input",
            "chat_history": [
                {"role": "USER", "message": "old question"},
                {"role": "CHATBOT", "message": "old answer"},
            ],
        }
        _strip_cohere(body)
        assert body["message"] == "current input"
        assert body["chat_history"][0]["message"] == ""
        assert body["chat_history"][1]["message"] == ""

    def test_blanks_preamble(self):
        body = {
            "message": "hello",
            "chat_history": [],
            "preamble": "You are a helpful assistant",
        }
        _strip_cohere(body)
        assert body["preamble"] == ""
        assert body["message"] == "hello"

    def test_empty_history(self):
        body = {"message": "hello", "chat_history": []}
        assert _strip_cohere(body) is False

    def test_modified_returns_true(self):
        body = {
            "message": "hello",
            "chat_history": [{"role": "USER", "message": "old"}],
        }
        assert _strip_cohere(body) is True

    def test_blanks_tool_results_outputs(self):
        """Cohere v1 tool_results outputs should be blanked."""
        body = {
            "message": "what did the tool say?",
            "chat_history": [],
            "tool_results": [
                {
                    "call": {"name": "search", "parameters": {"q": "test"}},
                    "outputs": [{"result": "secret data"}],
                }
            ],
        }
        _strip_cohere(body)
        assert body["tool_results"][0]["outputs"] == []
        assert body["message"] == "what did the tool say?"


class TestStripMessagesFormatOpenAI:
    """Additional OpenAI-specific tests for _strip_messages_format."""

    def test_blanks_developer_role(self):
        """OpenAI developer role (o1+ models) should be blanked like system."""
        body = {
            "messages": [
                {"role": "developer", "content": "You must follow these rules"},
                {"role": "user", "content": "current question"},
            ]
        }
        _strip_messages_format(body)
        assert body["messages"][0]["content"] == ""
        assert body["messages"][1]["content"] == "current question"

    def test_cohere_v2_handled_as_messages_format(self):
        """Cohere v2 uses OpenAI-compatible format — should work via _strip_messages_format."""
        body = {
            "model": "command-r-plus",
            "messages": [
                {"role": "system", "content": "You are helpful"},
                {"role": "user", "content": "old question"},
                {"role": "assistant", "content": "old answer"},
                {"role": "user", "content": "current question"},
            ],
        }
        _strip_messages_format(body)
        assert body["messages"][0]["content"] == ""
        assert body["messages"][1]["content"] == ""
        assert body["messages"][2]["content"] == ""
        assert body["messages"][3]["content"] == "current question"


class TestFormatDetection:
    """Test that _strip_model_content dispatches to the right format handler."""

    def test_blanks_secret_in_anthropic_system(self, redact_scanner):
        """Anthropic format: secret in system field should be blanked before scanning."""
        body = json.dumps(
            {
                "system": f"Key: {_TEST_KEY}",
                "messages": [{"role": "user", "content": "hello"}],
            }
        ).encode()
        _, alerts = redact_scanner.scan_body(body, "application/json")
        assert len(alerts) == 0

    def test_blanks_secret_in_openai_system(self, redact_scanner):
        """OpenAI format: secret in system message should be blanked."""
        body = json.dumps(
            {
                "model": "gpt-4",
                "messages": [
                    {"role": "system", "content": f"Key: {_TEST_KEY}"},
                    {"role": "user", "content": "hello"},
                ],
            }
        ).encode()
        _, alerts = redact_scanner.scan_body(body, "application/json")
        assert len(alerts) == 0

    def test_blanks_secret_in_gemini_history(self, redact_scanner):
        """Gemini format: secret in earlier turn should be blanked."""
        body = json.dumps(
            {
                "contents": [
                    {"role": "user", "parts": [{"text": f"Key: {_TEST_KEY}"}]},
                    {"role": "model", "parts": [{"text": "noted"}]},
                    {"role": "user", "parts": [{"text": "hello"}]},
                ],
            }
        ).encode()
        _, alerts = redact_scanner.scan_body(body, "application/json")
        assert len(alerts) == 0

    def test_blanks_secret_in_cohere_history(self, redact_scanner):
        """Cohere format: secret in chat_history should be blanked."""
        body = json.dumps(
            {
                "message": "hello",
                "chat_history": [
                    {"role": "USER", "message": f"Key: {_TEST_KEY}"},
                    {"role": "CHATBOT", "message": "ok"},
                ],
            }
        ).encode()
        _, alerts = redact_scanner.scan_body(body, "application/json")
        assert len(alerts) == 0

    def test_detects_secret_in_openai_current_turn(self, redact_scanner):
        """Secret in current user turn should be detected in OpenAI format."""
        body = json.dumps(
            {
                "model": "gpt-4",
                "messages": [
                    {"role": "system", "content": "You are helpful"},
                    {"role": "user", "content": f"Here is my key: {_TEST_KEY}"},
                ],
            }
        ).encode()
        _, alerts = redact_scanner.scan_body(body, "application/json")
        assert len(alerts) >= 1

    def test_detects_secret_in_gemini_current_turn(self, redact_scanner):
        """Secret in current user turn should be detected in Gemini format."""
        body = json.dumps(
            {
                "contents": [
                    {"role": "user", "parts": [{"text": f"Key: {_TEST_KEY}"}]},
                ],
            }
        ).encode()
        _, alerts = redact_scanner.scan_body(body, "application/json")
        assert len(alerts) >= 1

    def test_detects_secret_in_cohere_current_input(self, redact_scanner):
        """Secret in current Cohere message should be detected."""
        body = json.dumps(
            {
                "message": f"Key: {_TEST_KEY}",
                "chat_history": [],
            }
        ).encode()
        _, alerts = redact_scanner.scan_body(body, "application/json")
        assert len(alerts) >= 1

    def test_falls_back_on_unknown_format(self, redact_scanner):
        """Unknown JSON structure should scan the full body."""
        body = json.dumps(
            {
                "prompt": f"Key: {_TEST_KEY}",
                "max_tokens": 100,
            }
        ).encode()
        _, alerts = redact_scanner.scan_body(body, "application/json")
        assert len(alerts) >= 1
