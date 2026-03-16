"""Raw text/bytes scanning adapter for the forward proxy.

Wraps the existing SecretScanner to work with raw HTTP bodies
instead of structured JSON messages.
"""

from __future__ import annotations

import json

import structlog

from secretgate.secrets.redactor import _make_placeholder
from secretgate.secrets.scanner import SecretScanner

logger = structlog.get_logger()

# Content types that should never be scanned (binary data)
_SKIP_PREFIXES = ("image/", "audio/", "video/")
_SKIP_TYPES = frozenset(
    {
        "application/octet-stream",
        "application/gzip",
        "application/zip",
        "application/x-tar",
        "application/x-bzip2",
        "application/x-xz",
        "application/pdf",
    }
)


class TextScanner:
    """Scan raw HTTP bodies for secrets using the existing SecretScanner."""

    def __init__(self, scanner: SecretScanner, mode: str = "redact"):
        self._scanner = scanner
        self._mode = mode

    def should_scan(self, content_type: str) -> bool:
        """Return True if this content type should be scanned for secrets."""
        ct = content_type.lower().split(";")[0].strip()
        if any(ct.startswith(p) for p in _SKIP_PREFIXES):
            return False
        if ct in _SKIP_TYPES:
            return False
        return True

    def scan_body(self, body: bytes, content_type: str = "text/plain") -> tuple[bytes, list[str]]:
        """Scan body bytes for secrets. Returns (possibly modified body, alerts).

        In block mode, raises BlockedError if secrets are found.
        In audit mode, returns body unchanged but with alerts.
        In redact mode, replaces secrets with [REDACTED] markers.
        """
        alerts: list[str] = []

        if not body or not self.should_scan(content_type):
            return body, alerts

        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            return body, alerts

        # For JSON bodies (LLM API requests), strip content that should not
        # be scanned: assistant messages (model-generated, already scanned on
        # input) and thinking blocks (cryptographic signatures).
        ct = content_type.lower().split(";")[0].strip()
        scannable = self._strip_model_content(text) if "json" in ct else text

        matches = self._scanner.scan(scannable)
        if not matches:
            return body, alerts

        for m in matches:
            alert = f"Secret detected: {m.service}/{m.pattern_name} on line {m.line_number}"
            alerts.append(alert)
            logger.warning(
                "forward_secret_detected",
                service=m.service,
                pattern=m.pattern_name,
                line=m.line_number,
            )

        if self._mode == "block":
            raise BlockedError(f"Request blocked: {len(matches)} secret(s) detected", alerts)

        if self._mode == "audit":
            return body, alerts

        # Redact mode: replace secrets with deterministic placeholders
        # Same format as reverse proxy: REDACTED<slug:hash12>
        # Sort by length (longest first to avoid partial replacements)
        for m in sorted(matches, key=lambda m: len(m.value), reverse=True):
            text = text.replace(m.value, _make_placeholder(m))

        return text.encode("utf-8"), alerts

    @staticmethod
    def _strip_model_content(text: str) -> str:
        """Strip content that should not be scanned from LLM API request JSON.

        Detects the API format and keeps only the last user turn:
        - Anthropic: ``messages`` + top-level ``system``
        - OpenAI / Mistral / Azure OpenAI: ``messages`` with ``role: system``
        - Google Gemini: ``contents`` with ``role: user/model``
        - Cohere: ``message`` (current input) + ``chat_history``

        Falls back to scanning the full body for unrecognized formats.
        """
        try:
            body = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return text

        if not isinstance(body, dict):
            return text

        # Detect format and dispatch
        if "contents" in body and isinstance(body.get("contents"), list):
            modified = _strip_gemini(body)
        elif isinstance(body.get("message"), str) and "chat_history" in body:
            modified = _strip_cohere(body)
        elif isinstance(body.get("messages"), list):
            modified = _strip_messages_format(body)
        else:
            return text

        return json.dumps(body) if modified else text


# ---------------------------------------------------------------------------
# Format-specific stripping helpers
# ---------------------------------------------------------------------------


def _strip_messages_format(body: dict) -> bool:
    """Strip non-scannable content from OpenAI/Anthropic/Mistral message format.

    Handles both:
    - Anthropic: top-level ``system`` field, ``tool_result`` blocks, ``thinking`` blocks
    - OpenAI / Mistral: ``role: system`` messages, ``role: tool`` messages, ``tool_calls``
    """
    modified = False

    # Anthropic top-level system field
    system = body.get("system")
    if isinstance(system, str) and system:
        body["system"] = ""
        modified = True
    elif isinstance(system, list):
        for block in system:
            if isinstance(block, dict) and "text" in block and block["text"]:
                block["text"] = ""
                modified = True

    messages = body["messages"]

    # Find where the last user turn starts: walk backwards keeping
    # user-role messages (and OpenAI tool messages that belong to the
    # same turn) until we hit an assistant/system message.
    last_turn_start = len(messages)
    for i in range(len(messages) - 1, -1, -1):
        msg = messages[i]
        if not isinstance(msg, dict):
            break
        role = msg.get("role", "")
        if role in ("user", "tool"):
            last_turn_start = i
        else:
            break

    for i, msg in enumerate(messages):
        if not isinstance(msg, dict):
            continue

        # Keep the last user turn — strip only thinking blocks within it
        if i >= last_turn_start:
            content = msg.get("content")
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "thinking":
                        for key in ("thinking", "signature"):
                            if key in block and block[key]:
                                block[key] = ""
                                modified = True
            continue

        # Blank all earlier messages
        modified = _blank_message(msg) or modified

    return modified


def _strip_gemini(body: dict) -> bool:
    """Strip non-scannable content from Google Gemini format.

    Gemini uses ``contents`` (list of ``{role, parts}``) and optionally
    ``systemInstruction`` (``{parts: [{text: ...}]}``).
    """
    modified = False

    # Blank systemInstruction
    si = body.get("systemInstruction")
    if isinstance(si, dict):
        for part in si.get("parts", []):
            if isinstance(part, dict) and "text" in part and part["text"]:
                part["text"] = ""
                modified = True

    contents = body["contents"]

    # Find last user turn
    last_turn_start = len(contents)
    for i in range(len(contents) - 1, -1, -1):
        entry = contents[i]
        if isinstance(entry, dict) and entry.get("role") == "user":
            last_turn_start = i
        else:
            break

    for i, entry in enumerate(contents):
        if not isinstance(entry, dict):
            continue
        if i >= last_turn_start:
            continue

        # Blank earlier entries — all part types that may carry text/secrets
        for part in entry.get("parts", []):
            if not isinstance(part, dict):
                continue
            modified = _blank_gemini_part(part) or modified

    return modified


def _strip_cohere(body: dict) -> bool:
    """Strip non-scannable content from Cohere format.

    Cohere uses ``message`` (current user input), ``chat_history``
    (list of ``{role, message}``), and ``preamble`` (system prompt).
    """
    modified = False

    # Blank preamble (system prompt)
    if body.get("preamble"):
        body["preamble"] = ""
        modified = True

    # Blank chat_history — already scanned in previous turns
    for entry in body.get("chat_history", []):
        if isinstance(entry, dict) and entry.get("message"):
            entry["message"] = ""
            modified = True

    # Blank tool_results outputs — already processed in previous turns
    for tr in body.get("tool_results", []):
        if isinstance(tr, dict) and tr.get("outputs"):
            tr["outputs"] = []
            modified = True

    # Keep ``message`` (current user input) — it's what we want to scan
    return modified


def _blank_gemini_part(part: dict) -> bool:
    """Blank scannable content in a Gemini part dict."""
    modified = False
    # Text parts
    if "text" in part and part["text"]:
        part["text"] = ""
        modified = True
    # functionCall — model-generated, may echo secrets in args
    fc = part.get("functionCall")
    if isinstance(fc, dict) and fc.get("args"):
        fc["args"] = {}
        modified = True
    # functionResponse — user-supplied function output
    fr = part.get("functionResponse")
    if isinstance(fr, dict) and fr.get("response"):
        fr["response"] = {}
        modified = True
    # codeExecutionResult — code output may contain secrets
    cer = part.get("codeExecutionResult")
    if isinstance(cer, dict) and cer.get("output"):
        cer["output"] = ""
        modified = True
    # executableCode — model-generated code, may reference secrets
    ec = part.get("executableCode")
    if isinstance(ec, dict) and ec.get("code"):
        ec["code"] = ""
        modified = True
    return modified


def _blank_message(msg: dict) -> bool:
    """Blank all text content in a message dict (any format)."""
    modified = False
    content = msg.get("content")
    if isinstance(content, str) and content:
        msg["content"] = ""
        modified = True
    elif isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                continue
            for key in ("text", "thinking", "signature", "content"):
                if key in block and isinstance(block[key], str) and block[key]:
                    block[key] = ""
                    modified = True

    # OpenAI tool_calls — blank function arguments
    for tc in msg.get("tool_calls", []):
        if isinstance(tc, dict):
            fn = tc.get("function", {})
            if isinstance(fn, dict) and fn.get("arguments"):
                fn["arguments"] = ""
                modified = True

    return modified


class BlockedError(Exception):
    """Raised when a request is blocked due to secrets in block mode."""

    def __init__(self, message: str, alerts: list[str]):
        super().__init__(message)
        self.alerts = alerts
