"""Raw text/bytes scanning adapter for the forward proxy.

Wraps the existing SecretScanner to work with raw HTTP bodies
instead of structured JSON messages.
"""

from __future__ import annotations

import json
import re
import zlib

import structlog

from secretgate.packfile import PACK_MAGIC, extract_texts_from_packfile
from secretgate.secrets.redactor import _make_placeholder
from secretgate.secrets.scanner import SecretScanner

logger = structlog.get_logger()

# JWT pattern used to extract session tokens from upstream response bodies.
# Mirrors the JWT Token signature in signatures.yaml.  Used by the forward
# proxy to track tokens issued by an upstream so they are not redacted when
# the client sends them back in a subsequent request body (issue #66).
_JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_./+=-]+")

# Bound the per-host session-token set so a busy host cannot grow memory
# without limit.  64 tokens per host is plenty (most APIs issue 1-3 long-lived
# session tokens) and bounds total memory at ~64 * 64 hosts * ~2 KB each.
MAX_SESSION_TOKENS = 64
MAX_SESSION_HOSTS = 64

# Module-level store of session tokens harvested from upstream responses,
# keyed by host.  Shared across all forward-proxy connections so a token
# observed on one TCP connection to host X is excluded from request scans
# on a *different* TCP connection to the same host X.  Without this, a
# client like wrangler that uses a connection pool would not benefit from
# session-token tracking, because /assets-upload-session and /versions
# could land on different sockets and therefore different handler instances.
_SESSION_TOKENS_BY_HOST: dict[str, set[str]] = {}


def extract_session_tokens(data: bytes) -> set[str]:
    """Extract JWT-shaped strings from raw bytes (e.g. an upstream response body).

    Used by the forward proxy to remember session tokens issued by upstream
    servers so the same tokens are not redacted when the client echoes them
    back in a follow-up request body.
    """
    if not data or b"eyJ" not in data:
        return set()
    return {m.group(0).decode("ascii", errors="replace") for m in _JWT_RE.finditer(data)}


def remember_session_tokens(host: str, data: bytes) -> int:
    """Harvest JWTs from ``data`` and remember them under ``host``.

    Returns the number of new tokens added.  Bounded per-host to
    ``MAX_SESSION_TOKENS`` and per-process to ``MAX_SESSION_HOSTS`` hosts so
    a long-running proxy cannot grow memory without limit.
    """
    if not host or not data:
        return 0
    tokens = extract_session_tokens(data)
    if not tokens:
        return 0
    bucket = _SESSION_TOKENS_BY_HOST.get(host)
    if bucket is None:
        if len(_SESSION_TOKENS_BY_HOST) >= MAX_SESSION_HOSTS:
            return 0
        bucket = set()
        _SESSION_TOKENS_BY_HOST[host] = bucket
    added = 0
    for tok in tokens:
        if len(bucket) >= MAX_SESSION_TOKENS:
            break
        if tok not in bucket:
            bucket.add(tok)
            added += 1
    return added


def get_session_tokens(host: str) -> set[str]:
    """Return tokens previously harvested from ``host`` upstream responses."""
    if not host:
        return set()
    bucket = _SESSION_TOKENS_BY_HOST.get(host)
    return set(bucket) if bucket else set()


def clear_session_tokens() -> None:
    """Clear all harvested session tokens.  Used by tests."""
    _SESSION_TOKENS_BY_HOST.clear()


class SessionTokenHarvester:
    """Streaming JWT harvester that decompresses gzip/deflate before scanning.

    Cloudflare (and most APIs) return responses with ``Content-Encoding: gzip``.
    Running the JWT regex on the compressed bytes silently finds nothing, so
    session tokens issued by the upstream are never remembered and the same
    tokens get redacted when the client echoes them back in a follow-up
    request.  This class wraps a streaming decompressor so each chunk of the
    upstream response is decompressed, then buffered, then scanned when the
    response ends — buffering is necessary because a JWT may span multiple
    compressed or un-compressed chunks.

    A harvester is created per response (HTTP/1.1) or per stream (HTTP/2).
    Callers:

        h = SessionTokenHarvester(host, content_encoding)
        for chunk in response_body_chunks:
            h.feed(chunk)     # decompresses + buffers, relay chunk unmodified
        h.close()             # decompress-flush + scan buffer, returns count
    """

    # Cap the per-response decompressed buffer so a pathological upstream
    # cannot exhaust memory with a huge gzipped JSON body.
    MAX_BUFFER = 1 * 1024 * 1024  # 1 MB

    def __init__(self, host: str, content_encoding: str = "") -> None:
        self._host = host
        self._decompressor: zlib._Decompress | None = None
        self._buffer = bytearray()
        self._overflow = False
        encoding = (content_encoding or "").lower().strip()
        if encoding in ("gzip", "x-gzip", "deflate"):
            # wbits = 32 + MAX_WBITS auto-detects gzip header vs zlib wrapper
            # vs raw deflate, so a single path covers both encodings.
            self._decompressor = zlib.decompressobj(32 + zlib.MAX_WBITS)
            self._supported = True
        elif encoding and encoding != "identity":
            # br (brotli), zstd etc. — not supported, harvest will be a no-op
            logger.debug(
                "session_token_harvester_unsupported_encoding",
                host=host,
                encoding=encoding,
            )
            self._supported = False
        else:
            self._supported = True

    def _append(self, data: bytes) -> None:
        """Append data to the buffer, bounded by MAX_BUFFER."""
        if self._overflow or not data:
            return
        room = self.MAX_BUFFER - len(self._buffer)
        if room <= 0:
            self._overflow = True
            return
        if len(data) > room:
            self._buffer.extend(data[:room])
            self._overflow = True
        else:
            self._buffer.extend(data)

    def feed(self, data: bytes) -> int:
        """Feed one chunk of the upstream response body.

        Returns 0 — tokens are scanned on ``close()``.  Relay the original
        (un-decompressed) ``data`` bytes to the client unchanged; this method
        only observes, it never mutates.
        """
        if not data or not self._supported:
            return 0
        if self._decompressor is not None:
            try:
                decompressed = self._decompressor.decompress(data)
            except zlib.error:
                # Corrupt stream — disable further decompression on this
                # harvester so we don't keep retrying on each chunk.
                self._supported = False
                return 0
            if decompressed:
                self._append(decompressed)
        else:
            self._append(data)
        return 0

    def close(self) -> int:
        """Flush trailing state and scan the accumulated buffer.

        Returns the number of new tokens added to the per-host store.
        """
        if not self._supported:
            return 0
        if self._decompressor is not None:
            try:
                tail = self._decompressor.flush()
            except zlib.error:
                tail = b""
            if tail:
                self._append(tail)
        if not self._buffer:
            return 0
        added = remember_session_tokens(self._host, bytes(self._buffer))
        # Release buffer memory once scanned
        self._buffer = bytearray()
        return added


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

# Git packfile content types — binary but contain scannable objects
_GIT_PACK_TYPES = frozenset(
    {
        "application/x-git-receive-pack-request",
        "application/x-git-upload-pack-request",
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
        # Git packfile types are binary but contain scannable objects
        if ct in _GIT_PACK_TYPES:
            return True
        if any(ct.startswith(p) for p in _SKIP_PREFIXES):
            return False
        if ct in _SKIP_TYPES:
            return False
        return True

    def _is_git_packfile(self, body: bytes, content_type: str) -> bool:
        """Return True if this request is a git packfile."""
        ct = content_type.lower().split(";")[0].strip()
        if ct in _GIT_PACK_TYPES:
            return True
        # Also detect by PACK magic in the body (could be generic octet-stream)
        return PACK_MAGIC in body[:8192]  # only check first 8KB for the magic

    def scan_packfile(self, body: bytes) -> tuple[bytes, list[str]]:
        """Scan a git packfile for secrets.

        Extracts text from commit, blob, and tag objects and scans each.
        In audit mode: logs alerts, returns body unchanged.
        In block/redact mode: raises BlockedError (packfiles cannot be safely
        rewritten without corrupting checksums and delta chains).
        """
        alerts: list[str] = []
        texts = extract_texts_from_packfile(body)

        if not texts:
            return body, alerts

        all_matches = []
        for text in texts:
            matches = self._scanner.scan(text)
            all_matches.extend(matches)

        if not all_matches:
            return body, alerts

        for m in all_matches:
            alert = f"Secret detected in git packfile: {m.service}/{m.pattern_name} on line {m.line_number}"
            alerts.append(alert)
            logger.warning(
                "packfile_secret_detected",
                service=m.service,
                pattern=m.pattern_name,
                line=m.line_number,
            )

        if self._mode == "audit":
            return body, alerts

        # Block and redact modes both block — we cannot safely rewrite
        # individual objects inside a packfile without recomputing checksums
        # and potentially breaking delta chains.
        secret_list = "; ".join(f"{m.service}/{m.pattern_name}" for m in all_matches)
        raise BlockedError(
            f"Git push blocked: {len(all_matches)} secret(s) detected in packfile ({secret_list})",
            alerts,
        )

    def scan_body(
        self,
        body: bytes,
        content_type: str = "text/plain",
        exclude_values: set[str] | None = None,
    ) -> tuple[bytes, list[str]]:
        """Scan body bytes for secrets. Returns (possibly modified body, alerts).

        In block mode, raises BlockedError if secrets are found.
        In audit mode, returns body unchanged but with alerts.
        In redact mode, replaces secrets with [REDACTED] markers.

        ``exclude_values`` — secret values to ignore (e.g. the request's own
        Authorization token).  If a match's value is contained in any of the
        exclude strings it is silently dropped so the proxy never corrupts a
        request by redacting its own auth credential.
        """
        alerts: list[str] = []

        if not body or not self.should_scan(content_type):
            return body, alerts

        # Route git packfiles to the packfile scanner
        if self._is_git_packfile(body, content_type):
            return self.scan_packfile(body)

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

        # Drop matches that ARE the request's own auth token (not just any
        # substring).  A match is considered "the same credential" when it
        # covers ≥50 % of an exclude value's length — this allows partial
        # regex captures (e.g. JWT pattern grabbing 2 of 3 segments) while
        # preventing a short, unrelated secret from being silently skipped
        # just because it happens to appear inside a long token string.
        if matches and exclude_values:
            matches = [
                m
                for m in matches
                if not any(m.value in ev and len(m.value) >= len(ev) * 0.5 for ev in exclude_values)
            ]

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

# Allowlist of media types known to carry binary payloads (images, PDFs,
# audio, video).  The base64 ``data`` field of a content block with one of
# these media types decodes to opaque bytes that cannot contain text
# secrets — but that DO trip the entropy detector and corrupt legitimate
# content when redacted.  We only blank ``data`` when ``media_type`` is on
# this allowlist so a field advertising itself as ``text/plain`` (or missing
# a media type entirely) remains scannable for base64-encoded exfiltration.
_BINARY_MEDIA_TYPE_PREFIXES = ("image/", "audio/", "video/")
_BINARY_MEDIA_TYPES = frozenset({"application/pdf"})


def _is_binary_media_type(media_type: str) -> bool:
    if not isinstance(media_type, str) or not media_type:
        return False
    mt = media_type.lower().strip()
    if any(mt.startswith(p) for p in _BINARY_MEDIA_TYPE_PREFIXES):
        return True
    return mt in _BINARY_MEDIA_TYPES


def _blank_binary_image_data(block: dict) -> bool:
    """Blank the base64 ``data`` field of image/document blocks with binary media.

    The Anthropic content-block shape is
    ``{"type":"image"|"document","source":{"type":"base64","media_type":"...","data":"..."}}``.
    Only touches ``data`` — leaves ``media_type``, ``type``, and the rest of
    the block intact so the upstream API still receives a valid request.
    """
    if not isinstance(block, dict):
        return False
    if block.get("type") not in ("image", "document"):
        return False
    source = block.get("source")
    if not isinstance(source, dict):
        return False
    if source.get("type") != "base64":
        return False
    if not _is_binary_media_type(source.get("media_type", "")):
        return False
    data = source.get("data")
    if not isinstance(data, str) or not data:
        return False
    source["data"] = ""
    return True


def _blank_binary_blocks(blocks: list) -> bool:
    """Recursively blank binary image/document data in a content block list.

    Descends into ``tool_result.content`` so image blocks nested inside a
    tool result are also handled.
    """
    modified = False
    for block in blocks:
        if not isinstance(block, dict):
            continue
        modified = _blank_binary_image_data(block) or modified
        if block.get("type") == "tool_result":
            inner = block.get("content")
            if isinstance(inner, list):
                modified = _blank_binary_blocks(inner) or modified
    return modified


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

        # Keep the last user turn — strip only thinking blocks AND blank
        # binary image/document data (high-entropy false positives).
        if i >= last_turn_start:
            content = msg.get("content")
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "thinking":
                        for key in ("thinking", "signature"):
                            if key in block and block[key]:
                                block[key] = ""
                                modified = True
                modified = _blank_binary_blocks(content) or modified
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
            # Blank string fields that carry text content
            for key in ("text", "thinking", "signature", "content"):
                if key in block and isinstance(block[key], str) and block[key]:
                    block[key] = ""
                    modified = True
            # Blank list content (e.g. tool_result.content, server tool results)
            for key in ("content",):
                if key in block and isinstance(block[key], list):
                    block[key] = []
                    modified = True
            # Anthropic tool_use.input — dict field with tool arguments
            if "input" in block and isinstance(block["input"], dict) and block["input"]:
                block["input"] = {}
                modified = True
            # Anthropic document source — blank text content
            source = block.get("source")
            if isinstance(source, dict):
                for key in ("text", "content"):
                    if key in source and isinstance(source[key], str) and source[key]:
                        source[key] = ""
                        modified = True
            # Anthropic image/document binary base64 data
            modified = _blank_binary_image_data(block) or modified

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
