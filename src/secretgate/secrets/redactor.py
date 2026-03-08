"""Redact secrets from text and restore them later.

Simple UUID-placeholder approach: replace secret with REDACTED<uuid>,
store the mapping, reverse it on output.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from secretgate.secrets.scanner import Match, SecretScanner


REDACTED_PREFIX = "REDACTED<"
REDACTED_SUFFIX = ">"


@dataclass
class RedactedSecret:
    """A secret that was redacted, with enough info to restore and audit."""

    placeholder: str
    original: str
    match: Match


class SecretRedactor:
    """Redacts secrets from text and can restore them later.

    Each instance holds state for one request/response cycle.
    Create a new instance per request.
    """

    def __init__(self, scanner: SecretScanner):
        self._scanner = scanner
        self._store: dict[str, RedactedSecret] = {}  # placeholder_id -> RedactedSecret

    @property
    def redacted_secrets(self) -> list[RedactedSecret]:
        return list(self._store.values())

    @property
    def count(self) -> int:
        return len(self._store)

    def redact(self, text: str) -> str:
        """Scan text for secrets and replace them with placeholders."""
        matches = self._scanner.scan(text)
        if not matches:
            return text

        # Sort by position (last first) so replacements don't shift indices
        # We work line-by-line to handle multi-line text correctly
        lines = text.splitlines(keepends=True)

        # Group matches by line number
        by_line: dict[int, list[Match]] = {}
        for m in matches:
            by_line.setdefault(m.line_number, []).append(m)

        for line_num, line_matches in by_line.items():
            idx = line_num - 1
            if idx >= len(lines):
                continue
            line = lines[idx]
            # Sort matches right-to-left so replacements don't shift positions
            for m in sorted(line_matches, key=lambda m: m.start, reverse=True):
                placeholder_id = uuid.uuid4().hex[:12]
                placeholder = f"{REDACTED_PREFIX}{placeholder_id}{REDACTED_SUFFIX}"
                self._store[placeholder_id] = RedactedSecret(
                    placeholder=placeholder, original=m.value, match=m
                )
                line = line[: m.start] + placeholder + line[m.end :]
            lines[idx] = line

        return "".join(lines)

    def unredact(self, text: str) -> str:
        """Restore redacted placeholders with original values."""
        for pid, secret in self._store.items():
            text = text.replace(secret.placeholder, secret.original)
        return text

    def clear(self) -> None:
        """Wipe stored secrets from memory."""
        # Overwrite values before clearing
        for secret in self._store.values():
            secret.original = "\x00" * len(secret.original)
        self._store.clear()
