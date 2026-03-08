"""Redact secrets from text and restore them later.

Placeholders are deterministic and self-documenting:
  REDACTED<aws-access-key:a1b2c3d4e5f6>

The identifier comes from the pattern name, the suffix is a truncated
SHA-256 of the secret value. Same secret always produces the same
placeholder.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from secretgate.secrets.scanner import Match, SecretScanner


REDACTED_PREFIX = "REDACTED<"
REDACTED_SUFFIX = ">"


@dataclass
class RedactedSecret:
    """A secret that was redacted, with enough info to restore and audit."""

    placeholder: str
    original: str
    match: Match


def _slugify(name: str) -> str:
    """Turn a pattern name like 'AWS Access Key' into 'aws-access-key'."""
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-")


def _make_placeholder(match: Match) -> str:
    """Build a deterministic, self-documenting placeholder."""
    slug = _slugify(match.pattern_name)
    hash_suffix = hashlib.sha256(match.value.encode()).hexdigest()[:12]
    return f"{REDACTED_PREFIX}{slug}:{hash_suffix}{REDACTED_SUFFIX}"


class SecretRedactor:
    """Redacts secrets from text and can restore them later.

    Each instance holds state for one request/response cycle.
    Create a new instance per request.
    """

    def __init__(self, scanner: SecretScanner):
        self._scanner = scanner
        self._store: dict[str, RedactedSecret] = {}  # placeholder -> RedactedSecret

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
                placeholder = _make_placeholder(m)
                if placeholder not in self._store:
                    self._store[placeholder] = RedactedSecret(
                        placeholder=placeholder, original=m.value, match=m
                    )
                line = line[: m.start] + placeholder + line[m.end :]
            lines[idx] = line

        result = "".join(lines)

        # Second pass: replace any remaining occurrences of known secrets
        # (the scanner deduplicates, so repeated values are only matched once)
        for secret in self._store.values():
            result = result.replace(secret.original, secret.placeholder)

        return result

    def unredact(self, text: str) -> str:
        """Restore redacted placeholders with original values."""
        for placeholder, secret in self._store.items():
            text = text.replace(placeholder, secret.original)
        return text

    def clear(self) -> None:
        """Wipe stored secrets from memory."""
        # Overwrite values before clearing
        for secret in self._store.values():
            secret.original = "\x00" * len(secret.original)
        self._store.clear()
