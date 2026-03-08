"""Secret detection via regex patterns + Shannon entropy.

Inspired by CodeGate's approach but simplified — no singletons, no locks,
just a class you instantiate with patterns.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Match:
    """A detected secret."""

    service: str
    pattern_name: str
    value: str
    line_number: int
    start: int  # start index within the line
    end: int  # end index within the line


@dataclass
class _CompiledPattern:
    service: str
    name: str
    regex: re.Pattern[str]


class SecretScanner:
    """Scans text for secrets using regex patterns and entropy analysis."""

    def __init__(
        self,
        signatures_path: Path | None = None,
        entropy_threshold: float = 4.0,
    ):
        self._entropy_threshold = entropy_threshold
        self._patterns: list[_CompiledPattern] = []

        path = signatures_path or Path(__file__).parent.parent / "signatures.yaml"
        self._load_patterns(path)

    def _load_patterns(self, path: Path) -> None:
        if not path.exists():
            return
        with open(path) as f:
            data = yaml.safe_load(f)
        if not isinstance(data, list):
            return

        for group in data:
            if not isinstance(group, dict):
                continue
            for service, patterns in group.items():
                if not isinstance(patterns, list):
                    continue
                for pat_dict in patterns:
                    if not isinstance(pat_dict, dict):
                        continue
                    for name, regex_str in pat_dict.items():
                        try:
                            compiled = re.compile(regex_str)
                            self._patterns.append(
                                _CompiledPattern(service=service, name=name, regex=compiled)
                            )
                        except re.error:
                            pass  # skip invalid patterns

    def scan(self, text: str) -> list[Match]:
        """Scan text and return all detected secrets."""
        matches: list[Match] = []
        seen: set[str] = set()  # deduplicate by value

        lines = text.splitlines()
        for line_num, line in enumerate(lines, start=1):
            # Regex-based detection
            for pat in self._patterns:
                for m in pat.regex.finditer(line):
                    value = m.group(0)
                    if value not in seen:
                        seen.add(value)
                        matches.append(
                            Match(
                                service=pat.service,
                                pattern_name=pat.name,
                                value=value,
                                line_number=line_num,
                                start=m.start(),
                                end=m.end(),
                            )
                        )

            # Entropy-based detection for key=value patterns
            for em in self._find_entropy_matches(line, line_num):
                if em.value not in seen:
                    seen.add(em.value)
                    matches.append(em)

        return matches

    def _find_entropy_matches(self, line: str, line_num: int) -> list[Match]:
        """Find high-entropy values in key=value assignments."""
        matches: list[Match] = []
        # Match: KEY=VALUE, KEY="VALUE", KEY='VALUE', KEY: VALUE
        kv_pattern = re.compile(
            r"""(?:^|[\s,;{])([A-Z_][A-Z0-9_]*)\s*[=:]\s*["']?([^\s"',;}{]+)["']?""",
            re.IGNORECASE,
        )
        for m in kv_pattern.finditer(line):
            key, value = m.group(1), m.group(2)
            # Skip short values and common non-secret patterns
            if len(value) < 8 or value.lower() in ("true", "false", "null", "none", "undefined"):
                continue
            if self._entropy(value) >= self._entropy_threshold:
                matches.append(
                    Match(
                        service="entropy",
                        pattern_name=f"high-entropy value ({key})",
                        value=value,
                        line_number=line_num,
                        start=m.start(2),
                        end=m.end(2),
                    )
                )
        return matches

    @staticmethod
    def _entropy(s: str) -> float:
        """Shannon entropy of a string."""
        if not s:
            return 0.0
        freq: dict[str, int] = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())
