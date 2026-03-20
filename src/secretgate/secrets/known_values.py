"""Known-value secret scanning — detect secrets by literal value, not shape.

Harvests actual secret values from environment variables and files at startup,
then scans text for literal occurrences using Aho-Corasick (if available) or
naive string matching as fallback.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from secretgate.secrets.scanner import Match


@dataclass
class HarvestConfig:
    """Configuration for known-value harvesting."""

    scan_env: bool = True
    env_keywords: tuple[str, ...] = (
        "KEY",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "CREDENTIAL",
        "AUTH",
        "PRIVATE",
        "API_KEY",
        "APIKEY",
        "ACCESS_KEY",
        "PASSPHRASE",
    )
    env_denylist: tuple[str, ...] = (
        "PATH",
        "HOME",
        "SHELL",
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "USER",
        "LOGNAME",
        "PWD",
        "OLDPWD",
        "EDITOR",
        "VISUAL",
        "DISPLAY",
        "HOSTNAME",
        "SHLVL",
        "TMPDIR",
        "TMP",
        "TEMP",
        "XDG_RUNTIME_DIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "COLORTERM",
        "TERM_PROGRAM",
        "LS_COLORS",
        "_",
    )
    secret_files: list[str] = field(default_factory=list)
    min_length: int = 8
    entropy_threshold: float = 2.5


@dataclass
class _HarvestedValue:
    """A secret value harvested from env or file."""

    value: str
    source: str  # e.g. "env" or file path
    key_name: str  # env var name or file key
    slug: str  # slugified key name for Match.pattern_name


def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _slugify(name: str) -> str:
    """Turn a key name into a slug for pattern_name."""
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-")


def _harvest_env(config: HarvestConfig) -> list[_HarvestedValue]:
    """Scan os.environ for secret-like variables."""
    results: list[_HarvestedValue] = []
    denylist_upper = {d.upper() for d in config.env_denylist}

    for name, value in os.environ.items():
        upper_name = name.upper()
        # Skip denylist
        if upper_name in denylist_upper:
            continue
        # Skip SECRETGATE_* vars
        if upper_name.startswith("SECRETGATE_"):
            continue
        # Check if name contains a keyword
        if not any(kw in upper_name for kw in config.env_keywords):
            continue
        # Check min length
        if len(value) < config.min_length:
            continue
        # Check entropy
        if _entropy(value) < config.entropy_threshold:
            continue

        results.append(
            _HarvestedValue(
                value=value,
                source="env",
                key_name=name,
                slug=_slugify(name),
            )
        )
    return results


def _parse_env_file(text: str) -> dict[str, str]:
    """Parse a .env file: KEY=VALUE lines, handle quotes, comments, export."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip optional 'export ' prefix
        if line.startswith("export "):
            line = line[7:]
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        # Remove surrounding quotes
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        if key:
            result[key] = value
    return result


def _parse_json_file(text: str) -> dict[str, str]:
    """Parse JSON, flatten top-level string values."""
    import json

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, str)}


def _parse_toml_file(text: str) -> dict[str, str]:
    """Parse TOML, flatten top-level string values."""
    import tomllib

    try:
        data = tomllib.loads(text)
    except Exception:
        return {}
    return {k: v for k, v in data.items() if isinstance(v, str)}


def _parse_ini_file(text: str) -> dict[str, str]:
    """Parse INI/CFG, extract all values."""
    import configparser

    parser = configparser.ConfigParser()
    try:
        parser.read_string(text)
    except configparser.Error:
        return {}
    result: dict[str, str] = {}
    for section in parser.sections():
        for key, value in parser.items(section):
            result[f"{section}.{key}"] = value
    return result


def _parse_plain_text(text: str) -> dict[str, str]:
    """One value per line (plain text fallback)."""
    result: dict[str, str] = {}
    for i, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if line and not line.startswith("#"):
            result[f"line-{i}"] = line
    return result


_PARSERS: dict[str, callable] = {
    ".env": _parse_env_file,
    ".json": _parse_json_file,
    ".toml": _parse_toml_file,
    ".ini": _parse_ini_file,
    ".cfg": _parse_ini_file,
}


def _harvest_file(path: str, config: HarvestConfig) -> list[_HarvestedValue]:
    """Parse a secret file and extract values."""
    file_path = Path(path)
    if not file_path.exists():
        return []

    try:
        text = file_path.read_text()
    except (OSError, UnicodeDecodeError):
        return []

    suffix = file_path.suffix.lower()
    parser = _PARSERS.get(suffix, _parse_plain_text)
    entries = parser(text)

    results: list[_HarvestedValue] = []
    for key, value in entries.items():
        if len(value) < config.min_length:
            continue
        if _entropy(value) < config.entropy_threshold:
            continue
        results.append(
            _HarvestedValue(
                value=value,
                source=str(file_path),
                key_name=key,
                slug=_slugify(key),
            )
        )
    return results


class KnownValueScanner:
    """Scans text for known secret values harvested from env/files."""

    def __init__(self, config: HarvestConfig | None = None):
        self._config = config or HarvestConfig()
        self._values: list[_HarvestedValue] = []
        self._automaton = None  # ahocorasick.Automaton or None
        self._harvest()
        self._build_index()

    def _harvest(self) -> None:
        """Collect secret values from configured sources."""
        seen_values: set[str] = set()

        if self._config.scan_env:
            for hv in _harvest_env(self._config):
                if hv.value not in seen_values:
                    seen_values.add(hv.value)
                    self._values.append(hv)

        for path in self._config.secret_files:
            for hv in _harvest_file(path, self._config):
                if hv.value not in seen_values:
                    seen_values.add(hv.value)
                    self._values.append(hv)

    def _build_index(self) -> None:
        """Build Aho-Corasick automaton if available, else prepare fallback."""
        if not self._values:
            return

        try:
            import ahocorasick

            self._automaton = ahocorasick.Automaton()
            for idx, hv in enumerate(self._values):
                self._automaton.add_word(hv.value, idx)
            self._automaton.make_automaton()
        except ImportError:
            # Fallback: sort longest-first for naive matching
            self._values.sort(key=lambda hv: len(hv.value), reverse=True)

    @property
    def value_count(self) -> int:
        """Number of harvested values."""
        return len(self._values)

    def scan(self, text: str) -> list[Match]:
        """Scan text for known secret values."""
        if not self._values:
            return []

        matches: list[Match] = []
        seen_values: set[str] = set()

        if self._automaton is not None:
            self._scan_ahocorasick(text, matches, seen_values)
        else:
            self._scan_naive(text, matches, seen_values)

        return matches

    def _scan_ahocorasick(self, text: str, matches: list[Match], seen_values: set[str]) -> None:
        """Scan using Aho-Corasick automaton."""
        # Pre-compute line starts for offset-to-line mapping
        line_starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                line_starts.append(i + 1)

        for end_idx, value_idx in self._automaton.iter(text):
            hv = self._values[value_idx]
            if hv.value in seen_values:
                continue
            seen_values.add(hv.value)

            start_idx = end_idx - len(hv.value) + 1
            # Binary search for line number
            line_num = self._find_line(line_starts, start_idx)
            line_start = line_starts[line_num - 1]

            matches.append(
                Match(
                    service="known-value",
                    pattern_name=hv.key_name,
                    value=hv.value,
                    line_number=line_num,
                    start=start_idx - line_start,
                    end=end_idx + 1 - line_start,
                )
            )

    @staticmethod
    def _find_line(line_starts: list[int], offset: int) -> int:
        """Find 1-based line number for a byte offset."""
        lo, hi = 0, len(line_starts) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if line_starts[mid] <= offset:
                lo = mid + 1
            else:
                hi = mid - 1
        return lo  # 1-based because lo ends up one past the last valid index

    def _scan_naive(self, text: str, matches: list[Match], seen_values: set[str]) -> None:
        """Fallback: check each value with `in` operator."""
        for hv in self._values:
            if hv.value in seen_values:
                continue
            pos = text.find(hv.value)
            if pos == -1:
                continue

            seen_values.add(hv.value)
            # Count newlines before pos to get line number
            line_num = text.count("\n", 0, pos) + 1
            line_start = text.rfind("\n", 0, pos) + 1  # 0 if no newline found

            matches.append(
                Match(
                    service="known-value",
                    pattern_name=hv.key_name,
                    value=hv.value,
                    line_number=line_num,
                    start=pos - line_start,
                    end=pos - line_start + len(hv.value),
                )
            )

    def clear(self) -> None:
        """Overwrite stored values with null bytes, then discard."""
        for hv in self._values:
            hv.value = "\x00" * len(hv.value)
        self._values.clear()
        self._automaton = None
