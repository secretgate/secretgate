#!/usr/bin/env python3
"""Gap analysis: compare secretgate patterns against external pattern databases.

Compares secretgate's ~90 regex patterns against:
- secrets-patterns-db (~1,600 patterns from mazen160)
- gitleaks (~60 patterns)

Outputs a human-readable report and YAML candidates file with patterns
secretgate is missing.

Usage:
    python scripts/gap_analysis.py
    python scripts/gap_analysis.py --output-dir ./results --verbose
"""

from __future__ import annotations

import argparse
import re
import string
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO
from urllib.request import urlopen, Request

import yaml

# stdlib in 3.11+
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SECRETS_PATTERNS_DB_URL = (
    "https://raw.githubusercontent.com/mazen160/secrets-patterns-db/master/db/rules-stable.yml"
)
GITLEAKS_URL = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"

# Keywords that indicate a pattern is relevant for an LLM proxy
RELEVANT_KEYWORDS = {
    "key",
    "token",
    "secret",
    "password",
    "credential",
    "api",
    "auth",
    "private",
    "bearer",
    "webhook",
    "connection",
    "jwt",
    "pat",
    "oauth",
    "access",
    "signing",
    "encryption",
    "certificate",
    "cert",
}

# Keywords that indicate a pattern is NOT relevant for an LLM proxy
IRRELEVANT_KEYWORDS = {
    "ip address",
    "ipv4",
    "ipv6",
    "email",
    "phone",
    "credit card",
    "social security",
    "ssn",
    "file path",
    "filepath",
    "arn",
    "url",
    "domain",
    "hostname",
    "uuid",
    "gateway",
    "endpoint",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NormalizedPattern:
    """A pattern from any source, normalized to a common format."""

    source: str  # "secretgate", "secrets-patterns-db", "gitleaks"
    service: str  # e.g. "Amazon", "GitHub"
    name: str  # e.g. "AWS Access Key", "github-pat"
    regex: str  # raw regex string
    confidence: str  # "high", "low", or ""
    keywords: tuple[str, ...] = ()
    literal_prefix: str = ""
    name_tokens: frozenset[str] = field(default_factory=frozenset)


@dataclass
class MatchResult:
    """Result of matching an external pattern against secretgate."""

    external: NormalizedPattern
    matched_by: NormalizedPattern | None = None
    tier: str = ""  # "prefix", "keyword", "synthetic", or ""
    note: str = ""


# ---------------------------------------------------------------------------
# HTTP fetching
# ---------------------------------------------------------------------------


def fetch_url(url: str) -> str:
    """Fetch a URL and return its text content."""
    req = Request(url, headers={"User-Agent": "secretgate-gap-analysis/1.0"})
    with urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def load_source(path_or_url: str) -> str:
    """Load content from a URL or local file path."""
    if path_or_url.startswith(("http://", "https://")):
        print(f"  Downloading {path_or_url} ...")
        return fetch_url(path_or_url)
    else:
        p = Path(path_or_url)
        if not p.exists():
            print(f"  ERROR: File not found: {p}", file=sys.stderr)
            sys.exit(1)
        return p.read_text()


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def parse_secretgate(path: str) -> list[NormalizedPattern]:
    """Parse secretgate's signatures.yaml."""
    text = Path(path).read_text()
    data = yaml.safe_load(text)
    patterns = []
    if not isinstance(data, list):
        return patterns

    for group in data:
        if not isinstance(group, dict):
            continue
        for service, pat_list in group.items():
            if not isinstance(pat_list, list):
                continue
            for pat_dict in pat_list:
                if not isinstance(pat_dict, dict):
                    continue
                for name, regex_str in pat_dict.items():
                    prefix = extract_literal_prefix(regex_str)
                    tokens = tokenize_name(f"{service} {name}")
                    patterns.append(
                        NormalizedPattern(
                            source="secretgate",
                            service=str(service),
                            name=str(name),
                            regex=str(regex_str),
                            confidence="high",
                            literal_prefix=prefix,
                            name_tokens=tokens,
                        )
                    )
    return patterns


def parse_secrets_patterns_db(text: str, include_low: bool = False) -> list[NormalizedPattern]:
    """Parse secrets-patterns-db YAML format."""
    data = yaml.safe_load(text)
    patterns = []
    # Handle both top-level list and dict with 'patterns' key
    if isinstance(data, dict) and "patterns" in data:
        entries = data["patterns"]
    elif isinstance(data, list):
        entries = data
    else:
        return patterns

    for entry in entries:
        if not isinstance(entry, dict) or "pattern" not in entry:
            continue
        pat = entry["pattern"]
        name = pat.get("name", "")
        regex = pat.get("regex", "")
        confidence = pat.get("confidence", "low")

        if not regex or not name:
            continue
        if confidence == "low" and not include_low:
            continue

        # Try to extract service from the name (first word or known prefix)
        service = _extract_service_from_name(name)
        prefix = extract_literal_prefix(regex)
        tokens = tokenize_name(name)

        patterns.append(
            NormalizedPattern(
                source="secrets-patterns-db",
                service=service,
                name=name,
                regex=regex,
                confidence=confidence,
                literal_prefix=prefix,
                name_tokens=tokens,
            )
        )
    return patterns


def parse_gitleaks(text: str) -> list[NormalizedPattern]:
    """Parse gitleaks TOML config."""
    if tomllib is None:
        print("  WARNING: tomllib not available, skipping gitleaks", file=sys.stderr)
        return []

    data = tomllib.loads(text)
    patterns = []

    for rule in data.get("rules", []):
        rule_id = rule.get("id", "")
        regex = rule.get("regex", "")
        keywords = tuple(rule.get("keywords", []))

        if not regex:
            continue

        service = _extract_service_from_name(rule_id.replace("-", " "))
        prefix = extract_literal_prefix(regex)
        tokens = tokenize_name(rule_id.replace("-", " "))

        patterns.append(
            NormalizedPattern(
                source="gitleaks",
                service=service,
                name=rule_id,
                regex=regex,
                confidence="high",
                keywords=keywords,
                literal_prefix=prefix,
                name_tokens=tokens,
            )
        )
    return patterns


_SERVICE_PREFIXES = {
    "aws",
    "gcp",
    "google",
    "azure",
    "github",
    "gitlab",
    "bitbucket",
    "slack",
    "discord",
    "telegram",
    "stripe",
    "twilio",
    "sendgrid",
    "mailgun",
    "mailchimp",
    "shopify",
    "heroku",
    "vercel",
    "npm",
    "pypi",
    "rubygems",
    "docker",
    "digitalocean",
    "cloudflare",
    "databricks",
    "supabase",
    "firebase",
    "openai",
    "anthropic",
    "hugging",
    "replicate",
    "grafana",
    "sentry",
    "datadog",
    "new relic",
    "newrelic",
    "hashicorp",
    "vault",
    "terraform",
    "pulumi",
    "fly",
    "planetscale",
    "airtable",
    "notion",
    "linear",
    "atlassian",
    "jira",
    "confluence",
    "postman",
    "doppler",
    "buildkite",
    "octopus",
    "1password",
    "age",
    "artifactory",
    "mongodb",
    "postgres",
    "mysql",
    "redis",
    "alibaba",
    "square",
    "plaid",
    "flutterwave",
    "dynatrace",
    "typeform",
    "sendinblue",
    "perplexity",
    "confluent",
    "twitch",
    "facebook",
    "meta",
    "instagram",
    "twitter",
    "linkedin",
    "pinterest",
    "snapchat",
    "tiktok",
    "spotify",
    "dropbox",
    "asana",
    "clickup",
    "monday",
    "figma",
    "lob",
    "mapbox",
    "rapidapi",
    "shodan",
    "snyk",
    "sonarcloud",
    "sumologic",
    "travisci",
    "codecov",
    "coveralls",
    "circleci",
    "jenkins",
    "gitlab",
    "bitbucket",
    "launchdarkly",
    "split",
    "fastly",
    "netlify",
    "render",
    "railway",
    "upstash",
    "neon",
    "cockroachdb",
    "fauna",
    "contentful",
    "sanity",
    "algolia",
    "meilisearch",
    "elastic",
    "opensearch",
    "adafruit",
    "adobe",
    "age",
    "aiven",
    "clojars",
    "confluent",
    "contentful",
    "duffel",
    "easypost",
    "finicity",
    "frameio",
    "gitter",
    "grafana",
    "hubspot",
    "infracost",
    "intercom",
    "ionic",
    "kraken",
    "kucoin",
    "launchdarkly",
    "lob",
    "maxmind",
    "messagebird",
    "netlify",
    "nytimes",
    "okta",
    "openweathermap",
    "prefect",
    "readme",
    "rubygems",
    "scalingo",
    "sidekiq",
    "sourcegraph",
    "tailscale",
    "tatoo",
    "teams",
    "telegram",
    "trello",
    "twitch",
    "vault",
    "yandex",
    "zendesk",
    "zeplin",
}


def _extract_service_from_name(name: str) -> str:
    """Try to extract a service name from the pattern name."""
    lower = name.lower()
    # Check known prefixes
    for svc in sorted(_SERVICE_PREFIXES, key=len, reverse=True):
        if lower.startswith(svc):
            return name[: len(svc)].strip().title()
    # Fall back to first word
    parts = name.split()
    return parts[0].title() if parts else "Unknown"


# ---------------------------------------------------------------------------
# Prefix extraction and name tokenization
# ---------------------------------------------------------------------------


def extract_literal_prefix(regex: str) -> str:
    """Extract the fixed literal prefix from a regex string.

    Strips leading anchors, non-capturing groups, case-insensitive flags,
    word boundaries, and optional quotes to find the first run of literal
    characters (4+ chars required).
    """
    s = regex

    # Strip leading anchors and common regex noise
    while True:
        old = s
        s = re.sub(r"^\^", "", s)
        s = re.sub(r"^\\b", "", s)
        s = re.sub(r"^\(\?[imsxu]+\)", "", s)  # inline flags like (?i)
        s = re.sub(r"^\(\?:", "", s)  # non-capturing group start
        s = re.sub(r"^[\[\(][\'\"][\]\)][\?*]?", "", s)  # optional quotes
        s = re.sub(r"^[\'\"\[\]]", "", s)  # leading quotes/brackets
        if s == old:
            break

    prefix = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            # Escaped literal characters
            nc = s[i + 1]
            if nc in r"\.+*?[](){}|^$":
                prefix.append(nc)
                i += 2
                continue
            elif nc == "s":  # \s is not a literal
                break
            else:
                # Other escapes like \d, \w are not literals
                break
        elif c in r"[({|^$*+?":
            break
        else:
            prefix.append(c)
            i += 1

    result = "".join(prefix)
    return result if len(result) >= 4 else ""


def tokenize_name(name: str) -> frozenset[str]:
    """Break a pattern name into lowercase keyword tokens."""
    # Replace separators with spaces
    cleaned = re.sub(r"[-_/]", " ", name.lower())
    # Split on spaces and camelCase
    tokens = set()
    for word in cleaned.split():
        # Split camelCase
        parts = re.sub(r"([a-z])([A-Z])", r"\1 \2", word).split()
        tokens.update(p.lower() for p in parts if len(p) >= 2)
    # Remove very common non-discriminating words
    tokens -= {"the", "a", "an", "in", "of", "for", "to", "and", "or", "v1", "v2"}
    return frozenset(tokens)


# ---------------------------------------------------------------------------
# Synthetic test string generation
# ---------------------------------------------------------------------------


def generate_test_string(regex: str) -> str | None:
    """Generate a sample string that should match the given regex.

    Handles common regex constructs. Returns None for unsupported patterns.
    """
    # Clean up the regex
    s = regex
    # Remove anchors and word boundaries
    s = re.sub(r"^\^|\\b|\$$", "", s)
    # Remove inline flags
    s = re.sub(r"\(\?[imsxu]+\)", "", s)

    result = []
    i = 0
    while i < len(s):
        c = s[i]

        if c == "\\" and i + 1 < len(s):
            nc = s[i + 1]
            if nc == "d":
                result.append("5")
                i += 2
            elif nc == "w":
                result.append("a")
                i += 2
            elif nc == "s":
                result.append(" ")
                i += 2
            elif nc in r"\.+*?[](){}|^$-":
                result.append(nc)
                i += 2
            elif nc == "n":
                result.append("\n")
                i += 2
            elif nc == "r":
                result.append("\r")
                i += 2
            elif nc == "x" and i + 3 < len(s):
                # hex escape \x60
                hexchars = s[i + 2 : i + 4]
                try:
                    result.append(chr(int(hexchars, 16)))
                    i += 4
                except ValueError:
                    return None
            else:
                result.append(nc)
                i += 2

        elif c == "[":
            # Character class
            end = s.find("]", i + 1)
            if end == -1:
                return None
            char_class = s[i + 1 : end]
            sample = _sample_from_char_class(char_class)
            if sample is None:
                return None
            result.append(sample)
            i = end + 1

        elif c == "(":
            # Check for non-capturing group or alternation
            if s[i:].startswith("(?:"):
                # Find matching close paren
                depth = 1
                j = i + 3
                while j < len(s) and depth > 0:
                    if s[j] == "(" and (j == 0 or s[j - 1] != "\\"):
                        depth += 1
                    elif s[j] == ")" and (j == 0 or s[j - 1] != "\\"):
                        depth -= 1
                    j += 1
                group_content = s[i + 3 : j - 1]
                # Take first alternative
                alt = _first_alternative(group_content)
                sub = generate_test_string(alt)
                if sub is None:
                    return None
                result.append(sub)
                i = j
            elif s[i:].startswith("(?i)") or s[i:].startswith("(?s)"):
                i += 4
            else:
                # Capturing group
                depth = 1
                j = i + 1
                while j < len(s) and depth > 0:
                    if s[j] == "(" and (j == 0 or s[j - 1] != "\\"):
                        depth += 1
                    elif s[j] == ")" and (j == 0 or s[j - 1] != "\\"):
                        depth -= 1
                    j += 1
                group_content = s[i + 1 : j - 1]
                alt = _first_alternative(group_content)
                sub = generate_test_string(alt)
                if sub is None:
                    return None
                result.append(sub)
                i = j

        elif c in "+*?":
            # Quantifier — apply to last char
            if c == "+":
                # Already have one from the base, add a few more
                if result:
                    result.append(result[-1] * 2)
            elif c == "*":
                pass  # zero is fine
            elif c == "?":
                pass  # one is fine
            i += 1

        elif c == "{":
            # Quantifier {n}, {n,m}, {n,}
            end = s.find("}", i)
            if end == -1:
                return None
            quant = s[i + 1 : end]
            parts = quant.split(",")
            try:
                n = int(parts[0])
            except ValueError:
                return None
            # We already have 1 from the base char, add n-1 more
            if result and n > 1:
                last = result[-1][-1] if result[-1] else "a"
                result.append(last * (n - 1))
            i = end + 1

        elif c == "|":
            # We're in an alternation at top level — stop here, we already
            # have the first branch
            break

        elif c == ")":
            # End of group we didn't enter — skip
            i += 1

        else:
            result.append(c)
            i += 1

    generated = "".join(result)
    return generated if len(generated) >= 4 else None


def _sample_from_char_class(char_class: str) -> str | None:
    """Return a single character that belongs to the given character class."""
    if not char_class:
        return None

    # Handle negation
    negated = char_class.startswith("^")
    if negated:
        char_class = char_class[1:]

    chars = set()
    i = 0
    while i < len(char_class):
        if char_class[i] == "\\" and i + 1 < len(char_class):
            nc = char_class[i + 1]
            if nc == "d":
                chars.update("0123456789")
            elif nc == "w":
                chars.update(string.ascii_letters + string.digits + "_")
            elif nc == "s":
                chars.update(" \t\n")
            elif nc == "S":
                chars.add("a")
            elif nc == "-":
                chars.add("-")
            elif nc == ".":
                chars.add(".")
            elif nc == "/":
                chars.add("/")
            elif nc == "n":
                chars.add("\n")
            else:
                chars.add(nc)
            i += 2
        elif i + 2 < len(char_class) and char_class[i + 1] == "-":
            # Range like a-z
            start_c = char_class[i]
            end_c = char_class[i + 2]
            try:
                for c in range(ord(start_c), ord(end_c) + 1):
                    chars.add(chr(c))
            except (ValueError, TypeError):
                return None
            i += 3
        else:
            chars.add(char_class[i])
            i += 1

    if negated:
        # Pick a printable char not in the set
        for c in string.ascii_letters + string.digits:
            if c not in chars:
                return c
        return None

    if not chars:
        return None

    # Prefer alphanumeric characters
    for c in sorted(chars):
        if c.isalnum():
            return c
    return sorted(chars)[0]


def _first_alternative(group_content: str) -> str:
    """Return the first alternative from a group (split on unescaped |)."""
    depth = 0
    start = 0
    for i, c in enumerate(group_content):
        if c == "(" and (i == 0 or group_content[i - 1] != "\\"):
            depth += 1
        elif c == ")" and (i == 0 or group_content[i - 1] != "\\"):
            depth -= 1
        elif c == "|" and depth == 0:
            return group_content[start:i]
    return group_content[start:]


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


def match_external_pattern(
    ext: NormalizedPattern,
    sg_patterns: list[NormalizedPattern],
    verbose: bool = False,
) -> MatchResult:
    """Try to match an external pattern against secretgate's patterns.

    Uses 3 tiers: literal prefix, keyword overlap, synthetic test string.
    """
    # Tier 1: Literal prefix match (4+ chars, but skip overly generic prefixes)
    _GENERIC_PREFIXES = {"http://", "https://", "http", "https"}
    if ext.literal_prefix and len(ext.literal_prefix) >= 4:
        for sg in sg_patterns:
            if sg.literal_prefix and len(sg.literal_prefix) >= 4:
                if ext.literal_prefix.startswith(sg.literal_prefix) or sg.literal_prefix.startswith(
                    ext.literal_prefix
                ):
                    # Skip if the shared prefix is just a generic URL scheme
                    shared = (
                        ext.literal_prefix
                        if len(ext.literal_prefix) <= len(sg.literal_prefix)
                        else sg.literal_prefix
                    )
                    if shared.rstrip("/") in _GENERIC_PREFIXES:
                        continue
                    return MatchResult(
                        ext, sg, "prefix", f"prefix '{ext.literal_prefix}' ~ '{sg.literal_prefix}'"
                    )

    # Tier 2: Service + name keyword overlap
    ext_service = ext.service.lower()
    for sg in sg_patterns:
        sg_service = sg.service.lower()
        # Check if services match (substring match for flexibility)
        service_match = (
            ext_service == sg_service or ext_service in sg_service or sg_service in ext_service
        )
        if service_match and ext.name_tokens and sg.name_tokens:
            overlap = ext.name_tokens & sg.name_tokens
            # Require at least 1 meaningful keyword overlap beyond service name
            meaningful = overlap - {ext_service, sg_service}
            # Also check full overlap (service counts if both have it)
            if len(overlap) >= 2 or len(meaningful) >= 1:
                return MatchResult(
                    ext, sg, "keyword", f"service '{ext.service}' + keywords {overlap}"
                )

    # Tier 3: Synthetic test string
    test_str = generate_test_string(ext.regex)
    if test_str:
        import warnings

        for sg in sg_patterns:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    compiled = re.compile(sg.regex)
                if compiled.search(test_str):
                    return MatchResult(
                        ext, sg, "synthetic", f"test string matched: {test_str[:50]!r}"
                    )
            except re.error:
                continue

    return MatchResult(ext)


# ---------------------------------------------------------------------------
# Relevance filter
# ---------------------------------------------------------------------------


def is_relevant(pat: NormalizedPattern) -> bool:
    """Check if a pattern is relevant for an LLM proxy use case.

    For an LLM proxy, we want patterns that match secrets by their *format*
    (distinctive prefix, structure) rather than by surrounding context
    (variable name nearby). Context-dependent patterns like
    ``(?:servicename).{0,40}([a-f0-9]{32})`` produce false positives when
    applied to arbitrary message text.
    """
    name_lower = pat.name.lower()

    # Explicit irrelevance check
    for kw in IRRELEVANT_KEYWORDS:
        if kw in name_lower:
            return False

    # Skip context-dependent patterns — they rely on a keyword appearing
    # near a generic hex/alnum blob.  Great for git grep, bad for LLM text.
    if _is_context_dependent(pat.regex):
        return False

    # Explicit relevance check
    for kw in RELEVANT_KEYWORDS:
        if kw in name_lower:
            return True

    # Check regex for common secret-like prefixes
    for prefix in (
        "sk-",
        "sk_",
        "api_",
        "token",
        "secret",
        "key-",
        "key_",
        "pat-",
        "pat_",
        "ghp_",
        "glpat-",
    ):
        if prefix in pat.regex.lower():
            return True

    # Default: include if high confidence
    return pat.confidence == "high"


def _is_context_dependent(regex: str) -> bool:
    """Detect patterns that rely on a nearby keyword rather than secret format.

    Common shapes from secrets-patterns-db:
      (?:servicename).{0,40}([a-f0-9]{32})
    Common shapes from gitleaks:
      (?i)[\\w.-]{0,50}?(?:servicename)([ \\t\\w.-]...)([a-z0-9_-]{32})
    These match any hex/alnum string that happens to be near a keyword.
    They're great for scanning git repos but too noisy for LLM message text.
    """
    # secrets-patterns-db style: (?:keyword).{0,N}(capture)
    if re.search(r"\(\?:?\w+\)\.?\{0,\d+\}", regex):
        return True
    # gitleaks style: (?i) ... (?:keyword) ... generic capture
    # These have a keyword anchor followed by assignment operators and a
    # generic alphanumeric capture group
    if re.search(r"\(\?:\w+\)", regex) and re.search(r"\{0,\d+\}", regex):
        return True
    # secrets-patterns-db "key name" detectors:
    #   some_key_name(=| =|:| :)  or  some[_-]?key[_-]?name(=| =|:| :)
    # These detect the *variable name*, not the secret value itself.
    if re.search(r"\(=\|[^)]*:\)", regex) and not re.search(r"[A-Z]{3,}[a-z0-9]", regex):
        return True
    return False


def is_python_compatible(regex: str) -> bool:
    """Check if a regex string compiles in Python."""
    import warnings

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            re.compile(regex)
        return True
    except re.error:
        return False


# ---------------------------------------------------------------------------
# Output generation
# ---------------------------------------------------------------------------


def write_report(
    results: list[MatchResult],
    sg_patterns: list[NormalizedPattern],
    out: TextIO,
    verbose: bool = False,
) -> None:
    """Write the human-readable gap report."""
    covered = [r for r in results if r.tier]
    candidates = [
        r
        for r in results
        if not r.tier and is_relevant(r.external) and is_python_compatible(r.external.regex)
    ]
    skipped_irrelevant = [r for r in results if not r.tier and not is_relevant(r.external)]
    skipped_incompat = [
        r
        for r in results
        if not r.tier and is_relevant(r.external) and not is_python_compatible(r.external.regex)
    ]

    out.write("=" * 72 + "\n")
    out.write("  secretgate — Regex Gap Analysis Report\n")
    out.write("=" * 72 + "\n\n")

    # Summary
    out.write("## Summary\n\n")
    out.write(f"  secretgate patterns:              {len(sg_patterns)}\n")
    out.write(f"  External patterns analyzed:       {len(results)}\n")
    out.write(f"  Already covered:                  {len(covered)}\n")
    out.write(f"  Candidates to add:                {len(candidates)}\n")
    out.write(f"  Skipped (low relevance):          {len(skipped_irrelevant)}\n")
    out.write(f"  Skipped (incompatible regex):     {len(skipped_incompat)}\n\n")

    # Covered patterns
    if verbose:
        out.write("-" * 72 + "\n")
        out.write("## Already Covered\n\n")
        by_tier: dict[str, list[MatchResult]] = {}
        for r in covered:
            by_tier.setdefault(r.tier, []).append(r)
        for tier in ("prefix", "keyword", "synthetic"):
            tier_results = by_tier.get(tier, [])
            if tier_results:
                out.write(f"### Tier: {tier} ({len(tier_results)} patterns)\n\n")
                for r in sorted(tier_results, key=lambda x: x.external.name):
                    out.write(f"  [{r.external.source}] {r.external.name}\n")
                    if r.matched_by:
                        out.write(
                            f"    -> matched by: {r.matched_by.service} / {r.matched_by.name}\n"
                        )
                    out.write(f"    ({r.note})\n\n")

    # Candidates
    out.write("-" * 72 + "\n")
    out.write("## Candidates to Add\n\n")
    if not candidates:
        out.write("  No new candidates found.\n\n")
    else:
        # Group by service
        by_service: dict[str, list[MatchResult]] = {}
        for r in candidates:
            by_service.setdefault(r.external.service, []).append(r)

        for service in sorted(by_service):
            out.write(f"### {service}\n\n")
            for r in sorted(by_service[service], key=lambda x: x.external.name):
                out.write(f"  {r.external.name}\n")
                out.write(f"    Source:  {r.external.source}\n")
                out.write(f"    Regex:   {r.external.regex}\n")
                if r.external.confidence:
                    out.write(f"    Confidence: {r.external.confidence}\n")
                out.write("\n")

    # Skipped
    if verbose:
        out.write("-" * 72 + "\n")
        out.write("## Skipped (Low Relevance)\n\n")
        for r in sorted(skipped_irrelevant, key=lambda x: x.external.name):
            out.write(f"  [{r.external.source}] {r.external.name}\n")

        out.write("\n")
        out.write("-" * 72 + "\n")
        out.write("## Skipped (Incompatible Regex)\n\n")
        for r in sorted(skipped_incompat, key=lambda x: x.external.name):
            out.write(f"  [{r.external.source}] {r.external.name}\n")
            out.write(f"    Regex: {r.external.regex}\n")

    out.write("\n")


def write_yaml_candidates(
    results: list[MatchResult],
    out: TextIO,
) -> None:
    """Write candidate patterns in secretgate's YAML format."""
    candidates = [
        r
        for r in results
        if not r.tier and is_relevant(r.external) and is_python_compatible(r.external.regex)
    ]

    if not candidates:
        out.write("# No new candidate patterns found.\n")
        return

    out.write("# Gap analysis candidates — review before merging into signatures.yaml\n")
    out.write("# Generated by scripts/gap_analysis.py\n\n")

    # Group by service
    by_service: dict[str, list[MatchResult]] = {}
    for r in candidates:
        by_service.setdefault(r.external.service, []).append(r)

    for service in sorted(by_service):
        entry = {service: []}
        for r in sorted(by_service[service], key=lambda x: x.external.name):
            # Clean up the name for use in YAML
            name = _clean_pattern_name(r.external.name)
            entry[service].append({name: r.external.regex})

        # Manual YAML output to match secretgate's exact format
        out.write(f"- {service}:\n")
        for pat_dict in entry[service]:
            for name, regex in pat_dict.items():
                out.write(f'    - {name}: "{_yaml_escape(regex)}"\n')
        out.write("\n")


def _clean_pattern_name(name: str) -> str:
    """Convert a pattern name like 'aws-access-key' to 'AWS Access Key'."""
    # Replace dashes and underscores with spaces
    cleaned = name.replace("-", " ").replace("_", " ")
    # Title case
    return cleaned.title()


def _yaml_escape(s: str) -> str:
    """Escape a string for use in double-quoted YAML."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare secretgate patterns against external pattern databases.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python scripts/gap_analysis.py
              python scripts/gap_analysis.py --output-dir ./results --verbose
              python scripts/gap_analysis.py --include-low-confidence
        """),
    )
    parser.add_argument(
        "--secretgate-path",
        default="src/secretgate/signatures.yaml",
        help="Path to secretgate's signatures.yaml (default: src/secretgate/signatures.yaml)",
    )
    parser.add_argument(
        "--secrets-patterns-db",
        default=SECRETS_PATTERNS_DB_URL,
        help="URL or path to secrets-patterns-db rules-stable.yml",
    )
    parser.add_argument(
        "--gitleaks",
        default=GITLEAKS_URL,
        help="URL or path to gitleaks config TOML",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory to write output files (default: print to stdout)",
    )
    parser.add_argument(
        "--include-low-confidence",
        action="store_true",
        help="Include low-confidence patterns from secrets-patterns-db",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed matching info including covered patterns",
    )
    args = parser.parse_args()

    # 1. Load sources
    print("Loading patterns...")

    print(f"  secretgate: {args.secretgate_path}")
    sg_patterns = parse_secretgate(args.secretgate_path)
    print(f"    Loaded {len(sg_patterns)} patterns")

    print(f"  secrets-patterns-db: {args.secrets_patterns_db}")
    spdb_text = load_source(args.secrets_patterns_db)
    spdb_patterns = parse_secrets_patterns_db(spdb_text, args.include_low_confidence)
    print(f"    Loaded {len(spdb_patterns)} patterns")

    print(f"  gitleaks: {args.gitleaks}")
    gl_text = load_source(args.gitleaks)
    gl_patterns = parse_gitleaks(gl_text)
    print(f"    Loaded {len(gl_patterns)} patterns")

    all_external = spdb_patterns + gl_patterns
    print(f"\n  Total external patterns: {len(all_external)}")

    # 2. Match
    print("\nMatching patterns...")
    results = []
    for ext in all_external:
        result = match_external_pattern(ext, sg_patterns, args.verbose)
        results.append(result)

    covered = sum(1 for r in results if r.tier)
    uncovered = len(results) - covered
    print(f"  Covered: {covered}")
    print(f"  Uncovered: {uncovered}")

    candidates = [
        r
        for r in results
        if not r.tier and is_relevant(r.external) and is_python_compatible(r.external.regex)
    ]
    print(f"  Relevant + compatible candidates: {len(candidates)}")

    # 3. Output
    print("\nGenerating output...")

    if args.output_dir:
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        report_path = out_dir / "gap_report.txt"
        with open(report_path, "w") as f:
            write_report(results, sg_patterns, f, args.verbose)
        print(f"  Report: {report_path}")

        candidates_path = out_dir / "gap_candidates.yaml"
        with open(candidates_path, "w") as f:
            write_yaml_candidates(results, f)
        print(f"  Candidates: {candidates_path}")
    else:
        print()
        write_report(results, sg_patterns, sys.stdout, args.verbose)
        print()
        print("=" * 72)
        print("  YAML Candidates")
        print("=" * 72)
        print()
        write_yaml_candidates(results, sys.stdout)

    print("\nDone.")


if __name__ == "__main__":
    main()
