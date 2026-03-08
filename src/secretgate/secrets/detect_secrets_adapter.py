"""Optional adapter for Yelp's detect-secrets library.

Uses only the regex-based plugins (entropy detectors disabled due to
high false-positive rate on normal code). Produces Match objects
compatible with our scanner.
"""

from __future__ import annotations

from secretgate.secrets.scanner import Match

# Regex plugins only — entropy detectors produce too many false positives
# on normal code (e.g. "import os" triggers Base64 High Entropy String).
REGEX_PLUGINS = [
    {"name": "AWSKeyDetector"},
    {"name": "ArtifactoryDetector"},
    {"name": "AzureStorageKeyDetector"},
    {"name": "BasicAuthDetector"},
    {"name": "CloudantDetector"},
    {"name": "DiscordBotTokenDetector"},
    {"name": "GitHubTokenDetector"},
    {"name": "GitLabTokenDetector"},
    {"name": "IbmCloudIamDetector"},
    {"name": "IbmCosHmacDetector"},
    {"name": "JwtTokenDetector"},
    {"name": "MailchimpDetector"},
    {"name": "NpmDetector"},
    {"name": "OpenAIDetector"},
    {"name": "PrivateKeyDetector"},
    {"name": "PypiTokenDetector"},
    {"name": "SendGridDetector"},
    {"name": "SlackDetector"},
    {"name": "SoftlayerDetector"},
    {"name": "SquareOAuthDetector"},
    {"name": "StripeDetector"},
    {"name": "TelegramBotTokenDetector"},
    {"name": "TwilioKeyDetector"},
]


def is_available() -> bool:
    """Check if detect-secrets is installed."""
    try:
        import detect_secrets  # noqa: F401
        return True
    except ImportError:
        return False


def scan_text(text: str) -> list[Match]:
    """Scan text using detect-secrets regex plugins.

    Returns Match objects with value and position info.
    """
    from detect_secrets.settings import configure_settings_from_baseline
    from detect_secrets.core.scan import scan_line

    configure_settings_from_baseline({"plugins_used": REGEX_PLUGINS})

    matches: list[Match] = []
    seen: set[str] = set()
    lines = text.splitlines()

    for line_num, line in enumerate(lines, start=1):
        for secret in scan_line(line):
            value = secret.secret_value
            if not value or value in seen:
                continue
            seen.add(value)

            # Find the position of the secret in the line
            start = line.find(value)
            end = start + len(value) if start >= 0 else len(line)
            if start < 0:
                start = 0

            matches.append(
                Match(
                    service="detect-secrets",
                    pattern_name=secret.type,
                    value=value,
                    line_number=line_num,
                    start=start,
                    end=end,
                )
            )

    return matches
