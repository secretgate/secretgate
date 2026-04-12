"""Shared constants and compiled patterns used by multiple modules.

Centralises regex patterns that were previously duplicated across
``forward.py`` and ``h2_handler.py``.
"""

from __future__ import annotations

import re

# Paths that should never be scanned — auth/token endpoints contain
# credentials (JWTs, refresh tokens) that would be redacted and break
# authentication flows like OAuth token refresh.
AUTH_PATH_RE: re.Pattern[str] = re.compile(
    r"(?:"
    r"/oauth(?:/|$)"  # /oauth/ or /oauth at end
    r"|/auth(?:/|$)"  # /auth/ or /auth at end
    r"|/token(?:/|$|\?)"  # /token, /token/, /token?...
    r"|/authorize(?:/|$|\?)"  # /authorize, /authorize/, /authorize?...
    r"|/\.well-known/"  # /.well-known/openid-configuration etc.
    r"|/login"  # /login endpoints
    r")",
    re.IGNORECASE,
)


def is_auth_path(path: str) -> bool:
    """Return True if *path* is an auth/token endpoint that should skip scanning."""
    return bool(AUTH_PATH_RE.search(path))
