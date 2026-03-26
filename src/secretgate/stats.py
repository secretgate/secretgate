"""Runtime statistics for monitoring secretgate activity.

Thread-safe counters for tracking requests scanned, secrets found,
requests blocked/redacted, and per-service breakdowns.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass
class Stats:
    """Thread-safe runtime statistics."""

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _started_at: float = field(default_factory=time.time)

    # Counters
    requests_scanned: int = 0
    requests_blocked: int = 0
    requests_redacted: int = 0
    requests_audited: int = 0
    secrets_found: int = 0
    packfiles_scanned: int = 0
    packfiles_blocked: int = 0

    # Per-service breakdown
    _by_service: dict[str, int] = field(default_factory=dict)

    def record_scan(self, secrets: int, mode: str, services: list[str] | None = None) -> None:
        """Record a completed scan."""
        with self._lock:
            self.requests_scanned += 1
            self.secrets_found += secrets
            if secrets > 0:
                if mode == "block":
                    self.requests_blocked += 1
                elif mode == "redact":
                    self.requests_redacted += 1
                elif mode == "audit":
                    self.requests_audited += 1
            if services:
                for svc in services:
                    self._by_service[svc] = self._by_service.get(svc, 0) + 1

    def record_packfile(self, blocked: bool = False) -> None:
        """Record a packfile scan."""
        with self._lock:
            self.packfiles_scanned += 1
            if blocked:
                self.packfiles_blocked += 1

    def snapshot(self) -> dict:
        """Return a point-in-time snapshot of all stats."""
        with self._lock:
            return {
                "uptime_seconds": round(time.time() - self._started_at, 1),
                "requests_scanned": self.requests_scanned,
                "requests_blocked": self.requests_blocked,
                "requests_redacted": self.requests_redacted,
                "requests_audited": self.requests_audited,
                "secrets_found": self.secrets_found,
                "packfiles_scanned": self.packfiles_scanned,
                "packfiles_blocked": self.packfiles_blocked,
                "by_service": dict(self._by_service),
            }

    def reset(self) -> None:
        """Reset all counters (useful for testing)."""
        with self._lock:
            self.requests_scanned = 0
            self.requests_blocked = 0
            self.requests_redacted = 0
            self.requests_audited = 0
            self.secrets_found = 0
            self.packfiles_scanned = 0
            self.packfiles_blocked = 0
            self._by_service.clear()
            self._started_at = time.time()
