"""Server clock. Injectable so tests can move time; the client clock is never trusted."""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta


def fmt(dt: datetime) -> str:
    dt = dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parse(text: str) -> datetime:
    """Parse RFC 3339 UTC with milliseconds (also accepts other offsets and precisions)."""
    if not isinstance(text, str) or len(text) > 40:
        raise ValueError("bad time")
    t = text.replace("Z", "+00:00").replace("z", "+00:00")
    dt = datetime.fromisoformat(t)
    if dt.tzinfo is None:
        raise ValueError("time needs a zone")
    return dt.astimezone(UTC)


class Clock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()

    def iso(self) -> str:
        return fmt(self.now())


class FakeClock(Clock):
    """Manually advanced clock for tests."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 11, 26, 12, 0, 0, tzinfo=UTC)
        self._mono = 1000.0
        self._lock = threading.Lock()

    def now(self) -> datetime:
        with self._lock:
            return self._now

    def monotonic(self) -> float:
        with self._lock:
            return self._mono

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._now += timedelta(seconds=seconds)
            self._mono += seconds

    def set(self, when: datetime) -> None:
        with self._lock:
            self._now = when
