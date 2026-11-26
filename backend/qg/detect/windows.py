"""Sliding-window counters and EWMA baselines kept in memory (statistics, not ML)."""

from __future__ import annotations

import math
import threading
from collections import defaultdict, deque


class SlidingCounter:
    def __init__(self) -> None:
        self._events: dict[str, deque[tuple[float, str | None]]] = defaultdict(deque)
        self._lock = threading.Lock()

    def add(self, key: str, now: float, window: float, ref: str | None = None) -> list[str | None]:
        """Record an event and return the refs of all events for key inside the window."""
        with self._lock:
            q = self._events[key]
            q.append((now, ref))
            while q and q[0][0] < now - window:
                q.popleft()
            return [r for _, r in q]

    def clear(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)


class EwmaBaseline:
    """Per-identity requests-per-minute baseline: EWMA mean and variance."""

    def __init__(self, alpha: float = 0.2, warmup: int = 10) -> None:
        self.alpha = alpha
        self.warmup = warmup
        self._state: dict[str, list[float]] = {}  # key -> [mean, var, n, bucket_start, bucket_count]
        self._lock = threading.Lock()

    def observe(self, key: str, now: float, bucket: float = 60.0) -> tuple[float, float, float, int] | None:
        """Count one request. When a bucket closes, fold it into the baseline. Returns
        (current_count, mean, std, n) for the open bucket so callers can compare."""
        with self._lock:
            st = self._state.get(key)
            if st is None:
                st = [0.0, 0.0, 0, now, 0]
                self._state[key] = st
            while now - st[3] >= bucket:
                x = st[4]
                if st[2] == 0:
                    st[0], st[1] = float(x), 0.0
                else:
                    d = x - st[0]
                    st[0] += self.alpha * d
                    st[1] = (1 - self.alpha) * (st[1] + self.alpha * d * d)
                st[2] += 1
                st[3] += bucket
                st[4] = 0
                if st[2] > 10_000:
                    st[3] = now
            st[4] += 1
            return float(st[4]), st[0], math.sqrt(st[1]), int(st[2])
