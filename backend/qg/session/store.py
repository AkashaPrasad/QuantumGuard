"""Short-lived handshake state and session MAC keys. Kept in memory only: no session secret is ever
written to disk, so a copy of the database cannot be used to forge requests. A restart ends sessions."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Pending:
    kind: str  # "enroll" | "session"
    expires_mono: float
    data: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"Pending({self.kind}, <redacted>)"


class SecretStore:
    MAX_PENDING = 10_000

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: dict[str, Pending] = {}
        self._mac: dict[str, bytes] = {}

    def put_pending(self, key: str, p: Pending, now_mono: float) -> None:
        with self._lock:
            if len(self._pending) >= self.MAX_PENDING:
                for k in [k for k, v in self._pending.items() if v.expires_mono < now_mono]:
                    del self._pending[k]
                if len(self._pending) >= self.MAX_PENDING:
                    raise OverflowError("too many pending handshakes")
            self._pending[key] = p

    def take_pending(self, key: str, kind: str, now_mono: float) -> Pending | None:
        """Single use: removed whether or not it is still valid."""
        with self._lock:
            p = self._pending.pop(key, None)
        if p is None or p.kind != kind or p.expires_mono < now_mono:
            return None
        return p

    def set_mac(self, session_id: str, key: bytes) -> None:
        with self._lock:
            self._mac[session_id] = key

    def mac(self, session_id: str) -> bytes | None:
        with self._lock:
            return self._mac.get(session_id)

    def drop_mac(self, session_id: str) -> None:
        with self._lock:
            self._mac.pop(session_id, None)

    def drop_all(self) -> None:
        with self._lock:
            self._pending.clear()
            self._mac.clear()
