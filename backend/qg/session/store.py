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
        # sessions ended by revocation: key kept until the session's hard expiry so that only requests that
        # prove possession are recorded as denied attempts (M2); value = [k_mac, hard_expiry_epoch_s, last_seq]
        self._revoked: dict[str, list] = {}

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

    def retire_mac(self, session_id: str, hard_expiry: float, last_seq: int) -> None:
        with self._lock:
            key = self._mac.pop(session_id, None)
            if key is not None:
                self._revoked[session_id] = [key, hard_expiry, last_seq]

    def revoked_mac(self, session_id: str, now: float) -> list | None:
        with self._lock:
            for sid in [s for s, v in self._revoked.items() if v[1] <= now]:
                del self._revoked[sid]
            return self._revoked.get(session_id)

    def advance_revoked(self, session_id: str, seq: int) -> bool:
        """Accept a strictly increasing sequence number on a revoked session (replays are not attempts)."""
        with self._lock:
            entry = self._revoked.get(session_id)
            if entry is None or seq <= entry[2]:
                return False
            entry[2] = seq
            return True

    def drop_all(self) -> None:
        with self._lock:
            self._pending.clear()
            self._mac.clear()
            self._revoked.clear()
