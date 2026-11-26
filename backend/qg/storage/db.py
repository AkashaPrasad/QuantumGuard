"""SQLite storage in WAL mode. One connection guarded by a re-entrant lock: every write path runs in a
single serialised transaction, which is what makes revocation atomic against concurrent key release."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

SCHEMA = (Path(__file__).parent / "schema.sql").read_text()


class StorageUnavailable(RuntimeError):
    pass


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._depth = 0
        self._on_commit: list = []
        self._on_rollback: list = []
        self._after: list = []
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)
            self._migrate()

    def _migrate(self) -> None:
        """Additive migrations for databases created by earlier builds."""
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(leases)")}
        if "kind" not in cols:
            self._conn.execute("ALTER TABLE leases ADD COLUMN kind TEXT NOT NULL DEFAULT 'slot'")
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(invites)")}
        if "created_by_device" not in cols:
            self._conn.execute("ALTER TABLE invites ADD COLUMN created_by_device TEXT")
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(alerts)")}
        for col in ("event_kind", "service", "event_detail"):
            if col not in cols:
                self._conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} TEXT")

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Serialised read-write transaction (re-entrant: nested calls join the outer one)."""
        with self._lock:
            if self._depth:
                self._depth += 1
                try:
                    yield self._conn
                finally:
                    self._depth -= 1
                return
            try:
                self._conn.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise StorageUnavailable("database unavailable") from exc
            self._depth = 1
            try:
                yield self._conn
            except BaseException:
                self._depth = 0
                self._conn.execute("ROLLBACK")
                self._finish(self._on_rollback)
                self._run_after()
                raise
            else:
                self._depth = 0
                try:
                    self._conn.execute("COMMIT")
                except sqlite3.OperationalError as exc:
                    self._conn.execute("ROLLBACK")
                    self._finish(self._on_rollback)
                    raise StorageUnavailable("commit failed") from exc
                self._finish(self._on_commit)
                self._run_after()

    def _run_after(self) -> None:
        run = list(self._after)
        self._after.clear()
        for fn in run:
            fn()  # each opens its own transaction (depth is 0 again)

    @property
    def in_tx(self) -> bool:
        return self._depth > 0

    def after_tx(self, fn: Any) -> None:
        """Run fn after the outermost transaction ends, whether it commits or rolls back. Used for evidence
        that must survive a failing request (deny receipts, detection events)."""
        if self._depth:
            self._after.append(fn)
        else:
            fn()

    def _finish(self, hooks: list) -> None:
        run = list(hooks)
        self._on_commit.clear()
        self._on_rollback.clear()
        for fn in run:
            fn()

    def on_commit(self, fn: Any) -> None:
        """Run fn after the current transaction commits (fn runs while the lock is still held)."""
        self._on_commit.append(fn)

    def on_rollback(self, fn: Any) -> None:
        self._on_rollback.append(fn)

    def read(self) -> sqlite3.Connection:
        """For single statements outside a transaction; callers hold no lock across awaits."""
        return self._conn

    def one(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def all(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT v FROM meta WHERE k = ?", (key,)).fetchone()
    return row[0] if row else None


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", (key, value))
