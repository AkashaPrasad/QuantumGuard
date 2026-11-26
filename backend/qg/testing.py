"""Test harness: production app with an injectable clock, temporary data and key directories, a switch that
makes the policy engine unavailable, and captured structured log lines. Nothing here bypasses enforcement:
tests drive real enrolled devices through the public HTTP API with the `qg` client library.

    from qg.testing import TestEnv
    env = TestEnv(tmp_path)              # fresh org, keys and database
    aiko = env.device("Aiko Tanaka")     # enrolled and signed in
    env.set_policy_available(False)      # fail-closed checks
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI

from qg.app import create_app
from qg.clock import Clock, FakeClock
from qg.config import Settings
from qg.core import Core
from qg.gateway.http import gateway_dependency  # noqa: F401 - re-exported for route inventory tests

__all__ = ["CallableClock", "TestEnv", "create_test_app", "gateway_dependency", "set_policy_available"]


class CallableClock(Clock):
    """Adapts a zero-argument callable returning an aware UTC datetime (tests advance it)."""

    _EPOCH = datetime(2000, 1, 1, tzinfo=UTC)

    def __init__(self, fn: Callable[[], datetime]) -> None:
        self.fn = fn

    def now(self) -> datetime:
        value = self.fn()
        if value.tzinfo is None:
            raise ValueError("clock must return an aware datetime")
        return value.astimezone(UTC)

    def monotonic(self) -> float:
        return (self.now() - self._EPOCH).total_seconds()


def _clock(clock: Clock | Callable[[], datetime] | None) -> Clock:
    if clock is None:
        return FakeClock()
    if isinstance(clock, Clock):
        return clock
    return CallableClock(clock)


def create_test_app(*, data_dir: Path, keys_dir: Path, clock: Clock | Callable[[], datetime] | None = None,
                    log_sink: Callable[[str], None] | None = None, demo: bool = False) -> FastAPI:
    """A fully initialised production app on fresh storage. `app.state.core` is the runtime;
    `app.state.captured_logs` holds every stdout line the server would have printed, and
    `app.state.bootstrap_invites` the seeded people with codes as `qg.admin invite --all` would print them
    (that command's own output, never the server log)."""
    logs: list[str] = []

    def sink(line: str) -> None:
        logs.append(line)
        if log_sink is not None:
            log_sink(line)

    core = Core(Settings(data_dir=Path(data_dir), keys_dir=Path(keys_dir), demo=demo), clock=_clock(clock),
                log_sink=sink)
    app = create_app(core)
    app.state.captured_logs = logs
    app.state.bootstrap_invites = core.issue_bootstrap_invites()  # what `python -m qg.admin invite --all` prints
    return app


def set_policy_available(app: FastAPI, available: bool) -> None:
    app.state.core.policy.set_available(available)


class TestEnv:
    """One isolated server plus helpers to enrol the seeded identities and run sessions."""

    __test__ = False  # not a pytest class

    def __init__(self, root: Path, clock: Clock | Callable[[], datetime] | None = None) -> None:
        from fastapi.testclient import TestClient

        from qg.client import QGClient

        self.root = Path(root)
        self.app = create_test_app(data_dir=self.root / "data", keys_dir=self.root / "keys", clock=clock)
        self.core: Core = self.app.state.core
        self.clock = self.core.clock
        self.http = TestClient(self.app, base_url="http://testserver")
        self.client = QGClient(self.http)
        self.people: dict[str, dict[str, Any]] = {p["name"]: p for p in self.app.state.bootstrap_invites}
        self.devices: dict[str, Any] = {}

    @property
    def logs(self) -> list[str]:
        return self.app.state.captured_logs

    def user_id(self, name: str) -> str:
        return self.people[name]["user_id"]

    def enroll(self, name: str, device_name: str | None = None, code: str | None = None, login: bool = True) -> Any:
        """Enrol a device for a seeded person with their bootstrap code (first device) or a given code."""
        person = self.people[name]
        if code is None:
            code = person.pop("code", None)
            if code is None:
                raise RuntimeError(f"{name} has no unused bootstrap code; pass code=")
        dev = self.client.enroll(code, device_name or f"{name.split()[0]}'s laptop")
        if login:
            dev.login()
        return dev

    def device(self, name: str) -> Any:
        """The first enrolled, signed-in device of a seeded person (enrolled on first use)."""
        if name not in self.devices:
            self.devices[name] = self.enroll(name)
        return self.devices[name]

    def second_device(self, name: str, device_name: str = "phone") -> Any:
        first = self.device(name)
        inv = first.post("/api/v1/invites", {"user_id": first.user_id})
        return self.enroll(name, device_name, code=inv["code"])

    def set_policy_available(self, available: bool) -> None:
        self.core.policy.set_available(available)

    def alerts(self, rule_id: str | None = None) -> list[dict[str, Any]]:
        with self.core.db.tx() as conn:
            ids = [r[0] for r in conn.execute("SELECT id FROM alerts ORDER BY ts")]
            out = [self.core.alert_view(conn, i) for i in ids]
        return [a for a in out if a and (rule_id is None or a["rule_id"] == rule_id)]

    def json_logs(self) -> list[dict[str, Any]]:
        out = []
        for line in self.logs:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

    def decoy_file_id(self) -> str:
        row = self.core.db.one("SELECT file_id FROM files WHERE is_decoy = 1 LIMIT 1")
        assert row is not None
        return row[0]

    def close(self) -> None:
        self.http.close()
        self.core.stop()
        self.core.db.close()


def main(argv: list[str]) -> int:  # pragma: no cover - `python -m qg.testing fuzz`
    if argv[:1] == ["fuzz"]:
        from qg.fuzz import run

        return run()
    print("usage: python -m qg.testing fuzz", file=sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
