"""Scenario harness: starts a real server process (python -m qg.server) on a free port with throwaway data
and keys, gets enrolment codes from the local admin command, and prints exactly one JSON result line.
Works the same on a developer machine and inside the runtime container (no shell needed)."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[3]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, workdir: Path | None = None, port: int | None = None) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="qg-scenario-")
        self.workdir = workdir or Path(self.tmp.name)
        self.port = port or free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.proc: subprocess.Popen[str] | None = None
        self.lines: list[str] = []
        self.bootstrap: list[dict[str, Any]] = []
        self._reader: threading.Thread | None = None

    @property
    def env(self) -> dict[str, str]:
        env = dict(os.environ)
        env.update({
            "QG_DATA_DIR": str(self.workdir / "data"),
            "QG_KEYS_DIR": str(self.workdir / "keys"),
            "QG_PORT": str(self.port),
            "QG_HOST": "127.0.0.1",
        })
        if (ROOT / "backend" / "qg").is_dir():  # source checkout; the installed wheel needs nothing
            env["PYTHONPATH"] = f"{ROOT / 'backend'}:{ROOT / 'cli'}"
        env.pop("QG_WEB_DIST", None)
        return env

    def start(self, timeout: float = 30) -> Server:
        self.proc = subprocess.Popen(  # noqa: S603 - fixed argv
            [sys.executable, "-m", "qg.server"], env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if httpx.get(self.url + "/healthz", timeout=1).status_code == 200:
                    return self
            except httpx.HTTPError:
                pass
            if self.proc.poll() is not None:
                raise RuntimeError("server exited: " + " | ".join(self.lines[-5:]))
            time.sleep(0.1)
        raise RuntimeError("server did not start")

    def _read(self) -> None:
        if self.proc is None or self.proc.stdout is None:
            return
        for line in self.proc.stdout:
            line = line.rstrip("\n")
            self.lines.append(line)

    def admin(self, *args: str) -> dict[str, Any]:
        out = subprocess.run(  # noqa: S603 - fixed argv
            [sys.executable, "-m", "qg.admin", *args], env=self.env, capture_output=True, text=True, timeout=60,
            check=True,
        )
        return json.loads(out.stdout)

    def code(self, name: str) -> str:
        """A fresh single-use code for a seeded person, as `python -m qg.admin invite --all --json` prints it."""
        if not self.bootstrap:
            self.bootstrap = self.admin("invite", "--all", "--json")["invites"]
        for p in self.bootstrap:
            if p["name"] == name:
                code = p.pop("code", None)
                if code is None:
                    uid = p["user_id"]
                    code = self.admin("invite", "--user-id", uid, "--json")["invites"][0]["code"]
                return code
        raise KeyError(name)

    def kill(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGKILL)
            self.proc.wait(10)

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.kill()

    def events(self, name: str) -> list[dict[str, Any]]:
        out = []
        for line in list(self.lines):
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if obj.get("event") == name:
                    out.append(obj)
        return out

    def close(self) -> None:
        self.stop()
        self.tmp.cleanup()


def result(scenario: str, passed: bool, **fields: Any) -> int:
    print(json.dumps({"scenario": scenario, "pass": bool(passed), **fields}, separators=(",", ":"), sort_keys=False))
    return 0 if passed else 1
