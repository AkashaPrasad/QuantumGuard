"""Fixtures for reproduced findings. Each test here fails on the code it was written against and passes once
the finding is fixed. In-process app only; no network beyond loopback."""

from __future__ import annotations

import ipaddress
import socket
import sys
import warnings
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for source in (ROOT / "tests" / "security", ROOT / "cli", ROOT / "backend"):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))


@pytest.fixture(autouse=True)
def local_test_traffic_only(monkeypatch):
    original_connect = socket.socket.connect

    def connect(sock, address):
        if isinstance(address, tuple) and address[0] not in ("localhost", "testserver"):
            try:
                ok = ipaddress.ip_address(address[0]).is_loopback
            except ValueError:
                ok = False
            if not ok:
                pytest.fail("Attack tests attempted non-local network traffic.", pytrace=False)
        return original_connect(sock, address)

    monkeypatch.setattr(socket.socket, "connect", connect)


@pytest.fixture
def env(tmp_path):
    from qg.testing import TestEnv

    warnings.filterwarnings("ignore", category=DeprecationWarning)
    e = TestEnv(tmp_path / "server")
    yield e
    e.close()
