"""Local-only security fixtures and machine-readable claim outcomes."""

from datetime import datetime, timedelta, timezone
import importlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import socket
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
for source in (ROOT / "cli", ROOT / "backend"):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))


def pytest_addoption(parser):
    parser.addoption("--security-strict", action="store_true", help="Fail instead of skipping missing backend/test adapters")


def unavailable(request, message):
    if request.config.getoption("--security-strict"):
        pytest.fail(message, pytrace=False)
    pytest.skip(message)


class Clock:
    def __init__(self):
        self.value = datetime.now(timezone.utc)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += timedelta(seconds=seconds)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture(autouse=True)
def local_test_traffic_only(monkeypatch):
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_getaddrinfo = socket.getaddrinfo

    def check(host):
        if host in ("localhost", "testserver", None):
            return
        try:
            allowed = ipaddress.ip_address(host).is_loopback
        except ValueError:
            allowed = False
        if not allowed:
            pytest.fail("Security tests attempted non-local network traffic.", pytrace=False)

    def connect(sock, address):
        if isinstance(address, tuple):
            check(address[0])
        return original_connect(sock, address)

    def connect_ex(sock, address):
        if isinstance(address, tuple):
            check(address[0])
        return original_connect_ex(sock, address)

    def getaddrinfo(host, *args, **kwargs):
        check(host)
        return original_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


@pytest.fixture
def testing_module(request):
    if importlib.util.find_spec("qg") is None:
        unavailable(request, "Backend absent: waiting for core (Pass 1 skeleton).")
    # Import failures inside an existing backend are real errors, never skips.
    if importlib.util.find_spec("qg.testing") is None:
        unavailable(request, "Core must provide qg.testing; see tests/security/README.md.")
    return importlib.import_module("qg.testing")


@pytest.fixture
def app(testing_module, request, tmp_path, clock):
    factory = getattr(testing_module, "create_test_app", None)
    if factory is None:
        unavailable(request, "Missing qg.testing.create_test_app(data_dir, keys_dir, clock).")
    return factory(data_dir=tmp_path / "data", keys_dir=tmp_path / "keys", clock=clock)


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient

    with TestClient(app, base_url="http://testserver", follow_redirects=False) as connection:
        yield connection


@pytest.fixture
def security_case(testing_module, request, tmp_path, clock):
    factory = getattr(testing_module, "security_case", None)
    if factory is None:
        unavailable(request, "Missing qg.testing.security_case; advanced claim scenarios are pending.")

    def prepare(name):
        case = factory(name=name, data_dir=tmp_path / "data", keys_dir=tmp_path / "keys", clock=clock)
        request.addfinalizer(case.close)
        return case

    return prepare


@pytest.fixture
def gateway_dependency(testing_module, request):
    dependency = getattr(testing_module, "gateway_dependency", None)
    if dependency is None:
        unavailable(request, "qg.testing must export the actual gateway dependency callable.")
    return dependency


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    result = yield
    report = result.get_result()
    if report.when == "call" or (report.when == "setup" and report.outcome != "passed"):
        item.config._qg_claims = getattr(item.config, "_qg_claims", {})
        item.config._qg_claims[item.nodeid] = {
            "test": item.nodeid,
            "outcome": report.outcome,
        }


def pytest_sessionfinish(session, exitstatus):
    if session.config.option.collectonly:
        return
    claims = getattr(session.config, "_qg_claims", {})
    # Never include exception bodies, random credentials or captured logs in artifacts.
    data = [{"test": key, "outcome": value["outcome"]} for key, value in sorted(claims.items())]
    (ROOT / "claims.json").write_text(json.dumps({"schema": 1, "claims": data}, indent=2) + "\n", encoding="utf-8")
