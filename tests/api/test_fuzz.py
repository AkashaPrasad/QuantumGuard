"""Schemathesis fuzzing from spec/openapi.json (make fuzz). Every operation gets generated inputs, both without a
session and as correctly signed requests from an enrolled device; no response may be a server error."""

import json
from pathlib import Path

import pytest
import schemathesis
from hypothesis import HealthCheck, settings

from qg.testing import TestEnv

pytestmark = pytest.mark.fuzz
SPEC = Path(__file__).resolve().parents[2] / "spec" / "openapi.json"
schema = schemathesis.openapi.from_path(str(SPEC))
_env: dict = {}


def env(tmp_path_factory) -> TestEnv:  # noqa: ANN001
    if "env" not in _env:
        e = TestEnv(tmp_path_factory.mktemp("fuzz"))
        aiko = e.device("Aiko Tanaka")
        aiko.protect("fuzz-target.txt", b"fuzz", "confidential")
        _env["env"], _env["dev"] = e, aiko
    return _env["env"]


def _target(case) -> tuple[str, bytes]:  # noqa: ANN001
    path = case.formatted_path
    if case.query:
        from urllib.parse import urlencode

        path += "?" + urlencode(case.query, doseq=True)
    if case.body is None or isinstance(case.body, schemathesis.core.NotSet):
        return path, b""
    if isinstance(case.body, bytes):
        return path, case.body
    return path, json.dumps(case.body).encode()


FUZZ = settings(max_examples=25, deadline=None, suppress_health_check=list(HealthCheck))


@schema.parametrize()
@FUZZ
def test_no_server_error_without_session(case, tmp_path_factory):  # noqa: ANN001
    e = env(tmp_path_factory)
    path, body = _target(case)
    headers = {k: str(v) for k, v in (case.headers or {}).items() if k.lower() not in ("content-length", "host")}
    r = e.http.request(case.method, path, content=body, headers=headers)
    assert r.status_code < 500 or r.json()["error"]["code"] == "QG_UNAVAILABLE_FAIL_CLOSED" and \
        r.json()["error"]["reason"] in ("key_release_frozen", "policy_unavailable"), (case.method, path, r.text[:200])
    assert r.headers.get("qg-request-id")


@schema.parametrize()
@FUZZ
def test_no_server_error_signed(case, tmp_path_factory):  # noqa: ANN001
    env(tmp_path_factory)
    dev = _env["dev"]
    path, body = _target(case)
    if dev.session is None or dev.raw_request("GET", "/api/v1/policy").status_code != 200:
        dev.login()
    r = dev.raw_request(case.method, path, body=body)
    assert r.status_code < 500, (case.method, path, r.status_code, r.text[:200])
