"""Shared fixtures and helpers for the detection tests. Every test drives real enrolled devices through the HTTP API."""

from __future__ import annotations

import os
import warnings
from typing import Any

import pytest

from qg.client.api import ApiError
from qg.crypto.encoding import b64u, canon

warnings.filterwarnings("ignore", category=DeprecationWarning)


@pytest.fixture
def env(tmp_path):
    from qg.testing import TestEnv

    e = TestEnv(tmp_path)
    yield e
    e.close()


def only_alert(env, rule_id: str) -> dict[str, Any]:
    """The single alert of `rule_id`; also asserts that no other rule fired."""
    alerts = env.alerts()
    assert [a["rule_id"] for a in alerts] == [rule_id], [a["rule_id"] for a in alerts]
    return alerts[0]


def check_explanation(alert: dict[str, Any], *, receipts: bool = True) -> None:
    exp = alert["explanation"]
    assert isinstance(exp["condition"], str) and exp["condition"].strip()
    if receipts:
        assert exp["receipt_ids"]
    check_names(alert)


SERVICES = {"changes", "directory", "enrolment", "evidence-log", "files", "gateway", "identity-signals",
            "key-release", "messages", "service-keys"}


def check_names(alert: dict[str, Any]) -> None:
    """Every alert names the identity, the service and the event it concerns."""
    ident = alert["identity"]
    assert set(ident) == {"user_id", "name", "device_id", "session_id", "source", "claimed_id"}
    if ident["user_id"] is not None:
        assert ident["name"], "an alert about a person names that person"
    elif alert["rule_id"] != "QG-R013":  # the log self-audit concerns no single identity
        assert ident["device_id"] or ident["session_id"] or ident["source"], "an alert names the identity it concerns"
    assert alert["service"] in SERVICES
    assert alert["event"]["kind"] and alert["event"]["kind"] != "unknown"
    assert alert["event"]["ts"] == alert["ts"]


def check_response(alert: dict[str, Any], action: str, kind: str, scope_id: str | None) -> dict[str, Any]:
    resp = alert["response"]
    assert resp is not None
    assert resp["action"] == action
    assert resp["scope"]["kind"] == kind
    assert resp["scope"]["id"] == scope_id
    assert resp["scope"]["kind"] not in ("role", "org", "address_range")
    assert resp["lifted_at"] is None
    return resp


def lift(env, operator, alert: dict[str, Any], reason: str = "reviewed") -> None:
    operator.post(f"/api/v1/responses/{alert['response']['id']}/lift", {"reason": reason})
    fresh = next(a for a in env.alerts() if a["id"] == alert["id"])
    assert fresh["response"]["lifted_at"] is not None
    assert fresh["response"]["lifted_by"]


def err_of(callable_, *args, **kw) -> ApiError:
    with pytest.raises(ApiError) as ei:
        callable_(*args, **kw)
    return ei.value


def protect_file(dev, classification: str = "confidential", name: str = "doc.bin", recipients=None) -> str:
    return dev.protect(name, os.urandom(2000), classification, recipients)["file"]["file_id"]


def privilege_signal(env, operator, user_id: str, role: str = "admin") -> dict[str, Any]:
    now = int(env.clock.now().timestamp())
    return operator.post("/api/v1/signals", {
        "iss": "sandbox-idp", "jti": f"jti-{os.urandom(8).hex()}", "iat": now, "aud": "quantumguard",
        "events": {"urn:qg:event-type:privilege-observed": {
            "subject": {"format": "opaque", "id": user_id}, "event_timestamp": now, "role": role}}})


def grant_role(dev, target_user_id: str, role: str, reason: str = "test") -> dict[str, Any]:
    statement = {"directory_epoch": dev.refresh_directory()["epoch"], "file_id": None, "reason": reason,
                 "role": role, "suite": "QG-1", "target_user_id": target_user_id, "type": "role_grant"}
    sig = dev.state.keys.sig.sign(canon(statement), "change")
    return dev.post("/api/v1/changes", {"change": statement, "signature": b64u(sig)})
