"""Revocation, incidents and denied attempts."""

import os

import pytest

from qg.client.api import ApiError


def _setup(env):
    laptop = env.device("Aiko Tanaka")
    phone = env.second_device("Aiko Tanaka", "Aiko's phone")
    fid = laptop.protect("plates.csv", os.urandom(5000), "confidential", [phone.device_id])["file"]["file_id"]
    laptop.open(fid)
    phone.open(fid)
    rr = phone.post(f"/api/v1/devices/{laptop.device_id}/report-lost", {"lost_at": env.clock.iso()})
    return laptop, phone, fid, rr


@pytest.mark.parametrize("path", ["/api/v1/devices", "/api/v1/files", "SLOT"])
def test_denied_attempt_recorded_on_any_route(env, path):
    laptop, phone, fid, rr = _setup(env)
    target = f"/api/v1/files/{fid}/slot" if path == "SLOT" else path
    r = laptop.raw_request("GET", target)
    assert r.status_code == 403 and r.json()["error"]["code"] == "QG_DENY_REVOKED"
    receipt_id = r.json()["error"]["receipt_id"]
    assert receipt_id and r.headers.get("QG-Receipt") == receipt_id
    inc = phone.get(f"/api/v1/incidents/{rr['incident_id']}")
    assert inc["denied_attempts"] == 1
    steps = [t for t in inc["timeline"] if t["step"] == "denied_attempt"]
    assert len(steps) == 1 and steps[0]["receipt_id"] == receipt_id
    r001 = [a for a in env.alerts("QG-R001")]
    assert len(r001) == 1 and r001[0]["incident_id"] == rr["incident_id"]
    assert r001[0]["id"] in inc["alert_ids"]
    assert receipt_id in r001[0]["explanation"]["receipt_ids"]


def test_denied_session_attempts_counted_and_one_alert(env):
    laptop, phone, fid, rr = _setup(env)
    for _ in range(3):
        with pytest.raises(ApiError) as ei:
            laptop.login()
        assert ei.value.code == "QG_DENY_REVOKED"
    inc = phone.get(f"/api/v1/incidents/{rr['incident_id']}")
    assert inc["denied_attempts"] == 3
    alerts = env.alerts("QG-R001")
    assert len(alerts) == 1 and len(alerts[0]["explanation"]["receipt_ids"]) == 3


def test_revoke_result_and_idempotence(env):
    laptop, phone, fid, rr = _setup(env)
    assert rr["sessions_ended"] == 1 and rr["slots_deleted"] == 1 and rr["status"] == "revoked"
    assert rr["checkpoint"]["tree_size"] >= 1
    again = phone.post(f"/api/v1/devices/{laptop.device_id}/report-lost", {"lost_at": env.clock.iso()})
    assert again["incident_id"] == rr["incident_id"]
    priya = env.device("Priya Raman")
    op = priya.post(f"/api/v1/devices/{laptop.device_id}/revoke",
                    {"compromise_time": "2026-11-26T11:00:00.000Z", "reason": "earlier loss"})
    assert op["incident_id"] == rr["incident_id"]
    exp = priya.get(f"/api/v1/incidents/{rr['incident_id']}/exposure")
    assert exp["compromise_time"] == "2026-11-26T11:00:00.000Z"
    assert [f["file_id"] for f in exp["exposed"]] == [fid]
    steps = [t["step"] for t in priya.get(f"/api/v1/incidents/{rr['incident_id']}")["timeline"]]
    assert steps[:3] == ["reported", "revoked", "scoped"] and "rescoped" in steps


def test_report_lost_rules(env):
    laptop = env.device("Aiko Tanaka")
    daniel = env.device("Daniel Mensah")
    e = pytest.raises(ApiError, daniel.post, f"/api/v1/devices/{laptop.device_id}/report-lost",
                      {"lost_at": env.clock.iso()}).value
    assert e.code == "QG_NOT_FOUND"
    e = pytest.raises(ApiError, laptop.post, f"/api/v1/devices/{laptop.device_id}/report-lost",
                      {"lost_at": env.clock.iso()}).value
    assert e.reason == "report_from_other_device"
    e = pytest.raises(ApiError, daniel.post, f"/api/v1/devices/{laptop.device_id}/revoke",
                      {"compromise_time": env.clock.iso(), "reason": "x"}).value
    assert e.code in ("QG_DENY_POLICY", "QG_NOT_FOUND")


def test_enrolment_held_while_loss_open(env):
    laptop, phone, fid, rr = _setup(env)
    code = phone.post("/api/v1/invites", {"user_id": phone.user_id})["code"]
    e = pytest.raises(ApiError, env.client.enroll, code, "replacement").value
    assert (e.code, e.reason) == ("QG_QUARANTINED", "enrolment_held")
    alert = env.alerts("QG-R011")[0]
    priya = env.device("Priya Raman")
    priya.post(f"/api/v1/responses/{alert['response']['id']}/lift", {"reason": "verified by phone call"})
    assert env.client.enroll(code, "replacement").device_id


def test_close_requires_rekey(env):
    laptop, phone, fid, rr = _setup(env)
    priya = env.device("Priya Raman")
    e = pytest.raises(ApiError, priya.post, f"/api/v1/incidents/{rr['incident_id']}/close").value
    assert (e.code, e.reason) == ("QG_CONFLICT", "rekey_pending")
    phone.rekey_all()
    assert priya.post(f"/api/v1/incidents/{rr['incident_id']}/close")["status"] == "closed"
