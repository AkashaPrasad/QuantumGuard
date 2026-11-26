"""QG-R001: request or session attempt from a revoked device."""

from __future__ import annotations

from .conftest import check_explanation, check_response, lift, only_alert, protect_file


def test_revoked_device_attempt_denied_and_alerted(env):
    laptop = env.device("Aiko Tanaka")
    phone = env.second_device("Aiko Tanaka", "Aiko's phone")
    priya = env.device("Priya Raman")
    fid = protect_file(laptop, recipients=[phone.device_id])
    rr = phone.post(f"/api/v1/devices/{laptop.device_id}/report-lost", {"lost_at": env.clock.iso()})
    assert not env.alerts()

    r = laptop.raw_request("GET", "/api/v1/devices")
    assert r.status_code == 403
    err = r.json()["error"]
    assert err["code"] == "QG_DENY_REVOKED" and err["receipt_id"]

    alert = only_alert(env, "QG-R001")
    assert alert["severity"] == "critical"
    assert alert["incident_id"] == rr["incident_id"]
    check_explanation(alert)
    assert err["receipt_id"] in alert["explanation"]["receipt_ids"]
    check_response(alert, "deny", "device", laptop.device_id)

    # The effect: the lost device stays denied, the other device is unaffected.
    assert laptop.raw_request("GET", "/api/v1/devices").status_code == 403
    assert phone.get("/api/v1/devices")
    assert phone.open(fid)

    # An operator can lift the response; the device itself stays revoked in the directory.
    lift(env, priya, alert)
    assert phone.get("/api/v1/devices")
