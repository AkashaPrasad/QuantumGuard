"""QG-R011: enrolment attempt while a loss report is open."""

from __future__ import annotations

from .conftest import check_explanation, check_response, err_of, lift, only_alert


def test_enrolment_held_during_open_loss_report(env):
    laptop = env.device("Aiko Tanaka")
    phone = env.second_device("Aiko Tanaka", "Aiko's phone")
    priya = env.device("Priya Raman")
    code = phone.post("/api/v1/invites", {"user_id": phone.user_id})["code"]
    rr = phone.post(f"/api/v1/devices/{laptop.device_id}/report-lost", {"lost_at": env.clock.iso()})
    assert not env.alerts()

    e = err_of(env.client.enroll, code, "new tablet")
    assert e.status == 403 and e.code == "QG_QUARANTINED" and e.reason == "enrolment_held"

    alert = only_alert(env, "QG-R011")
    assert alert["severity"] == "high"
    assert alert["incident_id"] == rr["incident_id"]
    check_explanation(alert)
    check_response(alert, "hold_enrolment", "identity", phone.user_id)

    # Still held on a second attempt; other people can still enrol.
    again = phone.post("/api/v1/invites", {"user_id": phone.user_id})["code"]
    assert err_of(env.client.enroll, again, "new tablet").reason == "enrolment_held"
    assert env.device("Daniel Mensah").get("/api/v1/devices")

    lift(env, priya, alert)
    tablet = env.client.enroll(again, "new tablet")
    assert tablet.device_id
