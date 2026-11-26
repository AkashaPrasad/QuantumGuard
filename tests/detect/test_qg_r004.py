"""QG-R004: decoy file or decoy service key touched."""

from __future__ import annotations

from .conftest import check_explanation, check_response, err_of, lift, only_alert


def test_decoy_file_quarantines_the_device(env):
    aiko = env.device("Aiko Tanaka")
    daniel = env.device("Daniel Mensah")
    priya = env.device("Priya Raman")
    decoy = env.decoy_file_id()
    e = err_of(aiko.slot, decoy)
    assert e.status == 403

    alert = only_alert(env, "QG-R004")
    assert alert["severity"] == "critical"
    check_explanation(alert)
    check_response(alert, "quarantine_device", "device", aiko.device_id)

    e = err_of(aiko.get, "/api/v1/devices")
    assert e.status in (401, 403)
    e = err_of(aiko.login)
    assert e.status == 403 and e.code == "QG_QUARANTINED"
    assert daniel.get("/api/v1/devices")  # other people are unaffected

    lift(env, priya, alert)
    aiko.login()
    assert aiko.get("/api/v1/devices")


def test_decoy_service_key_quarantines_the_device(env):
    mira = env.device("Mira Okafor")
    priya = env.device("Priya Raman")
    keys = [r[0] for r in env.core.db.all(
        "SELECT k.key_id FROM service_keys k JOIN services s ON s.service_id=k.service_id WHERE s.is_decoy=1")]
    assert keys
    r = mira.raw_request("GET", "/api/v1/services", headers={"QG-Service-Key": keys[0]})
    assert r.status_code == 403
    alert = only_alert(env, "QG-R004")
    check_explanation(alert)
    check_response(alert, "quarantine_device", "device", mira.device_id)
    e = err_of(mira.get, "/api/v1/devices")  # the session was ended; its device is quarantined
    assert (e.status, e.code) == (403, "QG_QUARANTINED")
    e = err_of(mira.login)  # a quarantined device cannot sign in again
    assert e.status == 403 and e.code == "QG_QUARANTINED"
    lift(env, priya, alert)
    mira.login()
    assert mira.get("/api/v1/devices")
