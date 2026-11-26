"""QG-R008: access rate far above the person's own baseline."""

from __future__ import annotations

from .conftest import check_explanation, check_response, lift, only_alert, protect_file


def test_burst_above_baseline_requires_a_fresh_session(env):
    aiko = env.device("Aiko Tanaka")
    priya = env.device("Priya Raman")
    fid = protect_file(aiko, "internal", "b.bin")

    # A normal pattern: one open per minute for 12 minutes.
    for _ in range(12):
        aiko.slot(fid)
        env.clock.advance(60)
        aiko.login()
    priya.login()
    assert not env.alerts()

    sid = None
    triggered = False
    for _ in range(30):
        env.clock.advance(1)
        sid = aiko.session.session_id
        r = aiko.raw_request("GET", f"/api/v1/files/{fid}/slot")
        if env.alerts():
            triggered = True
            break
        assert r.status_code == 200
    assert triggered

    alert = only_alert(env, "QG-R008")
    assert alert["severity"] == "medium"
    check_explanation(alert)
    check_response(alert, "require_fresh_session", "session", sid)

    r = aiko.raw_request("GET", "/api/v1/devices")
    assert r.status_code == 401 and r.json()["error"]["reason"] == "fresh_session_required"

    lift(env, priya, alert)
    r = aiko.raw_request("GET", "/api/v1/devices")
    if r.status_code != 200:
        aiko.login()
        assert aiko.get("/api/v1/devices")
