"""QG-R002: replayed sequence number."""

from __future__ import annotations

from .conftest import check_explanation, check_response, lift, only_alert


def test_replay_ends_the_session(env):
    aiko = env.device("Aiko Tanaka")
    priya = env.device("Priya Raman")
    sid = aiko.session.session_id
    assert aiko.raw_request("GET", "/api/v1/devices", seq=5).status_code == 200
    assert not env.alerts()
    r = aiko.raw_request("GET", "/api/v1/devices", seq=5)
    assert r.status_code in (401, 403)
    assert r.json()["error"]["code"] == "QG_REPLAY"

    alert = only_alert(env, "QG-R002")
    assert alert["severity"] == "high"
    check_explanation(alert, receipts=False)  # a replayed request is refused before any receipt is written
    check_response(alert, "end_session", "session", sid)

    # The session is gone.
    r = aiko.raw_request("GET", "/api/v1/devices")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "QG_NO_SESSION"

    lift(env, priya, alert)
    # A new login works and the device is otherwise unaffected.
    aiko.login()
    assert aiko.get("/api/v1/devices")
