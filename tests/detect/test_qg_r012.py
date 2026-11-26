"""QG-R012: repeated MAC failures."""

from __future__ import annotations

from .conftest import check_explanation, check_response, lift, only_alert


def test_bad_mac_burst_throttles_the_session(env):
    aiko = env.device("Aiko Tanaka")
    priya = env.device("Priya Raman")
    sid = aiko.session.session_id
    good = aiko.session.k_mac
    aiko.session.k_mac = bytes(48)
    try:
        for i in range(5):
            r = aiko.raw_request("GET", "/api/v1/devices")
            assert r.status_code in (401, 403), i
            if i < 4:
                assert not env.alerts()
    finally:
        aiko.session.k_mac = good

    alert = only_alert(env, "QG-R012")
    assert alert["severity"] == "medium"
    check_explanation(alert, receipts=False)  # a failed MAC is refused before any receipt exists
    check_response(alert, "throttle", "session", sid)

    codes = [aiko.raw_request("GET", "/api/v1/devices").status_code for _ in range(80)]
    assert 429 in codes

    lift(env, priya, alert)
    env.clock.advance(60)
    assert aiko.raw_request("GET", "/api/v1/devices").status_code == 200
