"""QG-R009: enumeration of file ids."""

from __future__ import annotations

import os

from qg.crypto.encoding import b64u

from .conftest import check_explanation, check_response, lift, only_alert


def test_enumeration_throttles_the_session(env):
    aiko = env.device("Aiko Tanaka")
    priya = env.device("Priya Raman")
    sid = aiko.session.session_id
    for i in range(20):
        r = aiko.raw_request("GET", f"/api/v1/files/fil_{b64u(os.urandom(16))}/slot")
        assert r.status_code == 404, i
        if i < 19:
            assert not env.alerts()
        env.clock.advance(1)

    alert = only_alert(env, "QG-R009")
    assert alert["severity"] == "medium"
    check_explanation(alert)
    assert len(alert["explanation"]["receipt_ids"]) >= 1
    check_response(alert, "throttle", "session", sid)

    codes = [aiko.raw_request("GET", "/api/v1/devices").status_code for _ in range(80)]
    assert 429 in codes
    r = next(x for x in (aiko.raw_request("GET", "/api/v1/devices") for _ in range(5)) if x.status_code == 429)
    assert r.json()["error"]["code"] == "QG_RATE_LIMITED"

    lift(env, priya, alert)
    env.clock.advance(60)
    assert all(aiko.raw_request("GET", "/api/v1/devices").status_code == 200 for _ in range(10))
