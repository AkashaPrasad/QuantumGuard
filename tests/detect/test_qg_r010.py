"""QG-R010: a retired service key was used."""

from __future__ import annotations

from .conftest import check_explanation, check_response, lift, only_alert


def test_retired_key_is_denied_and_alerted(env):
    mira = env.device("Mira Okafor")
    priya = env.device("Priya Raman")
    svc = mira.post("/api/v1/services", {"name": "build-signer"})
    old_key = svc["keys"][0]["key_id"]
    mira.post(f"/api/v1/services/{svc['service_id']}/rotate", {"reason": "x", "emergency": True})
    assert not env.alerts()

    r = mira.raw_request("GET", "/api/v1/services", headers={"QG-Service-Key": old_key})
    assert r.status_code == 403
    err = r.json()["error"]
    assert err["code"] == "QG_DENY_POLICY" and err["reason"] == "key_retired"

    alert = only_alert(env, "QG-R010")
    assert alert["severity"] == "high"
    check_explanation(alert)
    assert err["receipt_id"] in alert["explanation"]["receipt_ids"]
    check_response(alert, "deny", "credential", old_key)

    # The effect is scoped to the credential: the caller and the other keys are unaffected.
    assert mira.get("/api/v1/services")
    lift(env, priya, alert)
