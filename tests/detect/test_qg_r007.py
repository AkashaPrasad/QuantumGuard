"""QG-R007: a new path to a crown-jewel resource appears in the privilege graph."""

from __future__ import annotations

from .conftest import check_explanation, privilege_signal, protect_file


def test_new_path_alert_has_the_path_and_no_response(env):
    daniel = env.device("Daniel Mensah")
    priya = env.device("Priya Raman")
    protect_file(env.device("Aiko Tanaka"), "restricted", "r.bin")

    privilege_signal(env, priya, daniel.user_id, "admin")
    alerts = env.alerts("QG-R007")
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["severity"] == "high"
    assert alert["response"] is None
    check_explanation(alert, receipts=False)

    detail = priya.get(f"/api/v1/alerts/{alert['id']}")
    assert detail["path"], "the alert must draw the path"
    assert any(edge["relation"] == "unlocks" for edge in detail["path"])
    assert all({"from", "to", "relation"} <= set(edge) for edge in detail["path"])

    # No response exists, so nothing was throttled or quarantined by this rule.
    assert daniel.get("/api/v1/devices")
    # An operator can acknowledge it.
    priya.post(f"/api/v1/alerts/{alert['id']}/ack", {})
    assert next(a for a in env.alerts("QG-R007"))["status"] != "open"
