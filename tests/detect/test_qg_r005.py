"""QG-R005: privilege in the identity source with no signed change."""

from __future__ import annotations

from .conftest import check_explanation, check_response, err_of, lift, privilege_signal, protect_file


def test_unsigned_privilege_quarantines_the_identity(env):
    aiko = env.device("Aiko Tanaka")
    daniel = env.device("Daniel Mensah")
    priya = env.device("Priya Raman")
    conf = protect_file(daniel, "confidential", "c.bin")
    internal = protect_file(daniel, "internal", "i.bin")
    conf_aiko = protect_file(aiko, "confidential", "a.bin")

    privilege_signal(env, priya, daniel.user_id, "admin")
    alert = only_alert_r005_pair(env)
    assert alert["severity"] == "critical"
    check_explanation(alert, receipts=False)
    check_response(alert, "quarantine_identity", "identity", daniel.user_id)

    e = err_of(daniel.slot, conf)
    assert e.status == 403 and e.code == "QG_QUARANTINED"
    assert daniel.open(internal)
    assert aiko.open(conf_aiko)

    lift(env, priya, alert)
    assert daniel.open(conf)


def only_alert_r005_pair(env):
    """QG-R007 may accompany QG-R005 on the same signal (restricted files exist); R005 must be present once."""
    alerts = env.alerts()
    assert {a["rule_id"] for a in alerts} <= {"QG-R005", "QG-R007"}
    r005 = [a for a in alerts if a["rule_id"] == "QG-R005"]
    assert len(r005) == 1
    return r005[0]
