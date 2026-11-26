"""QG-R006: a self-granted role followed by sensitive access within 10 minutes."""

from __future__ import annotations

from .conftest import check_explanation, check_response, err_of, grant_role, lift, only_alert, protect_file


def test_self_granted_role_then_sensitive_access(env):
    mira = env.device("Mira Okafor")
    priya = env.device("Priya Raman")
    aiko = env.device("Aiko Tanaka")
    conf = protect_file(mira, "confidential", "m.bin")
    internal = protect_file(mira, "internal", "i.bin")
    aiko_conf = protect_file(aiko, "confidential", "a.bin")

    change = grant_role(mira, mira.user_id, "auditor")
    assert change["status"] == "applied"
    assert not env.alerts()

    mira.slot(conf)  # the access that completes the pattern
    alert = only_alert(env, "QG-R006")
    assert alert["severity"] == "high"
    check_explanation(alert)
    check_response(alert, "quarantine_identity", "identity", mira.user_id)

    e = err_of(mira.slot, conf)
    assert e.status == 403 and e.code == "QG_QUARANTINED"
    assert mira.open(internal)
    assert aiko.open(aiko_conf)

    lift(env, priya, alert)
    # The pattern is still inside its 10 minute window, so wait it out; then access is normal again.
    env.clock.advance(601)
    mira.login()
    priya.login()
    assert mira.open(conf)
    assert len(env.alerts("QG-R006")) == 1
