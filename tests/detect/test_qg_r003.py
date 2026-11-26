"""QG-R003: object built on a stale directory epoch."""

from __future__ import annotations

from qg.crypto.encoding import b64u, canon
from qg.crypto.suite import SUITE

from .conftest import check_explanation, check_response, err_of, lift, only_alert, protect_file


def test_stale_epoch_share_requires_fresh_session(env):
    aiko = env.device("Aiko Tanaka")
    daniel = env.device("Daniel Mensah")
    priya = env.device("Priya Raman")
    fid = protect_file(aiko)
    slot = aiko.slot(fid)
    dek = aiko.unwrap(slot)
    old_epoch = aiko.refresh_directory()["epoch"]
    # Revoke another device: older epochs are forbidden from now on.
    spare = env.second_device("Aiko Tanaka", "spare")
    priya.post(f"/api/v1/devices/{spare.device_id}/revoke",
               {"compromise_time": env.clock.iso(), "reason": "test"})
    assert aiko.refresh_directory()["epoch"] > old_epoch
    assert not env.alerts()

    recips = sorted([daniel.device_id])
    statement = {"directory_epoch": old_epoch, "file_id": fid, "recipients": recips, "suite": SUITE,
                 "version": slot["version"]}
    wraps = aiko._wraps_for(recips, dek, fid, slot["version"], old_epoch)  # noqa: SLF001
    sid = aiko.session.session_id
    e = err_of(aiko.post, f"/api/v1/files/{fid}/share", {
        "share": statement, "share_sig": b64u(aiko.state.keys.sig.sign(canon(statement), "share")), "wraps": wraps})
    assert e.status == 409 and e.code == "QG_STALE_EPOCH"

    alert = only_alert(env, "QG-R003")
    assert alert["severity"] == "high"
    check_explanation(alert)
    check_response(alert, "require_fresh_session", "session", sid)

    r = aiko.raw_request("GET", "/api/v1/devices")
    assert r.status_code == 401
    err = r.json()["error"]
    assert err["code"] == "QG_NO_SESSION" and err["reason"] == "fresh_session_required"

    lift(env, priya, alert)
    # The requirement ends: the same session is accepted again (or a login works).
    r = aiko.raw_request("GET", "/api/v1/devices")
    if r.status_code != 200:
        aiko.login()
        assert aiko.get("/api/v1/devices")
