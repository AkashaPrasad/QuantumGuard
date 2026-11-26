"""QG-R012: repeated MAC or signature failures. The response falls on the source of the failures: an address
that fails key proofs cannot start handshakes for five minutes; the session or device the failures named is
not throttled (nobody can lock another person out). Signature failures on an authenticated session throttle
that session."""

from __future__ import annotations

import os

from qg.crypto.encoding import b64u, canon
from qg.crypto.suite import SUITE

from .conftest import check_explanation, check_response, lift, only_alert


def test_bad_mac_burst_blocks_only_that_source_and_claim(env):
    aiko = env.device("Aiko Tanaka")
    priya = env.device("Priya Raman")
    good = aiko.session.k_mac
    aiko.session.k_mac = bytes(48)
    try:
        for i in range(5):
            r = aiko.raw_request("GET", "/api/v1/devices")
            assert r.status_code == 401 and r.json()["error"]["code"] == "QG_BAD_MAC", i
            if i < 4:
                assert not env.alerts("QG-R012")
        for _ in range(50):  # further forged MACs are bounded: no second alert
            aiko.raw_request("GET", "/api/v1/devices")
    finally:
        aiko.session.k_mac = good

    alert = only_alert(env, "QG-R012")
    assert alert["severity"] == "medium" and alert["subject"]["session_id"] is None
    check_explanation(alert, receipts=False)  # a failed MAC is refused before any receipt exists
    check_response(alert, "throttle", "source", f"testclient|{aiko.device_id}")
    # the named session keeps working and its device can still sign in with a correct proof
    assert [aiko.raw_request("GET", "/api/v1/devices").status_code for _ in range(10)] == [200] * 10
    aiko.login()
    # a wrong proof for that device from that source is refused without being recorded again
    s = env.http.post("/api/v1/session/start", json={"suite": SUITE, "device_id": aiko.device_id}).json()
    r = env.http.post("/api/v1/session/finish", json={"start_id": s["start_id"], "signature": b64u(os.urandom(3309)),
                                                      "key_confirm": b64u(os.urandom(48))})
    assert r.status_code == 429 and r.json()["error"]["reason"] == "source_throttled"
    lift(env, priya, alert)  # an operator can lift it
    s = env.http.post("/api/v1/session/start", json={"suite": SUITE, "device_id": aiko.device_id}).json()
    r = env.http.post("/api/v1/session/finish", json={"start_id": s["start_id"], "signature": b64u(os.urandom(3309)),
                                                      "key_confirm": b64u(os.urandom(48))})
    assert r.status_code == 400


def test_handshake_proof_failures_never_throttle_the_claimed_device(env):
    priya = env.device("Priya Raman")
    for _ in range(5):
        s = env.http.post("/api/v1/session/start", json={"suite": SUITE, "device_id": priya.device_id}).json()
        env.http.post("/api/v1/session/finish", json={"start_id": s["start_id"], "signature": b64u(os.urandom(3309)),
                                                      "key_confirm": b64u(os.urandom(48))})
    alert = only_alert(env, "QG-R012")
    check_response(alert, "throttle", "source", f"testclient|{priya.device_id}")
    assert alert["subject"]["device_id"] is None
    assert [priya.raw_request("GET", "/api/v1/devices").status_code for _ in range(10)] == [200] * 10
    priya.login()  # a correct proof is never refused because of someone else's failures


def test_signature_failures_on_a_session_throttle_that_session(env):
    aiko = env.device("Aiko Tanaka")
    priya = env.device("Priya Raman")
    fid = aiko.protect("x.txt", b"x", "internal")["file"]["file_id"]
    statement = {"directory_epoch": aiko.refresh_directory()["epoch"], "file_id": fid, "recipients": [aiko.device_id],
                 "suite": SUITE, "version": 1}
    for _ in range(5):
        body = {"share": statement, "share_sig": b64u(os.urandom(3309)),
                "wraps": [{"device_id": aiko.device_id, "xwing_ct": b64u(os.urandom(1120)),
                           "wrapped_dek": b64u(os.urandom(60))}]}
        aiko.raw_request("POST", f"/api/v1/files/{fid}/share", body=canon(body))
    alert = only_alert(env, "QG-R012")
    check_response(alert, "throttle", "session", aiko.session.session_id)
    lift(env, priya, alert)
