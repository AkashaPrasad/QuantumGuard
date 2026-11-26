"""QG-R012: repeated MAC or signature failures. The response falls on the source of the failures: an address
that fails key proofs cannot start handshakes for five minutes; the session or device the failures named is
not throttled (nobody can lock another person out). Signature failures on an authenticated session throttle
that session."""

from __future__ import annotations

import os

from qg.crypto.encoding import b64u, canon
from qg.crypto.suite import SUITE

from .conftest import check_explanation, check_response, lift, only_alert


def test_bad_mac_burst_blocks_the_source_not_the_session(env):
    aiko = env.device("Aiko Tanaka")
    good = aiko.session.k_mac
    aiko.session.k_mac = bytes(48)
    try:
        for i in range(5):
            r = aiko.raw_request("GET", "/api/v1/devices")
            assert r.status_code == 401 and r.json()["error"]["code"] == "QG_BAD_MAC", i
            if i < 4:
                assert not env.alerts()
    finally:
        aiko.session.k_mac = good

    alert = only_alert(env, "QG-R012")
    assert alert["severity"] == "medium"
    check_explanation(alert, receipts=False)  # a failed MAC is refused before any receipt exists
    assert alert["response"] is None and alert["subject"]["session_id"] is None
    # the named session keeps working ...
    assert [aiko.raw_request("GET", "/api/v1/devices").status_code for _ in range(10)] == [200] * 10
    # ... while the source address cannot start new handshakes for five minutes
    r = env.http.post("/api/v1/session/start", json={"suite": SUITE, "device_id": aiko.device_id})
    assert r.status_code == 429 and r.json()["error"]["reason"] == "source_throttled"
    env.clock.advance(301)
    assert env.http.post("/api/v1/session/start", json={"suite": SUITE, "device_id": aiko.device_id}).status_code == 200


def test_handshake_proof_failures_never_throttle_the_claimed_device(env):
    priya = env.device("Priya Raman")
    for _ in range(5):
        s = env.http.post("/api/v1/session/start", json={"suite": SUITE, "device_id": priya.device_id}).json()
        env.http.post("/api/v1/session/finish", json={"start_id": s["start_id"], "signature": b64u(os.urandom(3309)),
                                                      "key_confirm": b64u(os.urandom(48))})
    alert = only_alert(env, "QG-R012")
    assert alert["response"] is None and alert["subject"]["device_id"] is None
    assert [priya.raw_request("GET", "/api/v1/devices").status_code for _ in range(10)] == [200] * 10


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
