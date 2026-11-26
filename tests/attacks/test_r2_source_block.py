"""Review r2, M3/M2 follow-ups on the source-scoped QG-R012 response.

1. Shared front address. Every client reaches the server through one front address: the TLS profile puts Caddy
   (`reverse_proxy quantumguard:8080`) in front, uvicorn is not told to trust its forwarding headers, and Docker's
   published port also presents one gateway address. `client_ip()` is `request.client.host`, so "the source" is
   everybody. Five failing proofs from a caller with no keys now refuse every new handshake for every person for
   300 s, renewable at will, and the alert carries no response an operator could lift. The operator cannot sign
   in to respond. (In-process, all callers share one address too, which is the deployed shape.)
2. Unbounded alerts. A request with a bad MAC on any live session id (ids are not secret: receipts show them)
   is checked before any rate limit, and the address-scoped QG-R012 finding has no response, so the duplicate
   check never applies: every five forged requests write a new alert row, log line and SECURITY_EVENTS line.
   Before the fix the session throttle de-duplicated this to one alert per five minutes.
"""

from __future__ import annotations

import os

from qg.crypto.encoding import b64u
from qg.crypto.suite import SUITE


def test_keyless_failures_do_not_stop_another_person_signing_in(env):
    priya = env.device("Priya Raman")  # the operator
    aiko = env.device("Aiko Tanaka")
    for _ in range(5):  # no keys at all, claims Aiko's device (the public directory lists it)
        s = env.http.post("/api/v1/session/start", json={"suite": SUITE, "device_id": aiko.device_id}).json()
        env.http.post("/api/v1/session/finish", json={"start_id": s["start_id"], "signature": b64u(os.urandom(3309)),
                                                      "key_confirm": b64u(os.urandom(48))})
    assert env.alerts("QG-R012")  # the failures were detected (today: an alert with no liftable response)

    try:
        priya.login()  # the operator needs a fresh session to respond
        refused = None
    except Exception as e:  # noqa: BLE001
        refused = e
    assert refused is None, f"the operator's correct proof was refused because of someone else's failures: {refused}"


def test_forged_macs_on_a_known_session_id_do_not_write_unbounded_alerts(env):
    aiko = env.device("Aiko Tanaka")
    sid = aiko.session.session_id  # not secret: receipts in GET /files/{id} activity carry it
    before = len(env.alerts("QG-R012"))

    for i in range(100):  # no key: just the id and garbage MACs
        env.http.get("/api/v1/devices", headers={"QG-Session": sid, "QG-Seq": str(1000 + i),
                                                 "QG-MAC": b64u(os.urandom(48))})

    added = len(env.alerts("QG-R012")) - before
    assert added <= 1, f"100 keyless requests wrote {added} QG-R012 alerts (one per 5 requests, unbounded)"
