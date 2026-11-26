"""Findings about automatic responses.

1. Lockout through detection: an unauthenticated caller who knows a device id (the public directory lists
   them all) sends five failing /session/finish proofs for it. QG-R012 counts them against that device and
   throttles the real device to 0.1 requests per second for five minutes, renewable at will. Pointed at the
   operator during an incident, this slows the response to the incident.
2. Self-lift: an operator whose own device was quarantined by QG-R004 (decoy touched) lifts that quarantine
   from a second device. The person the response contains can undo it.
"""

from __future__ import annotations

import os

from qg.crypto.encoding import b64u
from qg.crypto.suite import SUITE


def test_unauthenticated_failures_cannot_throttle_another_persons_device(env):
    priya = env.device("Priya Raman")  # the operator, already signed in
    assert any(d["device_id"] == priya.device_id for d in env.http.get("/api/v1/directory").json()["devices"])
    for _ in range(5):
        s = env.http.post("/api/v1/session/start", json={"suite": SUITE, "device_id": priya.device_id}).json()
        env.http.post("/api/v1/session/finish", json={"start_id": s["start_id"], "signature": b64u(os.urandom(3309)),
                                                      "key_confirm": b64u(os.urandom(48))})

    codes = [priya.raw_request("GET", "/api/v1/devices").status_code for _ in range(6)]

    assert codes == [200] * 6, f"the operator's own requests were throttled by someone else's failures: {codes}"


def test_operator_cannot_lift_a_response_that_contains_themselves(env):
    laptop = env.device("Priya Raman")
    phone = env.second_device("Priya Raman", "Priya's phone")
    assert laptop.raw_request("GET", f"/api/v1/files/{env.decoy_file_id()}/slot").status_code == 403
    alert = env.alerts("QG-R004")[0]
    assert alert["subject"]["device_id"] == laptop.device_id

    import json

    r = phone.raw_request("POST", f"/api/v1/responses/{alert['response']['id']}/lift",
                          body=json.dumps({"reason": "false positive"}).encode())

    assert r.status_code == 403, f"the contained operator lifted their own quarantine ({r.status_code})"
    assert env.alerts("QG-R004")[0]["response"]["lifted_at"] is None
