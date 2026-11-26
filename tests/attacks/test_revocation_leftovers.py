"""Findings about what a revocation leaves behind.

1. An enrolment code minted by the lost device before the loss report stays valid. The hold on enrolment
   lasts only while the incident is open; once an operator closes it (immediately possible when nothing needs
   a new key), the code enrols a fresh, unrevoked device for the victim, and the victim's remaining device then
   lists it under `shares` (the catch-up path) so files flow to it.
2. A request that carries the session id of a revoked device is recorded as a denied attempt by that device
   (receipt, incident timeline, QG-R001) without any MAC check and before rate limiting. Session ids are not
   secret (they are in receipts visible to co-holders), so anyone can fabricate incident evidence and write
   unbounded receipts into the log.
"""

from __future__ import annotations

import os

from qg.client.api import ApiError


def test_revocation_cancels_codes_minted_by_the_lost_device(env):
    laptop = env.device("Aiko Tanaka")
    phone = env.second_device("Aiko Tanaka", "Aiko's phone")
    priya = env.device("Priya Raman")
    code = laptop.post("/api/v1/invites", {"user_id": laptop.user_id})["code"]  # thief, before the report
    rr = phone.post(f"/api/v1/devices/{laptop.device_id}/report-lost", {"lost_at": env.clock.iso()})
    priya.post(f"/api/v1/incidents/{rr['incident_id']}/close", {})
    env.clock.advance(60)  # well inside the code's 15 minutes

    try:
        env.client.enroll(code, "thief's new device")
        enrolled = True
    except ApiError as e:
        enrolled = False
        assert (e.code, e.reason) == ("QG_INVALID_INPUT", "invite_invalid")
    assert not enrolled, "a code minted by the revoked device enrolled a new device after the incident closed"


def test_revoked_session_id_without_mac_does_not_write_evidence(env):
    laptop = env.device("Aiko Tanaka")
    phone = env.second_device("Aiko Tanaka", "Aiko's phone")
    fid = laptop.protect("x.txt", b"hello", "confidential", [phone.device_id])["file"]["file_id"]
    laptop.open(fid)
    sid = laptop.session.session_id
    assert sid in str(phone.get(f"/api/v1/files/{fid}")["activity"])  # visible to a co-holder
    rr = phone.post(f"/api/v1/devices/{laptop.device_id}/report-lost", {"lost_at": env.clock.iso()})
    size_before = env.core.log.size
    attempts_before = phone.get(f"/api/v1/incidents/{rr['incident_id']}")["denied_attempts"]

    statuses = set()
    for i in range(70):  # no device key, no MAC key: only the session id string
        r = env.http.get("/api/v1/devices", headers={"QG-Session": sid, "QG-Seq": str(i + 1),
                                                     "QG-MAC": os.urandom(48).hex()[:64]})
        statuses.add(r.status_code)

    assert statuses <= {401, 403, 429}
    added = env.core.log.size - size_before
    attempts = phone.get(f"/api/v1/incidents/{rr['incident_id']}")["denied_attempts"] - attempts_before
    assert added == 0 and attempts == 0, f"{added} receipts and {attempts} denied attempts fabricated without a MAC"
