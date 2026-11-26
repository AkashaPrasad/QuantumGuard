"""Review r2, M1 follow-up: the revoke transaction cancels pending codes *for the lost device's person* only.
An admin's device can mint codes for other people (P-ADMIN-PEOPLE). A thief holding an admin's laptop mints a
code for an existing employee before the loss is reported. The revocation leaves it pending, and no enrolment
hold applies to that employee (the incident is about the admin), so the code enrols a device in the employee's
name at once, without waiting for the incident to close. The employee's own device then offers it every file
under `/rekey/pending` `shares` (the catch-up path)."""

from __future__ import annotations

from qg.client.api import ApiError


def test_revocation_cancels_codes_the_lost_device_minted_for_other_people(env):
    laptop = env.device("Mira Okafor")  # admin
    phone = env.second_device("Mira Okafor", "Mira's phone")
    dan = env.device("Daniel Mensah")
    dan.protect("salaries.txt", b"dan's file", "confidential")
    code = laptop.post("/api/v1/invites", {"user_id": dan.user_id})["code"]  # thief, before the report
    phone.post(f"/api/v1/devices/{laptop.device_id}/report-lost", {"lost_at": env.clock.iso()})

    try:
        rogue = env.client.enroll(code, "thief's device")
    except ApiError as e:
        assert e.code in ("QG_INVALID_INPUT", "QG_QUARANTINED"), e
        return
    offered = [s for s in dan.rekey_pending()["shares"] if s["device_id"] == rogue.device_id]
    raise AssertionError(f"a code minted by the revoked admin device enrolled a device as Daniel "
                         f"({rogue.device_id}); Daniel's device offers it {len(offered)} file(s) to catch up")
