"""Supporting workflow 4, messaging device revocation: messages are encrypted per recipient device with
X-Wing; after one of the recipient's devices is reported lost, it receives nothing and cannot be addressed,
while the person's remaining device keeps working."""

from __future__ import annotations

from datetime import UTC, datetime

from qg.client import ApiError, QGClient
from qg.clock import fmt
from qg.scenarios.harness import Server, result


def run() -> int:
    srv = Server().start()
    try:
        client = QGClient(srv.url)
        aiko = client.enroll(srv.code("Aiko Tanaka"), "Aiko's laptop")
        aiko.login()
        d_laptop = client.enroll(srv.code("Daniel Mensah"), "Daniel's laptop")
        d_laptop.login()
        d_phone = client.enroll(d_laptop.post("/api/v1/invites", {"user_id": d_laptop.user_id})["code"], "Daniel's phone")
        d_phone.login()

        aiko.send_message(d_laptop.user_id, b"Freezer 3 alarm at 02:10")
        both = [m["plaintext"] for m in d_laptop.read_messages()] == [b"Freezer 3 alarm at 02:10"] and \
            [m["plaintext"] for m in d_phone.read_messages()] == [b"Freezer 3 alarm at 02:10"]

        rr = d_laptop.post(f"/api/v1/devices/{d_phone.device_id}/report-lost", {"lost_at": fmt(datetime.now(UTC))})
        aiko.send_message(d_laptop.user_id, b"Samples moved to freezer 5")
        laptop_msgs = [m["plaintext"] for m in d_laptop.read_messages()]
        try:
            d_phone.read_messages()
            phone_denied = False
        except ApiError as e:
            phone_denied = e.code == "QG_DENY_REVOKED"
        try:
            aiko.send_message(d_laptop.user_id, b"x", device_ids=[d_laptop.device_id, d_phone.device_id])
            addressed_revoked = True
        except (ApiError, Exception):  # noqa: BLE001 - the client refuses (not in directory) or the server does
            addressed_revoked = False
        ok = both and laptop_msgs[0] == b"Samples moved to freezer 5" and len(laptop_msgs) == 2 and phone_denied \
            and not addressed_revoked
        return result("messaging", ok, delivered_to_both=both, after_revoke_delivered_to_remaining=len(laptop_msgs) == 2,
                      revoked_device_denied=phone_denied, revoked_device_addressable=addressed_revoked,
                      incident_id=rr["incident_id"], time_to_enforce_ms=rr["time_to_enforce_ms"])
    finally:
        srv.close()
